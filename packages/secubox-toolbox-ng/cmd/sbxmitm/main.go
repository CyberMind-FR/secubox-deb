// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: forging MITM PoC (#662 Phase 1)
//
// De-risking spike for migrating the R3 MITM engine off Python mitmproxy onto a
// multi-core Go core. Pure standard library (no external modules) so it builds
// offline and cross-compiles to arm64 with `GOOS=linux GOARCH=arm64 go build`.
//
// It is NOT wired into the live R3 path. It proves the discriminating
// capabilities the engine analysis flagged as risky:
//   - forge per-host leaf certs from the EXISTING ca-wg CA (client trust intact),
//   - request short-circuit 204 (ad_ghost block),
//   - response body inject (banner / ad-CSS),
//   - SNI splice passthrough (tls_splice),
//   - TLS ClientHello capture for JA4 (ja4 addon) via crypto/tls.GetCertificate.
//
// Runs as an HTTP CONNECT proxy for easy smoke-testing (`curl -x`). The live
// engine will run transparent (SO_ORIGINAL_DST) — same handlers, different
// accept path (Phase 2+).
package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// ── CA + per-host leaf forging ──────────────────────────────────────────────

// CA holds the loaded forging CA (reused from ca-wg) + a per-host leaf cache.
type CA struct {
	cert  *x509.Certificate
	key   crypto.Signer
	mu    sync.Mutex
	cache map[string]*tls.Certificate
}

func loadCA(certPath, keyPath string) (*CA, error) {
	cpem, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read ca cert: %w", err)
	}
	kpem, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read ca key: %w", err)
	}
	cblk, _ := pem.Decode(cpem)
	if cblk == nil {
		return nil, fmt.Errorf("ca cert: no PEM block")
	}
	cert, err := x509.ParseCertificate(cblk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse ca cert: %w", err)
	}
	kblk, _ := pem.Decode(kpem)
	if kblk == nil {
		return nil, fmt.Errorf("ca key: no PEM block")
	}
	key, err := parseKey(kblk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse ca key: %w", err)
	}
	return &CA{cert: cert, key: key, cache: map[string]*tls.Certificate{}}, nil
}

func parseKey(der []byte) (crypto.Signer, error) {
	if k, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		if s, ok := k.(crypto.Signer); ok {
			return s, nil
		}
	}
	if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return k, nil
	}
	if k, err := x509.ParseECPrivateKey(der); err == nil {
		return k, nil
	}
	return nil, fmt.Errorf("unsupported CA key format")
}

// forge returns a leaf cert for host signed by the CA, cached.
func (c *CA) forge(host string) (*tls.Certificate, error) {
	host = strings.ToLower(strings.TrimSpace(host))
	c.mu.Lock()
	if tc, ok := c.cache[host]; ok {
		c.mu.Unlock()
		return tc, nil
	}
	c.mu.Unlock()

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{host},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, c.key.Public(), c.key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der) // parsed cert has Raw populated (Verify needs it)
	if err != nil {
		return nil, err
	}
	tc := &tls.Certificate{Certificate: [][]byte{der, c.cert.Raw}, PrivateKey: c.key, Leaf: leaf}
	c.mu.Lock()
	c.cache[host] = tc
	c.mu.Unlock()
	return tc, nil
}

// ── Pure handler logic ───────────────────────────────────────────────────────
//
// The decision surface (Decide / action / registrable / splice helpers) lives
// in policy.go, ported from the Python addons and proven at parity by the
// cross-engine harness. The body-inject helper is kept here next to the wiring.

// injectMarker inserts p.Inject before </head> (else </body>, else prepends).
func (p *Policy) injectMarker(body []byte) []byte {
	if len(p.Inject) == 0 || bytes.Contains(body, p.Inject) {
		return body
	}
	for _, tag := range [][]byte{[]byte("</head>"), []byte("</body>")} {
		if i := bytes.Index(bytes.ToLower(body), bytes.ToLower(tag)); i >= 0 {
			out := make([]byte, 0, len(body)+len(p.Inject))
			out = append(out, body[:i]...)
			out = append(out, p.Inject...)
			out = append(out, body[i:]...)
			return out
		}
	}
	return append(append([]byte{}, p.Inject...), body...)
}

// ── JA4 ClientHello capture (the Go-feasibility proof for the ja4 addon) ─────

// ja4ish builds a compact handshake fingerprint from the fields crypto/tls
// exposes in ClientHelloInfo (SNI, TLS versions, cipher count, ALPN). A FULL
// JA4 also needs the extension list, which requires a raw-ClientHello-bytes
// peek before stdlib parsing — feasible (Phase 4); this proves the material is
// reachable in Go without Python.
func ja4ish(h *tls.ClientHelloInfo) string {
	maxVer := uint16(0)
	for _, v := range h.SupportedVersions {
		if v > maxVer {
			maxVer = v
		}
	}
	alpn := "none"
	if len(h.SupportedProtos) > 0 {
		alpn = h.SupportedProtos[0]
	}
	return fmt.Sprintf("t%04x_c%02d_a%s_sni=%s", maxVer, len(h.CipherSuites), alpn, h.ServerName)
}

// ── CONNECT-proxy MITM wiring ────────────────────────────────────────────────

type Proxy struct {
	ca     *CA
	pol    *Policy
	jaSink func(string) // JA4 observations (logged; a sidecar in prod)
	jarKey []byte       // anti-track HMAC fake-identity seed (nil → poison off)
	poison bool         // master gate: poison tracker Set-Cookies (default on when jarKey present)
}

func (px *Proxy) serverTLSConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if px.jaSink != nil {
				px.jaSink(ja4ish(h)) // capture handshake fingerprint
			}
			name := h.ServerName
			if name == "" {
				name = "unknown.local"
			}
			return px.ca.forge(name)
		},
	}
}

func (px *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Hostname()
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "no hijack", 500)
		return
	}
	client, _, err := hj.Hijack()
	if err != nil {
		return
	}
	defer client.Close()
	io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n")

	// Decide once on (host, sni). For the CONNECT PoC the SNI is the CONNECT
	// host; the transparent engine will splice on the real ClientHello SNI.
	verdict := px.pol.Decide(host, host)

	if verdict == "splice" {
		// passthrough: raw TCP to upstream, no TLS interception (tls_splice).
		up, err := net.DialTimeout("tcp", r.URL.Host, 10*time.Second)
		if err != nil {
			return
		}
		defer up.Close()
		go io.Copy(up, client)
		io.Copy(client, up)
		return
	}

	// MITM: TLS-terminate the client with a forged cert (+ ClientHello capture).
	tconn := tls.Server(client, px.serverTLSConfig())
	if err := tconn.Handshake(); err != nil {
		return
	}
	defer tconn.Close()
	br := newReader(tconn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	req.URL.Scheme, req.URL.Host = "https", r.URL.Host

	if verdict == "block" {
		writeRaw(tconn, 204, "No Content", map[string]string{"X-SecuBox-Ng": "blocked"}, nil)
		return
	}

	// ── verdict ∈ {"allow","mitm"} → intercept normally ──────────────────────
	//
	// allow  → own-infra / allowlist: clean MITM, apply NO block/poison.
	// mitm   → intercept + apply the response handlers (poison if a tracker).
	//
	// Always-on hygiene: anonymize the request on EVERY MITM'd flow (incl.
	// allow — stripping operator headers + asserting opt-out is universally
	// safe and never touches own-infra correctness).
	clientHash := clientHashFromConn(client) // PoC: peer IP — TODO(#662 P6): mac_hash
	anonymizeRequest(req.Header)

	// proxy upstream, inject into HTML bodies.
	up := &http.Client{Timeout: 30 * time.Second}
	req.RequestURI = ""
	resp, err := up.Do(req)
	if err != nil {
		writeRaw(tconn, 502, "Bad Gateway", nil, nil)
		return
	}
	defer resp.Body.Close()

	// Poison: only on MITM'd tracker flows (never on allow/own-infra), and only
	// when the jar key is loaded. Replaces tracking-id Set-Cookie values with a
	// stable fabricated persona; benign cookies pass through untouched.
	if verdict == "mitm" && px.poison && len(px.jarKey) > 0 && px.pol.shouldPoison(host) {
		if sc := resp.Header.Values("Set-Cookie"); len(sc) > 0 {
			poisoned := poisonSetCookies(sc, clientHash, host, px.jarKey)
			resp.Header.Del("Set-Cookie")
			for _, c := range poisoned {
				resp.Header.Add("Set-Cookie", c)
			}
		}
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
		body = px.pol.injectMarker(body)
	}
	writeResponse(tconn, resp, body)
}

func main() {
	caCert := flag.String("ca-cert", "/etc/secubox/toolbox/ca-wg/ca.pem", "CA cert PEM")
	caKey := flag.String("ca-key", "/etc/secubox/toolbox/ca-wg/key.pem", "CA key PEM")
	addr := flag.String("listen", ":8090", "CONNECT proxy listen addr")
	jarKeyPath := flag.String("jar-key", "/etc/secubox/secrets/privacy-jar.key",
		"anti-track HMAC fake-identity seed (poison disabled if absent)")
	poison := flag.Bool("poison", true,
		"poison tracking Set-Cookies on MITM'd tracker flows (needs --jar-key; never touches allow/own-infra)")
	flag.Parse()
	ca, err := loadCA(*caCert, *caKey)
	if err != nil {
		log.Fatalf("CA load: %v", err)
	}
	// Load the BLOCK/SPLICE policy from the SAME on-disk config the Python
	// addons read (defaults + env overrides). Missing files are tolerated
	// (best-effort, like the addons): the engine then simply MITMs everything.
	pol, err := LoadPolicy(PolicyOpts{})
	if err != nil {
		log.Fatalf("policy load: %v", err)
	}
	pol.Inject = []byte("<!-- sbx-ng banner -->")
	// Anti-track jar seed: best-effort (like the Python _jar_key). Absent/empty
	// → loadJarKey returns nil → poison stays off even if --poison is set.
	jarKey := loadJarKey(*jarKeyPath)
	if *poison && len(jarKey) == 0 {
		log.Printf("poison requested but jar key %s absent/empty → poison OFF", *jarKeyPath)
	}
	px := &Proxy{
		ca:     ca,
		pol:    pol,
		jaSink: func(s string) { log.Printf("ja4 %s", s) },
		jarKey: jarKey,
		poison: *poison,
	}
	srv := &http.Server{Addr: *addr, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			px.handleConnect(w, r)
			return
		}
		http.Error(w, "CONNECT only (PoC)", 405)
	})}
	log.Printf("sbxmitm PoC listening on %s (CA %s)", *addr, *caCert)
	log.Fatal(srv.ListenAndServe())
}
