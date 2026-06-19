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
	"context"
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
	"strconv"
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
	// Scan for the right block TYPE rather than assuming position: the live R3
	// CA the toolbox forges with (mitmproxy confdir `mitmproxy-ca.pem`) is a
	// COMBINED cert+key bundle, and --ca-key may point at it. Tolerate cert and
	// key co-residing in either file, in any order.
	cblk := firstPEMBlock(cpem, func(b *pem.Block) bool { return b.Type == "CERTIFICATE" })
	if cblk == nil {
		return nil, fmt.Errorf("ca cert: no CERTIFICATE PEM block")
	}
	cert, err := x509.ParseCertificate(cblk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse ca cert: %w", err)
	}
	kblk := firstPEMBlock(kpem, func(b *pem.Block) bool { return strings.Contains(b.Type, "PRIVATE KEY") })
	if kblk == nil {
		return nil, fmt.Errorf("ca key: no PRIVATE KEY PEM block")
	}
	key, err := parseKey(kblk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse ca key: %w", err)
	}
	return &CA{cert: cert, key: key, cache: map[string]*tls.Certificate{}}, nil
}

// firstPEMBlock returns the first PEM block in data satisfying want, or nil.
// Used to pull a specific block (CERTIFICATE / PRIVATE KEY) out of a file that
// may hold several (e.g. mitmproxy's combined CA bundle).
func firstPEMBlock(data []byte, want func(*pem.Block) bool) *pem.Block {
	for {
		blk, rest := pem.Decode(data)
		if blk == nil {
			return nil
		}
		if want(blk) {
			return blk
		}
		data = rest
	}
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
	portal string       // portal base URL for /__toolbox/* reverse-proxy (banner assets)
	ads    *adStats     // #662 — ad-block metrics aggregator (flushed to the portal)
}

// recordAdBlock forwards a 204'd ad/tracker block to the engine's metrics
// aggregator (#662). Nil-safe so the CONNECT PoC (no aggregator) and tests can
// run the block path without one. Non-blocking (the aggregator is O(1)).
func (px *Proxy) recordAdBlock(adHost, site, macHash string) {
	if px.ads != nil {
		px.ads.recordAdBlock(adHost, site, macHash)
	}
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

	// Shared post-TLS pipeline. CONNECT dials upstream by the request URL host
	// (req.URL.Host set inside), so dialHost is "" → mitmPipeline derives it.
	// CONNECT PoC is never an R3 WG client → wg=false.
	px.mitmPipeline(tconn, client, host, verdict, "", false)
}

// mitmPipeline runs the shared post-TLS-handshake MITM logic used by BOTH the
// CONNECT path (handleConnect) and the transparent path (handleTransparent):
// read the decrypted request, apply the verdict, anonymize, proxy upstream,
// poison tracker Set-Cookies, inject into HTML, and write the response back over
// tconn. Factored out so the two accept paths never drift.
//
//   - tconn      : the TLS-terminated client connection (forged leaf).
//   - rawClient  : the underlying client net.Conn (for the per-client identity).
//   - host       : the decision host (CONNECT host / transparent SNI). Also the
//     Host/SNI used for the upstream request and TLS verification.
//   - verdict    : the already-Decided action ∈ {allow, mitm, block}.
//   - dialHost   : upstream "ip:port" to FORCE-dial at the TCP layer. "" →
//     CONNECT semantics: dial by req.URL.Host (the request URL / host). Non-""
//     → transparent: TCP-connect the captured original-dst while doing TLS with
//     ServerName=host and verifying the cert against host (not the bare IP).
//   - wg         : the client is an R3 WireGuard peer (10.99.1.0/24); threaded
//     into the injected loader's data-wg attribute. CONNECT path passes false.
func (px *Proxy) mitmPipeline(tconn *tls.Conn, rawClient net.Conn, host, verdict, dialHost string, wg bool) {
	br := newReader(tconn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	req.URL.Scheme = "https"
	if req.URL.Host == "" {
		req.URL.Host = host
	}

	// #636/#662 — serve the banner loader + bundle for ANY origin so the injected
	// <script src="/__toolbox/loader.js"> resolves (R3 clients hit arbitrary
	// hosts whose origin can't serve /__toolbox/*). Short-circuit BEFORE dialing
	// the real upstream by reverse-proxying to the portal. Mirrors the Python
	// InjectBanner.request() startswith checks (path includes the query string).
	if isToolboxAssetPath(req.URL.RequestURI()) {
		servePortalAsset(tconn, px.portal, req.URL.RequestURI())
		return
	}
	// Transparent: the upstream request must carry the SNI host (for Host header,
	// SNI, and cert verification); the actual TCP dial is pinned to the captured
	// original-dst by transparentTransport. We do NOT put the bare ip:port in
	// req.URL.Host (that would make http.Client verify the cert against the IP).
	if dialHost != "" && host != "" {
		req.URL.Host = host
	}

	if verdict == "block" {
		// #662 — tally the block BEFORE writing the 204 so the #ads dashboard
		// (frozen since the cutover) sees it again. site = registrable(Referer)
		// (the ad_ghost _site_of flavour); empty when there is no Referer. The
		// per-client breakdown keys on the WG persona hash. recordAdBlock is
		// O(1) and never blocks the block path.
		px.recordAdBlock(host, refererSite(req.Header.Get("Referer")), clientHashFromConn(rawClient))
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
	clientHash := clientHashFromConn(rawClient) // mac_hash-aware (WG persona)
	anonymizeRequest(req.Header)

	// #662 — pin the upstream Accept-Encoding to gzip (overwrite, dropping
	// br/zstd/deflate we cannot decode with the stdlib). This guarantees every
	// response is either gzip or identity, so the inject path can reliably
	// gunzip→inject→re-gzip the HTML. We Set (not Del): Del would make Go's
	// Transport auto-decompress and re-serve identity, losing wire compression
	// to the client for ALL resources (incl. non-injected ones). Set keeps the
	// Transport in pass-through mode so non-HTML bodies stay compressed
	// end-to-end. Browsers always accept gzip, so relaying gzip back is safe.
	req.Header.Set("Accept-Encoding", "gzip")

	// proxy upstream, inject into HTML bodies.
	//
	// CheckRedirect: a MITM proxy must NOT follow 3xx itself — it relays the
	// redirect to the client so the BROWSER follows it (correct URL bar, origin,
	// cookie scope, method semantics). Go's http.Client follows by default, which
	// would collapse a 301/302 into the final 200 under the original URL (wrong).
	// Mirror mitmproxy's pass-through behaviour.
	up := &http.Client{
		Timeout:       30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	if dialHost != "" {
		// Transparent: pin the TCP dial to the captured original-dst, do TLS with
		// ServerName=host, verify the cert against host (verification stays ON).
		up.Transport = transparentTransport(dialHost, host)
	}
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
	// Inject the transparency-banner loader only on 2xx text/html responses
	// (mirrors the Python addon, which skips non-200). The loader's same-origin
	// <script src="/__toolbox/loader.js"> is served by the short-circuit above.
	//
	// #662 — the body may be gzip-compressed (we pinned Accept-Encoding: gzip
	// upstream). injectIntoBody gunzips→injects→re-gzips when Content-Encoding
	// is gzip, injects directly when identity, and fails open (untouched) on a
	// corrupt/unknown encoding. Only on a successful rewrite do we update the
	// framing: writeResponse emits Content-Length from len(body), but a stale
	// resp.ContentLength / Content-Encoding could mislead downstream — so we
	// keep them consistent with the bytes we actually serve.
	if resp.StatusCode >= 200 && resp.StatusCode < 300 &&
		strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
		if out, ok := injectIntoBody(body, resp.Header.Get("Content-Encoding"), clientHash, wg); ok {
			body = out
			// Keep the response framing consistent with the served bytes. The
			// encoding is unchanged (gzip stays gzip, identity stays identity);
			// only the length changed because injection grew the body. A stale
			// Content-Length would truncate/corrupt the response.
			resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
			resp.ContentLength = int64(len(body))
		}
	}
	writeResponse(tconn, resp, body)
}

// transparentTransport builds a per-request http.Transport for the transparent
// path: it TCP-dials the captured original-dst (ip:port) for EVERY connection
// regardless of req.URL.Host, while performing TLS with ServerName=sni and
// verifying the cert against that name — so a transparently-redirected upstream
// is reached at the real captured IP yet validated by hostname, NOT the bare IP
// (which would always mismatch the cert). Cert verification stays ON
// (no InsecureSkipVerify). Pure stdlib so it builds on all GOOS.
func transparentTransport(dialAddr, sni string) *http.Transport {
	d := &net.Dialer{Timeout: 10 * time.Second}
	return &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return d.DialContext(ctx, network, dialAddr)
		},
		TLSClientConfig:       &tls.Config{ServerName: sni},
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ForceAttemptHTTP2:     false,
	}
}

func main() {
	caCert := flag.String("ca-cert", "/etc/secubox/toolbox/ca-wg/ca.pem", "CA cert PEM")
	caKey := flag.String("ca-key", "/etc/secubox/toolbox/ca-wg/key.pem", "CA key PEM")
	addr := flag.String("listen", ":8090", "CONNECT proxy listen addr")
	jarKeyPath := flag.String("jar-key", "/etc/secubox/secrets/privacy-jar.key",
		"anti-track HMAC fake-identity seed (poison disabled if absent)")
	poison := flag.Bool("poison", true,
		"poison tracking Set-Cookies on MITM'd tracker flows (needs --jar-key; never touches allow/own-infra)")
	transparent := flag.Bool("transparent", false,
		"transparent mode: accept nft-DNAT'd conns + recover SO_ORIGINAL_DST (live R3); default is the CONNECT proxy PoC")
	portal := flag.String("portal", "http://127.0.0.1:8088",
		"portal base URL; /__toolbox/loader.js + /__toolbox/bundle are reverse-proxied here (banner assets, served for any MITM'd origin)")
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
		portal: *portal,
		ads:    newAdStats(),
	}
	// #662 — start the ad-block metrics flusher: the block path tallies every
	// 204 into px.ads, drained every 10s to the portal's /__toolbox/ad-event
	// (best-effort, fire-and-forget) so the #ads dashboard sees blocks again.
	go px.ads.runAdStatsFlusher(*portal)
	if *transparent {
		// Transparent R3 mode: raw accept loop, each conn carries its pre-DNAT
		// destination via SO_ORIGINAL_DST (recovered in handleTransparent). The
		// accept loop lives in runTransparent — linux-tagged, with a non-linux
		// stub so the package still builds (and `darwin go build`) off-target.
		runTransparent(px, *addr)
		return
	}

	srv := &http.Server{Addr: *addr, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			px.handleConnect(w, r)
			return
		}
		http.Error(w, "CONNECT only (PoC)", 405)
	})}
	log.Printf("sbxmitm CONNECT PoC listening on %s (CA %s)", *addr, *caCert)
	log.Fatal(srv.ListenAndServe())
}
