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
		// #689 — forged leaves must outlive the (non-evicting) cert cache, else a
		// long-running worker keeps serving an expired leaf and every client
		// reports "certificat expiré". 365d forward + 48h back-skew = 367d span,
		// safely under Apple's 398-day max-validity rule for server certs.
		NotBefore:    time.Now().Add(-48 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
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
	ca      *CA
	pol     *Policy
	jaSink  func(string)  // JA4 observations (logged; a sidecar in prod)
	jarKey  []byte        // anti-track HMAC fake-identity seed (nil → poison off)
	poison  bool          // master gate: poison tracker Set-Cookies (default on when jarKey present)
	portal  string        // portal base URL for /__toolbox/* reverse-proxy (banner assets)
	ads     *adStats      // #662 — ad-block metrics aggregator (flushed to the portal)
	cand    *adCandidates // #662 — ad-candidate learning feed (flushed with ads to the portal)
	pin     *pinCandidates // #740 — cert-pinning splice candidates (rides the ad-event flush)
	cspDemo bool          // #662 CONSENTED-DEMONSTRATION: relax a page's CSP so the injected loader runs, and flag the bypass (data-csp=1 → 🔓). Default on.

	// analysisRelay gates the per-flow telemetry relay to the dpi/cookies/ja4
	// analysis sidecar sockets (#662 — restoring the "Qui te piste?" events the
	// decommissioned Python addons fed). Default on; relay.go is the transport.
	analysisRelay bool

	// socialRelay gates the cross-site cookie-tracker correlation (#662 — restoring
	// the kbin /social graph the decommissioned Python social_graph addon fed).
	// Default on. social.go is the engine; edges are batched + POSTed to the
	// portal's /__toolbox/social-event ingest. nil → off (CONNECT PoC / tests).
	socialRelayOn bool
	social        *socialRelay
	consent       *consentLog
}

// recordAdBlock forwards a 204'd ad/tracker block to the engine's metrics
// aggregator (#662). Nil-safe so the CONNECT PoC (no aggregator) and tests can
// run the block path without one. Non-blocking (the aggregator is O(1)).
func (px *Proxy) recordAdBlock(adHost, site, macHash string) {
	if px.ads != nil {
		px.ads.recordAdBlock(adHost, site, macHash)
	}
}

// maybeRecordAdCandidate feeds the auto-learn loop (#662): on the allow/mitm
// path (NOT block — already caught; NOT allowlisted/own-infra), it records an
// ad-candidate (host, site) when the request is 3rd-party
// (registrable(host) != registrable(site)) AND the path smells like an ad/track
// endpoint (adPathRE). It is the engine port of ad_ghost's candidate capture —
// the feed secubox-toolbox-autolearn promotes into learned-trackers.txt at
// AD_MIN_SITES distinct sites. Gated behind the analysis/ad relay flag, O(1) hot
// path, fire-and-forget, nil-safe (CONNECT PoC / tests with no feed).
func (px *Proxy) maybeRecordAdCandidate(host, site, path string) {
	if px == nil || px.cand == nil || !px.relayEnabled() || px.pol == nil {
		return
	}
	if site == "" || host == "" {
		return // no 1st-party context (no Referer) → nothing to attribute.
	}
	if px.pol.allowedSafe(host) {
		return // own-infra / allowlist: never learn our own / trusted hosts.
	}
	if registrable(host) == registrable(site) {
		return // 1st-party request: not a cross-site ad/track signal.
	}
	if !adPathRE.MatchString(path) {
		return // path doesn't look like an ad/track endpoint.
	}
	px.cand.record(host, site)
}

func (px *Proxy) serverTLSConfig() *tls.Config {
	return px.serverTLSConfigCapture(nil)
}

// serverTLSConfigCapture is serverTLSConfig with an extra per-handshake hook:
// capture, if non-nil, is invoked inside GetCertificate with the live
// *tls.ClientHelloInfo (SNI, SupportedProtos, CipherSuites). The accept-path
// handlers use it to relay the ja4 ClientHello payload (relay.go) WITH the
// client conn's peer IP — which is known at the handler, not inside the TLS
// config. Passing nil yields the plain forging config (CONNECT PoC, tests).
func (px *Proxy) serverTLSConfigCapture(capture func(*tls.ClientHelloInfo)) *tls.Config {
	return &tls.Config{
		GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if px.jaSink != nil {
				px.jaSink(ja4ish(h)) // capture handshake fingerprint
			}
			if capture != nil {
				capture(h) // ja4 relay material (peer IP threaded in by the handler)
			}
			name := h.ServerName
			if name == "" {
				name = "unknown.local"
			}
			return px.ca.forge(name)
		},
	}
}

// peerIP returns the remote IP (no port) of a client conn, the same basis as
// clientHashFromConn. Used as the client_ip field of every relay payload.
func peerIP(conn net.Conn) string {
	if conn == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return conn.RemoteAddr().String()
	}
	return host
}

// captureAndEmitJA4 returns a GetCertificate capture hook that relays the ja4
// ClientHello payload for THIS handshake (once), tagged with the given client
// conn's peer IP + mac-hash-aware clientHash. Gated by analysisRelay (emitJA4
// checks). The hook copies the ClientHelloInfo fields it needs immediately
// (the struct is only valid during the callback). Returns nil when the relay is
// off so the plain config is used (no per-handshake allocation).
func (px *Proxy) captureAndEmitJA4(rawClient net.Conn) func(*tls.ClientHelloInfo) {
	if !px.relayEnabled() {
		return nil
	}
	ip := peerIP(rawClient)
	hash := clientHashFromConn(rawClient)
	return func(h *tls.ClientHelloInfo) {
		alpn := append([]string(nil), h.SupportedProtos...)
		ciphers := append([]uint16(nil), h.CipherSuites...)
		px.emitJA4(ip, hash, h.ServerName, alpn, ciphers)
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
	// The capture hook relays the ja4 ClientHello payload for this handshake,
	// tagged with the client's peer IP (#662). nil when the relay gate is off.
	tconn := tls.Server(client, px.serverTLSConfigCapture(px.captureAndEmitJA4(client)))
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
	// original-dst by the uchromeTransport. We do NOT put the bare ip:port in
	// req.URL.Host (that would make the upstream verify the cert against the IP).
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
		// #662 — the cross-site tracking evidence lives PRECISELY on the blocked
		// trackers: the browser still SENT its 3rd-party Cookie to doubleclick/
		// adnxs/… before we 204 it. Correlate that request-Cookie here (resp=nil,
		// request-only) or the /social graph misses the very trackers it exists to
		// expose. Hash-only, WG-peer only, fire-and-forget — same as the allow path.
		px.emitSocial(peerIP(rawClient), host, req, nil)
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

	// #662 — relay the DPI classification hint for this MITM'd request (allow|mitm
	// only; never the block 204 / splice paths). Fire-and-forget BEFORE anonymize
	// mutates headers, so we relay the client's original User-Agent (the Python
	// DPIRelay ran on the unmodified request). Gated by --analysis-relay; a
	// dead/slow dpi.sock can never block or delay the proxy flow.
	relayIP := peerIP(rawClient)
	px.emitDPI(relayIP, clientHash, host, req)

	// #662 — feed the auto-learn loop: on this allow/mitm flow, record an
	// ad-candidate when the request is 3rd-party AND its path smells like an
	// ad/track endpoint (ad_ghost's _AD_PATH heuristic). site = registrable of
	// the Referer (the ad_ghost _site_of flavour). Done BEFORE anonymize mutates
	// headers (so the Referer is the client's original). O(1), gated,
	// fire-and-forget — a new adware host gets observed here, promoted by
	// autolearn, then blocked+smogged after the policy live-reloads it.
	px.maybeRecordAdCandidate(host, refererSite(req.Header.Get("Referer")), req.URL.Path)

	anonymizeRequest(req.Header)

	// #662 — do NOT touch Accept-Encoding. We FORWARD the client's original
	// header untouched: a real browser sends `gzip, deflate, br, zstd`, and
	// overriding it (the old `Set("Accept-Encoding","gzip")`) is itself a bot
	// tell that anti-bot vendors fingerprint on. The inject path
	// (injectIntoBody) now decodes/re-encodes br + zstd in addition to gzip, so
	// preserving the real AE no longer costs us injection. If the client sent no
	// AE we add none — the uTLS Chrome upstream transport never auto-injects one,
	// so non-HTML bodies still stay compressed end-to-end exactly as the origin
	// chose.

	// proxy upstream, inject into HTML bodies.
	//
	// #662 — the upstream TLS is now a uTLS Chrome-fingerprinted RoundTripper
	// (uchromeTransport): the upstream ClientHello presents a current Chrome
	// JA3/JA4 to defeat DataDome / anti-bot blocking, WITHOUT splicing (full body
	// inspection + cert verification preserved). The dial is pinned exactly as
	// before — transparent (dialHost != "") → the captured original-dst, CONNECT
	// (dialHost == "") → req.URL.Host — and the cert is verified against the
	// SNI/Host (here `host`), never the bare IP.
	//
	// CheckRedirect: a MITM proxy must NOT follow 3xx itself — it relays the
	// redirect to the client so the BROWSER follows it (correct URL bar, origin,
	// cookie scope, method semantics). Go's http.Client follows by default, which
	// would collapse a 301/302 into the final 200 under the original URL (wrong).
	// Mirror mitmproxy's pass-through behaviour.
	up := &http.Client{
		Timeout:       30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport:     newUchromeTransport(dialHost, host),
	}
	req.RequestURI = ""
	resp, err := up.Do(req)
	if err != nil {
		writeRaw(tconn, 502, "Bad Gateway", nil, nil)
		return
	}
	defer resp.Body.Close()

	// #662 — relay the cookie metadata for this MITM'd response (allow|mitm only).
	// NAMES ONLY (never values — privacy/CSPN); no-op unless ≥1 Set-Cookie OR ≥1
	// request Cookie is present. Emitted before poison rewrites Set-Cookie VALUES,
	// which is irrelevant here (names are unchanged by poison) but keeps the
	// relayed names byte-for-byte the origin's. Fire-and-forget, gated.
	px.emitCookies(relayIP, clientHash, req, resp)

	// #662 — cross-site cookie-tracker correlation (restores the kbin /social
	// graph). FAITHFUL to the decommissioned Python social_graph addon: extract
	// 3rd-party cookie edges (Set-Cookie + request Cookie), hash the identifier
	// (cookieIDHash — NEVER the raw value), classify consent_state, and buffer
	// them for the batched POST to the portal /__toolbox/social-event ingest.
	// Like the addon, this ONLY fires for known R3 WG peers (macHashOf, not the
	// raw-IP fallback): non-WG flows yield no edges. allow|mitm only (the block
	// 204 / splice paths return before here). Gated by --social-relay; pure +
	// non-blocking (the flush is a background goroutine).
	px.emitSocial(relayIP, host, req, resp)

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

	// #662 — strip Alt-Svc so the browser is never told this origin offers HTTP/3
	// (h3). With h3 unadvertised it keeps using HTTP/2 over TCP, which we MITM;
	// otherwise it caches "h3 available" and keeps trying QUIC (UDP 443) — which
	// bypasses this TCP proxy and is only best-effort blocked by the nft reject.
	resp.Header.Del("Alt-Svc")

	// We only ever rewrite 2xx text/html (the transparency-banner inject).
	// EVERYTHING else — JSON/protobuf APIs, images, downloads, mail bodies,
	// video — must pass through byte-for-byte. Buffering them capped at 8 MiB was
	// silently TRUNCATING any larger response (#697: Gmail messages/attachments
	// over the tunnel just stopped rendering). Stream those verbatim.
	injectEligible := resp.StatusCode >= 200 && resp.StatusCode < 300 &&
		strings.Contains(resp.Header.Get("Content-Type"), "text/html")
	if !injectEligible {
		streamResponse(tconn, resp, nil)
		return
	}

	// Inject path: buffer up to the cap (+1 so we DETECT an oversized page instead
	// of truncating it). The body may be compressed in whatever codec the origin
	// chose (Accept-Encoding is forwarded verbatim). injectIntoBody
	// decodes→injects→re-encodes for gzip/br/zstd (encoding unchanged), injects
	// directly when identity, and fails open (untouched) on a corrupt/unknown
	// encoding.
	const injectCap = 8 << 20
	body, _ := io.ReadAll(io.LimitReader(resp.Body, injectCap+1))
	if int64(len(body)) > injectCap {
		// HTML larger than the inject buffer: never serve a truncated inject —
		// stream the peeked bytes plus the remainder verbatim.
		streamResponse(tconn, resp, body)
		return
	}
	// #662 CONSENTED-DEMONSTRATION — ONLY here, on the responses we actually inject
	// into, and ONLY when the operator left the demo on, do we relax the page's CSP
	// so the inline banner runs even on strict-CSP sites. Never on non-injected
	// responses. cspBypassed becomes csp=1 on the inline script (banner shows 🔓).
	cspBypassed := false
	if px.cspDemo {
		cspBypassed = relaxCSPForLoader(resp.Header)
	}
	// #662 — INLINE the banner (supersedes the <script src="/__toolbox/loader.js">
	// tag): sites with a SERVICE WORKER hijack the same-origin src before it
	// reaches this engine. We fetch the COMPLETE script body from the portal
	// server-side and bake it into a self-contained <script>. Fail-open: a
	// dead/slow portal → scriptBody=="" → inject skipped, page served intact.
	scriptBody, _ := fetchInlineBanner(px.portal, clientHash, wg, cspBypassed)
	injHost := ""
	if resp.Request != nil {
		injHost = resp.Request.Host
	}
	if out, ok := injectIntoBody(body, resp.Header.Get("Content-Encoding"), scriptBody, wg, injHost); ok {
		body = out
		// Keep framing consistent with the served bytes (only the length changed).
		resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
		resp.ContentLength = int64(len(body))
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
	transparent := flag.Bool("transparent", false,
		"transparent mode: accept nft-DNAT'd conns + recover SO_ORIGINAL_DST (live R3); default is the CONNECT proxy PoC")
	portal := flag.String("portal", "http://127.0.0.1:8088",
		"portal base URL; /__toolbox/loader.js + /__toolbox/bundle are reverse-proxied here (banner assets, served for any MITM'd origin)")
	cspDemo := flag.Bool("csp-bypass-demo", true,
		"CONSENTED DEMONSTRATION: relax a page's CSP so the injected transparency-banner loader runs even on strict-CSP sites, and flag the bypass (banner shows 🔓). Only on injected 2xx text/html R3 responses; never on non-injected responses. Set false to never touch CSP.")
	analysisRelay := flag.Bool("analysis-relay", true,
		"relay per-flow telemetry (dpi/cookies/ja4) to the analysis sidecar sockets so the kbin \"Qui te piste?\" events refill (#662; replaces the decommissioned Python relay addons). Fire-and-forget; a dead/slow sidecar never affects the proxy. Set false to emit nothing.")
	socialRelay := flag.Bool("social-relay", true,
		"compute cross-site cookie-tracker edges and POST them to the portal /__toolbox/social-event ingest so the kbin /social graph refills (#662; replaces the decommissioned Python social_graph addon). Hash-only (never raw cookie values); WG-peer flows only; batched + fire-and-forget — a dead/slow portal never affects the proxy. Set false to emit nothing.")
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
		ca:      ca,
		pol:     pol,
		jaSink:  func(s string) { log.Printf("ja4 %s", s) },
		jarKey:  jarKey,
		poison:  *poison,
		portal:  *portal,
		ads:     newAdStats(),
		cand:    newAdCandidates(),
		pin:     newPinCandidates(),
		cspDemo: *cspDemo,

		analysisRelay: *analysisRelay,

		socialRelayOn: *socialRelay,
		social:        newSocialRelay(),
		consent:       newConsentLog(),
	}
	// #662 — start the social-edge flusher: the MITM path buffers cross-site
	// tracker edges into px.social, drained every 10s to the portal's
	// /__toolbox/social-event (best-effort, fire-and-forget) so the kbin /social
	// graph (frozen since the cutover) refills.
	go px.social.runFlusher(*portal)
	// #662 — start the ad-block metrics flusher: the block path tallies every
	// 204 into px.ads, drained every 10s to the portal's /__toolbox/ad-event
	// (best-effort, fire-and-forget) so the #ads dashboard sees blocks again.
	// #662 — the candidate feed (px.cand) is drained in the SAME flush so the
	// learning candidates ride the existing ad-event channel (one POST / 10s).
	// #740 — px.pin (cert-pinning splice candidates, recorded on a client cert
	// rejection in handleTransparent) is drained in the SAME flush too.
	go px.ads.runAdStatsFlusher(*portal, px.cand, px.pin)
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
