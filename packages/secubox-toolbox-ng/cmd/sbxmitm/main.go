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
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/forge"
	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/sentinel"
)

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

// ja4stack is the SNI-INDEPENDENT part of ja4ish: a client-TLS-stack
// fingerprint (max version, cipher-suite count, first ALPN) with NO server
// name. Unlike ja4ish (which embeds the destination SNI, so it varies per
// host), ja4stack is stable across every flow from the same client stack, so
// it can distinguish a browser from a non-browser client — the input the
// Sentinel C2 auto-learn "non_browser_ja" signal (and browser-ja4.txt) needs.
//
// NOTE: this is an ad-hoc "stack" fingerprint (crypto/tls exposes no raw
// ClientHello bytes, so a spec-compliant JA4 hash isn't computable in pure
// Go here). It is self-consistent — the SENTINEL_JA4_CAPTURE recorder writes
// this exact format into browser-ja4.txt and the signal compares against it —
// but it is NOT interchangeable with a public JA4 blocklist's hashes.
func ja4stack(h *tls.ClientHelloInfo) string {
	if h == nil {
		return ""
	}
	// GREASE values (RFC 8701) are randomly injected by browsers into the
	// version and cipher lists; they MUST be excluded or the fingerprint jitters
	// per handshake (e.g. max version flips between 0x0304 and a GREASE 0xfafa).
	maxVer := uint16(0)
	for _, v := range h.SupportedVersions {
		if isGREASE(v) {
			continue
		}
		if v > maxVer {
			maxVer = v
		}
	}
	nCiphers := 0
	for _, c := range h.CipherSuites {
		if !isGREASE(c) {
			nCiphers++
		}
	}
	alpn := "none"
	if len(h.SupportedProtos) > 0 {
		alpn = h.SupportedProtos[0]
	}
	return fmt.Sprintf("t%04x_c%02d_a%s", maxVer, nCiphers, alpn)
}

// isGREASE reports whether v is a TLS GREASE placeholder (RFC 8701): the 16
// values 0x0a0a, 0x1a1a, … 0xfafa — both bytes equal, each low nibble 0xa.
func isGREASE(v uint16) bool {
	return (v>>8) == (v&0xff) && (v&0x0f) == 0x0a
}

// ── CONNECT-proxy MITM wiring ────────────────────────────────────────────────

type Proxy struct {
	ca      *forge.CA
	pol     *Policy
	jaSink  func(string)   // JA4 observations (logged; a sidecar in prod)
	jarKey  []byte         // anti-track HMAC fake-identity seed (nil → poison off)
	poison  bool           // master gate: poison tracker Set-Cookies (default on when jarKey present)
	portal  string         // portal base URL for /__toolbox/* reverse-proxy (banner assets)
	ads     *adStats       // #662 — ad-block metrics aggregator (flushed to the portal)
	cand    *adCandidates  // #662 — ad-candidate learning feed (flushed with ads to the portal)
	pin     *pinCandidates // #740 — cert-pinning splice candidates (rides the ad-event flush)
	cspDemo bool           // #662 CONSENTED-DEMONSTRATION: relax a page's CSP so the injected loader runs, and flag the bypass (data-csp=1 → 🔓). Default on.

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

	// media is the R4 media reverse-catcher (#736): records cloneable media URLs
	// (manifests / direct audio-video) seen on MITM'd flows to a JSONL log the
	// mediaflow "Discovered Media" view reads. nil/disabled → no-op.
	media *mediaCatcher

	// mbuf is the R4 media BUFFER (#812): tees the actual bytes of whole-file
	// media up/downloads into a time-bounded rolling buffer on /data so an
	// admin/owner can replay a recent capture. Non-blocking (async writer +
	// drop-if-full) — never slows the proxied flow. nil/disabled → no-op.
	mbuf *MediaBuffer

	// swNeuter (#753) is the targeted Service-Worker neuter: for allow-listed
	// hosts it answers the SW script fetch with a self-unregistering SW so PWA
	// shells stop being SW-cached and the banner can be injected on the next nav.
	swNeuter *SWNeuter

	// sentinel (#823) is the inline threat-detection gate: it neutralizes
	// high-confidence known-infra IOC hits (block/strip/sinkhole) and mirrors the
	// rest to the async sbx-sentinel analyzer. nil-safe and fail-open — a
	// disabled/erroring hook is a transparent passthrough. See sentinel.go.
	sentinel *sentinelHook

	// rlevel (#rlevel-per-peer, Task 3) is the per-peer R-level clamp: it
	// ceilings the verdict px.pol.Decide already computed to what the calling
	// peer's mode allows (see decideForPeer, rlevel.go's clampVerdict). nil is
	// a TOTAL NO-OP — every existing test/PoC that builds a Proxy{} without
	// setting this field keeps today's exact behavior (raw px.pol.Decide).
	rlevel *PeerPolicy
}

// decideForPeer resolves the policy verdict for (host, sni) and, if a
// PeerPolicy is wired in (px.rlevel != nil), clamps it to the calling client's
// R-level (clientIP). Both accept paths (CONNECT/handleConnect and
// transparent/handleTransparent) call this SAME helper so they can never
// drift on how the clamp is applied. px.rlevel == nil is a total no-op:
// the result is exactly px.pol.Decide(host, sni), preserving current
// behavior for callers/tests that never set rlevel.
func (px *Proxy) decideForPeer(clientIP, host, sni string) string {
	v := px.pol.Decide(host, sni)
	if px.rlevel != nil {
		v = clampVerdict(px.rlevel.ModeForIP(clientIP), v)
	}
	return v
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
	return px.serverTLSConfigCapture(nil, nil)
}

// serverTLSConfigCapture is serverTLSConfig with an extra per-handshake hook:
// capture, if non-nil, is invoked inside GetCertificate with the live
// *tls.ClientHelloInfo (SNI, SupportedProtos, CipherSuites). The accept-path
// handlers use it to relay the ja4 ClientHello payload (relay.go) WITH the
// client conn's peer IP — which is known at the handler, not inside the TLS
// config. Passing nil yields the plain forging config (CONNECT PoC, tests).
func (px *Proxy) serverTLSConfigCapture(capture func(*tls.ClientHelloInfo), onJA4 func(string)) *tls.Config {
	return &tls.Config{
		GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if px.jaSink != nil {
				px.jaSink(ja4ish(h)) // capture handshake fingerprint
			}
			if onJA4 != nil {
				onJA4(ja4stack(h)) // SNI-independent stack fp → Sentinel FlowMeta.JA4
			}
			if capture != nil {
				capture(h) // ja4 relay material (peer IP threaded in by the handler)
			}
			name := h.ServerName
			if name == "" {
				name = "unknown.local"
			}
			return px.ca.Forge(name)
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

	// Decide once on (host, sni), clamped to the calling peer's R-level (#rlevel
	// -per-peer). For the CONNECT PoC the SNI is the CONNECT host; the
	// transparent engine will splice on the real ClientHello SNI.
	verdict := px.decideForPeer(peerIP(client), host, host)

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
	var ja4 string // SNI-independent client-stack fp, captured at handshake below
	tconn := tls.Server(client, px.serverTLSConfigCapture(px.captureAndEmitJA4(client),
		func(s string) { ja4 = s }))
	if err := tconn.Handshake(); err != nil {
		return
	}
	defer tconn.Close()

	// Shared post-TLS pipeline. CONNECT dials upstream by the request URL host
	// (req.URL.Host set inside), so dialHost is "" → mitmPipeline derives it.
	// CONNECT PoC is never an R3 WG client → wg=false.
	px.mitmPipeline(tconn, client, host, verdict, "", false, ja4)
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
func (px *Proxy) mitmPipeline(tconn *tls.Conn, rawClient net.Conn, host, verdict, dialHost string, wg bool, ja4 string) {
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

	// #753 — targeted SW-neuter. For an allow-listed host, answer the
	// Service-Worker script fetch with a self-unregistering SW (the next
	// navigation bypasses the now-gone SW → reaches the MITM → banner). Off the
	// list, record the host as an auto-learn candidate. Only ever fires on the
	// `Service-Worker: script` request — normal traffic is untouched.
	if px.swNeuter != nil && isSWScriptRequest(req) {
		px.swNeuter.Maybe()
		if px.swNeuter.Match(host) {
			writeRaw(tconn, 200, "OK", map[string]string{
				"Content-Type":  "application/javascript",
				"Cache-Control": "no-store",
				"X-SecuBox-Ng":  "sw-neutered",
			}, []byte(NeuterSW))
			return
		}
		px.swNeuter.RecordCandidate(host)
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

	// WebSocket upgrade: the http.Client below cannot carry a 101 Switching
	// Protocols, so a wss:// on a MITM'd host would hang/fail (Socket.IO,
	// zigbee2mqtt, any real-time app behind wg-toolbox). Hand the flow to a raw
	// bidirectional pipe after forwarding the handshake. Done BEFORE
	// anonymize/DPI/inject: an upgrade is a control channel, not an inspectable
	// request, and the client's Sec-WebSocket-* handshake headers must reach
	// upstream untouched. `br` (the reader over tconn) may already hold buffered
	// client frames, so proxyWebSocket copies the client→upstream direction from
	// it, not from tconn.
	if isWebSocketUpgrade(req) {
		target, sni := wsDialTarget(req, dialHost, host)
		px.proxyWebSocket(tconn, br, req, target, sni)
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
	// #757 — SW revalidation nudge: for an allow-listed (sw-neuter) host, strip the
	// conditional headers off an HTML navigation / SW-revalidation request so the
	// upstream returns a full 200 (not a 304) → the MITM injects the banner →
	// a stale-while-revalidate SW caches a banner'd shell WITHOUT being neutered.
	// Cache-first SWs that never revalidate still need the #753 neuter.
	if px.swNeuter != nil && requestWantsHTML(req) && px.swNeuter.Match(host) {
		req.Header.Del("If-None-Match")
		req.Header.Del("If-Modified-Since")
	}
	// #812 R4 media buffer (upload) — if this MITM'd REQUEST is media, tee the
	// request body into the rolling buffer as the upstream reads it. Non-blocking:
	// the tee's ObjectWriter never errors/blocks, so a stuck buffer never affects
	// the upload; a nil writer is a no-op. The upstream transport closes req.Body,
	// which finalises the capture (w.Close). Only on non-splice allow|mitm flows
	// (splice returns far earlier).
	//
	// I1 whole-branch-review fix — req.Body is NEVER nil for a proxied request,
	// even a bodyless GET (net/http gives it http.NoBody), so a nil check alone
	// doesn't tell us there is an uploaded body. And IsMedia's mediaKind falls
	// back to classifying by PATH EXTENSION when the request Content-Type is
	// empty — so a plain media DOWNLOAD GET (e.g. GET /v.mp4) used to match
	// this UPLOAD branch on path alone, producing a phantom session dir, an
	// empty object-0.mp4 and a direction:"up", bytes:0 metatag on every
	// download. Require BOTH a real request body (ContentLength > 0 — a GET
	// download has no request body; this is the primary guard) AND a
	// non-empty request Content-Type that IsMedia matches ON THE CONTENT-TYPE,
	// so the path-extension fallback never drives the upload direction.
	if px.mbuf != nil && req.ContentLength > 0 {
		rct := req.Header.Get("Content-Type")
		if rct != "" && px.mbuf.IsMedia(rct, req.URL.Path) {
			if w := px.mbuf.Capture(clientHash, host,
				"https://"+host+req.URL.RequestURI(), req.URL.Path, rct, "up",
				req.ContentLength); w != nil {
				req.Body = teeReadCloser(req.Body, w)
			}
		}
	}
	resp, err := up.Do(req)
	if err != nil {
		writeRaw(tconn, 502, "Bad Gateway", nil, nil)
		return
	}
	// defer binds a plain method-value expression AT THE DEFER STATEMENT, not at
	// return time — `defer resp.Body.Close()` would capture the ORIGINAL upstream
	// body here, before the #812 media-buffer tee below reassigns resp.Body to a
	// teeReadCloser. That would leave the tee's Close() (and therefore w.Close(),
	// which flushes the sink + appends the metatag + unblocks the drain goroutine)
	// never called — a silent goroutine/fd leak with zero captures. Wrapping in a
	// closure defers evaluation of `resp.Body` to when the closure RUNS (return),
	// so it always closes whatever resp.Body currently is — the tee when a capture
	// was armed, the original body otherwise. resp itself is never reassigned, so
	// this remains the single, sole closer (teeReadCloser.Close is once-guarded).
	defer func() { resp.Body.Close() }()

	// #823 — inline Sentinel gate. host + the client identity are known here and
	// the upstream response headers are in hand. Match the flow's observable
	// metadata against the loaded IOC set: a HIGH-CONFIDENCE known-infra hit
	// neutralizes inline (block/sinkhole → serve a Sentinel block page instead of
	// the upstream response; strip → serve the response with an emptied body),
	// everything else is mirrored to the async analyzer and proceeds unchanged.
	// Fail-open + nil-safe (see sentinel.go): a disabled/erroring/absent hook is a
	// transparent passthrough, so this can never break a normal flow. Only the
	// domain + URL vectors drive inline matching today: JA4/JA3 (captured at
	// handshake) and cert/file-hash are not plumbed to this shared pipeline, and
	// ClientIP is DELIBERATELY left empty — IP IOCs are malicious *destination*
	// IPs, so matching them against the client's own source IP is wrong and could
	// auto-block the client. The destination-IP vector is a follow-up (plumb the
	// resolved upstream IP here); until then IP matching stays inert inline.
	switch action, blockPage := px.sentinel.inspect(sentinel.FlowMeta{
		Host:    host,
		URL:     "https://" + host + req.URL.RequestURI(),
		MacHash: clientHash,
		JA4:     ja4, // SNI-independent client-stack fp (feeds non_browser_ja)
	}, nil); action {
	case sentinel.ActionBlock, sentinel.ActionSinkhole:
		writeRaw(tconn, 403, "Forbidden", map[string]string{
			"Content-Type":       "text/html; charset=utf-8",
			"Cache-Control":      "no-store",
			"X-SecuBox-Sentinel": "blocked",
		}, blockPage)
		return
	case sentinel.ActionStrip:
		// Neutralize the payload: serve the upstream status + headers with an
		// emptied body. Drop Content-Encoding so the zero-length body is not
		// mis-decoded as a truncated compressed stream.
		resp.Header.Del("Content-Encoding")
		resp.Header.Set("X-SecuBox-Sentinel", "stripped")
		writeResponse(tconn, resp, nil)
		return
	}

	// #662 — relay the cookie metadata for this MITM'd response (allow|mitm only).
	// NAMES ONLY (never values — privacy/CSPN); no-op unless ≥1 Set-Cookie OR ≥1
	// request Cookie is present. Emitted before poison rewrites Set-Cookie VALUES,
	// which is irrelevant here (names are unchanged by poison) but keeps the
	// relayed names byte-for-byte the origin's. Fire-and-forget, gated.
	px.emitCookies(relayIP, clientHash, req, resp)

	// #736 R4 — media reverse-catcher: if this MITM'd response is cloneable media
	// (HLS/DASH manifest or direct audio/video), record its URL (never the body)
	// to the discovery log the mediaflow "Discovered Media" view reads. Best-
	// effort + deduped; a no-op when --media-catch is off or the flow isn't media.
	if px.media != nil && resp.StatusCode >= 200 && resp.StatusCode < 300 {
		ctype := resp.Header.Get("Content-Type")
		kind := mediaKind(req.URL.Path, ctype)
		if kind == "" {
			kind = videoPageKind(host, req.URL.Path, ctype) // YouTube watch/shorts → cloneable page
		}
		if kind != "" {
			px.media.record(clientHash, host,
				"https://"+host+req.URL.RequestURI(), req.URL.Path,
				req.Header.Get("Referer"), kind, ctype, resp.ContentLength)
		}
	}

	// #812 R4 media buffer (download) — tee the FULL response body into the
	// rolling buffer so it can be replayed for a short window. Non-blocking: the
	// ObjectWriter behind the TeeReader copies chunks to a bounded channel and
	// drops-if-full, so it NEVER slows or fails the client stream; a nil writer
	// is a no-op. resp.Body's deferred Close (above) finalises the capture.
	// splice/passthrough flows never reach here.
	//
	// I2 whole-branch-review fix — 200 ONLY, not the whole 2xx range. Browser
	// <video>/<audio> elements fetch media via Range requests, which the
	// origin answers with a stream of 206 Partial Content responses; capturing
	// each 206 as its own "whole" object produced a pile of unrelated byte
	// fragments (never a replayable file). Phase 1 is whole-file capture only
	// — Range/partial (206) + HLS segment reassembly is Phase 2.
	if px.mbuf != nil && resp.StatusCode == 200 {
		rctype := resp.Header.Get("Content-Type")
		if px.mbuf.IsMedia(rctype, req.URL.Path) {
			if w := px.mbuf.Capture(clientHash, host,
				"https://"+host+req.URL.RequestURI(), req.URL.Path, rctype, "down",
				resp.ContentLength); w != nil {
				resp.Body = teeReadCloser(resp.Body, w)
			}
		}
	}

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
	cspNonce := ""
	if px.cspDemo {
		cspNonce, cspBypassed = relaxCSPForLoader(resp.Header)
	}
	// CSP diagnostic (#751) — opt-in via SBX_DEBUG_CSP, off by default (zero cost
	// when unset). For every injected HTML response it logs what relaxCSPForLoader
	// actually saw — the proto, the count of CSP / CSP-Report-Only headers visible
	// in resp.Header, the borrowed nonce and the bypass decision. Kept as a
	// permanent operator tool: it pinpoints why a banner does/doesn't render on a
	// given site (header present? nonce-source? hash-only? strict-dynamic?), the
	// class of problem that took an x.com-shaped CSP to surface.
	if os.Getenv("SBX_DEBUG_CSP") != "" {
		csps := resp.Header.Values("Content-Security-Policy")
		cspRO := resp.Header.Values("Content-Security-Policy-Report-Only")
		head := ""
		if len(csps) > 0 {
			head = csps[0]
			if len(head) > 220 {
				head = head[:220]
			}
		}
		log.Printf("[csp-debug] host=%s proto=%s status=%d cspHdrs=%d cspRO=%d nonce=%q bypassed=%v head=%q",
			host, resp.Proto, resp.StatusCode, len(csps), len(cspRO), cspNonce, cspBypassed, head)
	}
	// #662 — INLINE the banner (supersedes the <script src="/__toolbox/loader.js">
	// tag): sites with a SERVICE WORKER hijack the same-origin src before it
	// reaches this engine. We fetch the COMPLETE script body from the portal
	// server-side and bake it into a self-contained <script>. Fail-open: a
	// dead/slow portal → scriptBody=="" → inject skipped, page served intact.
	// cspNonce (#728): the page's borrowed nonce, stamped on the inline <script>
	// so a nonce-based CSP (YouTube, most news sites) accepts it.
	scriptBody, _ := fetchInlineBanner(px.portal, clientHash, wg, cspBypassed)
	injHost := ""
	if resp.Request != nil {
		injHost = resp.Request.Host
	}
	if out, ok := injectIntoBody(body, resp.Header.Get("Content-Encoding"), scriptBody, cspNonce, wg, injHost); ok {
		body = out
		if wg && px.ads != nil {
			px.ads.recordCosmetic() // #755 — cosmetic style is wg-only (injectHTML gates it)
		}
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
	mediaCatch := flag.Bool("media-catch", true,
		"R4 media reverse-catcher (#736): record cloneable media URLs (HLS/DASH manifests + direct audio/video) seen on MITM'd flows to "+mediaCatchPath+" for the mediaflow \"Discovered Media\" clone view. URLs only, never bodies; deduped. Set false to disable.")
	swNeuterHosts := flag.String("sw-neuter-hosts", "/var/lib/secubox/toolbox/sw-neuter-hosts.txt",
		"#753 allow-list of PWA hosts whose Service Worker is neutered (served a self-unregistering SW) so the banner can be injected; empty/missing file = no-op")
	// #812 R4 media buffer — capture whole-file media bytes (up + download) into a
	// short rolling buffer on /data for admin/owner replay. Default OFF (Task 6
	// formalises the flag docs + janitor wiring); the tee is a no-op when off.
	mediaBuffer := flag.Bool("media-buffer", false,
		"R4 media buffer (#812): tee whole-file media up/downloads into a time-bounded rolling buffer on /data for admin/owner replay. Non-blocking (async writer, drop-if-full). Default off.")
	mediaBufferRoot := flag.String("media-buffer-root", "/data/secubox/media-buffer",
		"root directory for the R4 media buffer (0750 secubox:secubox); per-session subdirs + media-buffer.jsonl metatag log live here")
	mediaBufferPerObj := flag.Int64("media-buffer-per-object", 512<<20,
		"per-object byte ceiling for the R4 media buffer; a media object exceeding this is truncated (metatag flagged) rather than persisted whole")
	mediaBufferRetention := flag.Int64("media-buffer-retention", defaultRetentionSecs,
		"seconds the R4 media buffer's captured bytes are kept before the janitor evicts them (the metatag survives eviction)")
	mediaBufferSizeCeil := flag.Int64("media-buffer-size-ceil", defaultSizeCeilBytes,
		"hard byte ceiling for the R4 media buffer on /data; the janitor LRU-evicts the oldest sessions first when exceeded")
	flag.Parse()
	ca, err := forge.LoadCA(*caCert, *caKey)
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
	// #rlevel-per-peer Task 3 — per-peer R-level clamp. LoadPeerPolicy is
	// best-effort (like LoadPolicy above): a missing/unreadable/corrupt store
	// degrades to its own Passive fail-safe rather than erroring, so in
	// practice this branch is defensive only. On the rare non-nil error we
	// choose rlevel = nil (total no-op via decideForPeer) over a policy we
	// have no confidence in, rather than risk fail-closed-passive silently
	// blanket-splicing every peer.
	peerRlevelPath := envOr("SECUBOX_PEER_RLEVEL", "/var/lib/secubox/toolbox/peer-rlevel.json")
	peerWgPeersPath := envOr("SECUBOX_WG_PEERS", wgPeersPath)
	rlevelPol, err := LoadPeerPolicy(peerRlevelPath, peerWgPeersPath)
	if err != nil {
		log.Printf("peer rlevel policy load failed (per-peer clamp disabled): %v", err)
		rlevelPol = nil
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
		media:         newMediaCatcher(*mediaCatch),
		mbuf:          NewMediaBuffer(*mediaBufferRoot, *mediaBuffer, *mediaBufferPerObj),
		swNeuter:      newSWNeuter(*swNeuterHosts),
		// #823 — inline Sentinel gate. Construction reads the environment
		// (SENTINEL_ENABLED / SENTINEL_PACK_DIR / SENTINEL_OVERLAY_DIR /
		// SENTINEL_MIRROR_SOCK); unset/false or a failed pack load yields a
		// disabled no-op hook, so the default build is byte-identical to today.
		sentinel: newSentinelHook(),
		// #rlevel-per-peer Task 3 — per-peer R-level clamp (see decideForPeer).
		rlevel: rlevelPol,
	}
	// #812 Task 6 — apply the retention/size-ceil overrides on top of
	// NewMediaBuffer's defaults. Same-package unexported field access (see
	// mediabuffer.go); the constructor signature stays (root, enabled,
	// perObjectCeil) — do not add params there instead.
	if px.mbuf != nil {
		px.mbuf.retentionSecs = *mediaBufferRetention
		px.mbuf.sizeCeilBytes = *mediaBufferSizeCeil
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
	// rejection in handleTransparent) is drained in the SAME flush.
	go px.ads.runAdStatsFlusher(*portal, px.cand, px.pin)
	go px.swNeuter.runCandidateFlusher(*portal)
	if *mediaBuffer {
		// #812 R4 media buffer janitor — evicts bytes past retention (time) or
		// under disk pressure (LRU size ceiling), leaving only the metatag.
		// Process-lifetime background goroutine (mirrors the flushers above);
		// each of the 4 sbxmitm worker processes runs its own — SweepOnce is
		// written to be safe under that concurrency (see mediabuffer_janitor.go).
		go px.mbuf.RunJanitor(context.Background())
	}
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
