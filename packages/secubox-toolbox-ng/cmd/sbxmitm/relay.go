// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: per-flow analysis relay (#662)
//
// Restores the dpi / cookies / ja4 EVENTS that feed the kbin "Qui te piste?"
// cumulative-stats page, frozen since the #662 Phase-7 cutover decommissioned
// the Python mitmproxy relay addons (packages/secubox-toolbox/mitmproxy_addons/
// {dpi,cookies,ja4}.py). The Go engine is now the live R3 MITM core; this file
// re-implements EXACTLY what those addons did — extract privacy-safe flow
// metadata and fire-and-forget it to the analysis sidecar sockets, which
// enrich + write toolbox.db.events keyed by client_mac_hash.
//
// Transport is the existing emit() helper (sidecar.go): a detached goroutine
// with its own 2s timeout — a dead/slow analysis socket can NEVER block, delay,
// or break a client flow. The payload builders here are pure (no I/O), O(1)-ish
// per flow, and emit NAMES ONLY for cookies (never values — privacy / CSPN).
//
// Pure standard library — no external modules.
package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/relay"
)

// Stable socket paths — verbatim from the Python addons' TARGET constants
// (the http+unix:///run/secubox/<x>.sock/<route> URLs), split into path+route.
const (
	dpiSocket     = "/run/secubox/dpi.sock"
	cookiesSocket = "/run/secubox/cookies.sock"
	ja4Socket     = "/run/secubox/threat-analyst.sock"

	dpiRoute     = "/classify"
	cookiesRoute = "/inject"
	ja4Route     = "/ja4"
)

// Caps + truncation limits, matching the Python addons exactly.
const (
	maxSetCookieNames = 30  // cookies.py _names_only(set_cookies, cap=30)
	maxCookieNames    = 50  // cookies.py sent_names[:50]
	maxCookieNameLen  = 32  // cookies.py name[:32]
	maxCookieURL      = 300 // cookies.py pretty_url[:300]
)

// nowMS returns the current time as unix milliseconds (ts_ms in every payload).
func nowMS() int64 { return time.Now().UnixMilli() }

// ── gate ─────────────────────────────────────────────────────────────────────

// relayEnabled reports whether per-flow analysis relaying is on (the
// --analysis-relay flag → Proxy.analysisRelay). When false, nothing is emitted.
// Nil-safe so tests / the CONNECT PoC that build a bare Proxy can call it.
func (px *Proxy) relayEnabled() bool {
	return px != nil && px.analysisRelay
}

// relayEmit is the gated, fire-and-forget emit used by every relay call site.
// It NEVER blocks (delegates to emit() which detaches a goroutine with its own
// timeout) and emits nothing when the relay gate is off.
func (px *Proxy) relayEmit(socketPath, route string, payload []byte) {
	if !px.relayEnabled() || len(payload) == 0 {
		return
	}
	relay.Emit(socketPath, route, payload)
}

// ── dpi payload ──────────────────────────────────────────────────────────────

// dpiEvent mirrors the JSON the Python DPIRelay.request() emitted. user_agent is
// a *string so an absent UA serialises to JSON null (not ""), matching
// headers.get("user-agent") → None. scheme + sni are constant "https" / host on
// the MITM'd path (we only relay terminated TLS flows).
type dpiEvent struct {
	TSMs      int64   `json:"ts_ms"`
	ClientIP  string  `json:"client_ip"`
	MacHash   string  `json:"client_mac_hash"`
	Host      string  `json:"host"`
	Scheme    string  `json:"scheme"`
	Method    string  `json:"method"`
	UserAgent *string `json:"user_agent"`
	SNI       string  `json:"sni"`
}

// buildDPIPayload builds the /classify payload for one MITM'd request.
func buildDPIPayload(clientIP, macHash, host string, req *http.Request) []byte {
	var ua *string
	if v := req.Header.Get("User-Agent"); v != "" {
		ua = &v
	}
	ev := dpiEvent{
		TSMs:      nowMS(),
		ClientIP:  clientIP,
		MacHash:   macHash,
		Host:      host,
		Scheme:    "https",
		Method:    req.Method,
		UserAgent: ua,
		SNI:       host,
	}
	b, _ := json.Marshal(ev)
	return b
}

// emitDPI relays the DPI classification hint for a MITM'd request (gated).
func (px *Proxy) emitDPI(clientIP, macHash, host string, req *http.Request) {
	if !px.relayEnabled() {
		return
	}
	px.relayEmit(dpiSocket, dpiRoute, buildDPIPayload(clientIP, macHash, host, req))
}

// ── cookies payload ──────────────────────────────────────────────────────────

// cookiesEvent mirrors the JSON the Python CookiesRelay.response() emitted.
// NAMES ONLY — never cookie values (privacy / CSPN).
type cookiesEvent struct {
	TSMs           int64    `json:"ts_ms"`
	ClientIP       string   `json:"client_ip"`
	MacHash        string   `json:"client_mac_hash"`
	URL            string   `json:"url"`
	Method         string   `json:"method"`
	SetCookieNames []string `json:"set_cookie_names"`
	CookieNames    []string `json:"cookie_names"`
	SetCookieCount int      `json:"set_cookie_count"`
	CookieCount    int      `json:"cookie_count"`
	Status         int      `json:"status"`
}

// cookiesRelevant reports whether a flow carries any cookie signal worth
// relaying: ≥1 Set-Cookie in the response OR ≥1 Cookie in the request. Mirrors
// the Python `if not (set_cookies or req_cookies): return`.
func cookiesRelevant(req *http.Request, resp *http.Response) bool {
	if resp != nil && len(resp.Header.Values("Set-Cookie")) > 0 {
		return true
	}
	return req != nil && len(req.Header.Values("Cookie")) > 0
}

// setCookieName extracts the cookie NAME from a Set-Cookie header line: the text
// before the first '=' of the first ';'-delimited field, trimmed and capped.
// Returns "" for attribute-only / malformed / empty-name lines (skipped).
func setCookieName(sc string) string {
	head := sc
	if i := strings.IndexByte(sc, ';'); i >= 0 {
		head = sc[:i]
	}
	eq := strings.IndexByte(head, '=')
	if eq < 0 {
		return ""
	}
	n := strings.TrimSpace(head[:eq])
	if len(n) > maxCookieNameLen {
		n = n[:maxCookieNameLen]
	}
	return n
}

// parseCookieHeaderNames splits a single "Cookie:" header value into its
// individual cookie NAMES (text before each '=' across ';'-separated pairs),
// trimmed + capped. Mirrors cookies.py _parse_cookie_header.
func parseCookieHeaderNames(value string) []string {
	var names []string
	for _, part := range strings.Split(value, ";") {
		eq := strings.IndexByte(part, '=')
		if eq < 0 {
			continue
		}
		n := strings.TrimSpace(part[:eq])
		if len(n) > maxCookieNameLen {
			n = n[:maxCookieNameLen]
		}
		if n != "" {
			names = append(names, n)
		}
	}
	return names
}

// setCookieNames returns the NAMES of the response Set-Cookie lines, scanning at
// most the first `cap` header lines (Python _names_only(headers[:cap])).
func setCookieNames(setCookies []string, cap int) []string {
	out := make([]string, 0, len(setCookies))
	for i, sc := range setCookies {
		if i >= cap {
			break
		}
		if n := setCookieName(sc); n != "" {
			out = append(out, n)
		}
	}
	return out
}

// buildCookiesPayload builds the /inject payload for one MITM'd response that
// carries a cookie signal. The caller is expected to have checked
// cookiesRelevant; building on an empty flow yields empty name lists.
func buildCookiesPayload(clientIP, macHash string, req *http.Request, resp *http.Response) []byte {
	setCookies := resp.Header.Values("Set-Cookie")
	reqCookies := req.Header.Values("Cookie")

	// Sent cookie names: flatten every Cookie header line, then cap to 50 total.
	var sent []string
	for _, ch := range reqCookies {
		sent = append(sent, parseCookieHeaderNames(ch)...)
	}
	if len(sent) > maxCookieNames {
		sent = sent[:maxCookieNames]
	}

	u := req.URL.String()
	if len(u) > maxCookieURL {
		u = u[:maxCookieURL]
	}

	ev := cookiesEvent{
		TSMs:           nowMS(),
		ClientIP:       clientIP,
		MacHash:        macHash,
		URL:            u,
		Method:         req.Method,
		SetCookieNames: setCookieNames(setCookies, maxSetCookieNames),
		CookieNames:    sent,
		SetCookieCount: len(setCookies),
		CookieCount:    len(reqCookies),
		Status:         resp.StatusCode,
	}
	b, _ := json.Marshal(ev)
	return b
}

// emitCookies relays the cookie metadata for a MITM'd response (gated). No-op
// when neither a Set-Cookie nor a request Cookie is present.
func (px *Proxy) emitCookies(clientIP, macHash string, req *http.Request, resp *http.Response) {
	if !px.relayEnabled() || !cookiesRelevant(req, resp) {
		return
	}
	px.relayEmit(cookiesSocket, cookiesRoute, buildCookiesPayload(clientIP, macHash, req, resp))
}

// ── ja4 payload ──────────────────────────────────────────────────────────────

// ja4Event mirrors the JSON the Python JA4Relay.tls_clienthello() emitted.
// alpn_protocols / cipher_suites are always JSON arrays (never null) — matching
// list(ch.alpn_protocols or []). extensions is always null: crypto/tls'
// ClientHelloInfo does not expose the raw extension list, exactly the Python
// `if hasattr(ch, "extensions") else None` fallback (the service tolerates it).
type ja4Event struct {
	TSMs       int64    `json:"ts_ms"`
	ClientIP   string   `json:"client_ip"`
	MacHash    string   `json:"client_mac_hash"`
	SNI        string   `json:"sni"`
	ALPN       []string `json:"alpn_protocols"`
	Ciphers    []uint16 `json:"cipher_suites"`
	Extensions *[]int   `json:"extensions"` // always nil → JSON null
}

// buildJA4Payload builds the /ja4 payload for one MITM'd TLS ClientHello.
func buildJA4Payload(clientIP, macHash, sni string, alpn []string, ciphers []uint16) []byte {
	if alpn == nil {
		alpn = []string{}
	}
	if ciphers == nil {
		ciphers = []uint16{}
	}
	ev := ja4Event{
		TSMs:       nowMS(),
		ClientIP:   clientIP,
		MacHash:    macHash,
		SNI:        sni,
		ALPN:       alpn,
		Ciphers:    ciphers,
		Extensions: nil,
	}
	b, _ := json.Marshal(ev)
	return b
}

// emitJA4 relays the captured ClientHello fingerprint material for a MITM'd
// handshake (gated). Called once per handshake, before Decide — so blocked and
// allowed flows alike are relayed, matching the Python addon which ran on every
// tls_clienthello.
func (px *Proxy) emitJA4(clientIP, macHash, sni string, alpn []string, ciphers []uint16) {
	if !px.relayEnabled() {
		return
	}
	px.relayEmit(ja4Socket, ja4Route, buildJA4Payload(clientIP, macHash, sni, alpn, ciphers))
}
