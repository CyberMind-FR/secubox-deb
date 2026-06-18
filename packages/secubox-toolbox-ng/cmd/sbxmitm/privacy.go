// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: always-on anonymize + Set-Cookie poison wiring
// (#662 Phase 5-prep, Part A)
//
// These helpers wire the ported policy (policy.go) + HMAC fake-identity jar
// (jar.go) into the MITM response path. They mirror the INTENT of the Python
// privacy_guard._anonymize and privacy.fake_id poison (mitmproxy_addons/
// privacy_guard.py, secubox_toolbox/privacy.py) — best-effort privacy hygiene,
// NOT byte-identical to the Python request-Cookie path. The jar values
// themselves ARE byte-exact (proven in jar_test.go).
//
// Safety envelope (DARK, like anti-track): poison only acts on MITM'd TRACKER
// flows. allow/own-infra flows are left CLEAN — never poisoned, never blocked.
//
// Pure standard library — no external modules.
package main

import (
	"net"
	"net/http"
	"strings"
)

// ── anonymize: always-on hygiene ─────────────────────────────────────────────

// anonymizeStrip mirrors privacy_guard._STRIP / protective_mode._STRIP: the
// operator/carrier + re-identification REQUEST headers we drop on every MITM'd
// flow. Lower-cased for case-insensitive matching against canonicalised keys.
var anonymizeStrip = []string{
	"msisdn", "x-msisdn", "x-up-calling-line-id", "x-up-subno",
	"x-nokia-msisdn", "x-acr", "x-vf-acr", "x-amobee-1", "x-amobee-2",
	"tm-user-id", "x-wap-profile", "x-wap-msisdn", "x-network-info",
	"x-forwarded-for", "forwarded", "x-real-ip", "via",
}

// anonymizeRequest applies always-on privacy hygiene to a MITM'd request:
// drop the operator/tracking headers above, then pin DNT:1 + Sec-GPC:1 (the
// opt-out signals). Mirrors privacy_guard._anonymize. Minimal + best-effort:
// it never errors and is safe to call on every intercepted request.
//
// NOTE: unlike the Python spoof path we do NOT drop Cookie/Referer here —
// anonymize is the universally-safe hygiene layer; cookie neutralisation is the
// poison layer (poisonSetCookies), gated behind the tracker classification.
func anonymizeRequest(h http.Header) {
	for _, name := range anonymizeStrip {
		// http.Header.Del canonicalises the key; our list is lower-case but Del
		// matches case-insensitively via CanonicalMIMEHeaderKey.
		h.Del(name)
	}
	h.Set("DNT", "1")
	h.Set("Sec-GPC", "1")
}

// ── poison: response Set-Cookie value replacement ────────────────────────────

// trackingCookieNames is the set of exact cookie names we treat as tracking
// identifiers worth poisoning (lower-cased). These map onto the shapes the jar
// (_shape in jar.go) knows how to forge plausibly.
var trackingCookieNames = map[string]bool{
	"_fbp": true, "_fbc": true, "_gid": true, "_gcl_au": true,
	"uid": true, "uuid": true, "_pk_id": true, "_pk_ses": true,
	"__qca": true, "muid": true, "ide": true, "fr": true,
	"_uetvid": true, "_uetsid": true, "anid": true, "nid": true,
}

// isTrackingCookieName reports whether a Set-Cookie name looks like a tracking
// identifier we should poison. Prefix rule: any "_ga*" cookie (GA + GA4
// per-property _ga_<id>) is a tracking id; otherwise an exact-match against
// trackingCookieNames. Benign session/CSRF cookies (sessionid, csrftoken, …)
// are NOT matched, so they pass through untouched.
func isTrackingCookieName(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return false
	}
	if strings.HasPrefix(n, "_ga") {
		return true
	}
	return trackingCookieNames[n]
}

// poisonSetCookies rewrites the response Set-Cookie header lines for a MITM'd
// tracker flow: for each cookie whose NAME is a tracking id, the value is
// replaced with the jar fakeID(clientHash, host, name, key) while ALL cookie
// attributes (Path, Domain, Max-Age, Secure, HttpOnly, SameSite, …) are
// preserved verbatim. Non-tracking cookies are returned byte-identical.
//
// Gating (caller's responsibility too, but defensive here): if the jar key is
// absent OR fakeID returns !ok (empty clientHash / tracker), the cookie is left
// UNCHANGED — we never emit a malformed cookie, and we never invent a fake
// where we lack the seed. This keeps the poison fail-closed-to-clean.
//
// This is the emission half of the jar; the classification half (is this a
// tracker flow at all) is Policy.shouldPoison, applied by the wiring before
// this is ever called — poison NEVER touches allow/own-infra flows.
func poisonSetCookies(setCookies []string, clientHash, host string, key []byte) []string {
	if len(setCookies) == 0 {
		return setCookies
	}
	out := make([]string, len(setCookies))
	for i, sc := range setCookies {
		out[i] = poisonOneSetCookie(sc, clientHash, host, key)
	}
	return out
}

// poisonOneSetCookie rewrites a single Set-Cookie line. The line shape is
// `name=value; Attr1; Attr2=...`; we split off the first `;` to isolate the
// name=value pair, replace value if name is a tracking id and a fake mints,
// then re-attach the (unchanged) attribute tail.
func poisonOneSetCookie(sc, clientHash, host string, key []byte) string {
	semi := strings.IndexByte(sc, ';')
	pair := sc
	tail := ""
	if semi >= 0 {
		pair = sc[:semi]
		tail = sc[semi:] // includes the leading ';'
	}
	eq := strings.IndexByte(pair, '=')
	if eq < 0 {
		return sc // attribute-only / malformed → leave untouched
	}
	name := strings.TrimSpace(pair[:eq])
	if !isTrackingCookieName(name) {
		return sc
	}
	fake, ok := fakeID(clientHash, host, name, key)
	if !ok {
		return sc // no jar key / no clientHash → leave clean (fail-closed)
	}
	return name + "=" + fake + tail
}

// ── tracker classification + poison gate ─────────────────────────────────────

// isTracker mirrors the tracker classification used by the block decision
// (privacy.is_tracker / ad_ghost): _AD_HOST regex OR host/registrable in the
// learned-trackers set. Reused here so poison fires on exactly the hosts the
// engine already considers trackers.
func (p *Policy) isTracker(host string) bool {
	return p.blockedByAd(host)
}

// shouldPoison reports whether a MITM'd flow to host should have its tracking
// Set-Cookies poisoned. TRUE only for tracker hosts that are NOT own-infra /
// allowlisted — own-infra flows are left clean (same dark safety as the block
// path). The caller additionally requires a loaded jar key.
func (p *Policy) shouldPoison(host string) bool {
	if p.allowed(host) {
		return false // own-infra / allowlist → never poison
	}
	return p.isTracker(host)
}

// ── client identity ──────────────────────────────────────────────────────────

// clientHashFromConn returns the per-client identity used to mint the stable
// fake persona (jar fakeID first arg).
//
// PoC / CONNECT path: this is the peer IP string. A real TRANSPARENT R3 deploy
// MUST replace this with the mac_hash the Python addon uses
// (privacy_guard._client_hash → _common.mac_hash_of(peer_ip)), resolved via the
// SO_ORIGINAL_DST original-destination socket option and the WireGuard-peer →
// MAC map. Using the raw peer IP here is NOT identity-stable across NAT/DHCP
// and is intentionally a Phase-6-cutover TODO, not a shipped behaviour.
//
// TODO(#662 Phase 6): wire mac_hash via SO_ORIGINAL_DST + WG-peer map.
func clientHashFromConn(conn net.Conn) string {
	if conn == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return conn.RemoteAddr().String()
	}
	return host
}
