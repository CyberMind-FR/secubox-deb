// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: cross-site cookie-tracker correlation (#662)
//
// Restores the kbin "/social" cross-site tracker graph, frozen since the #662
// Phase-7 cutover decommissioned the in-process Python `social_graph` addon
// (packages/secubox-toolbox/mitmproxy_addons/social_graph.py). The graph reads
// social_nodes/social_links in toolbox.db, folded from raw social_edges — and
// the edges stopped flowing when the Python addon was retired.
//
// This is a FAITHFUL Go port of the addon's correlation logic:
//   - cookieIDHash : byte-exact port of social.cookie_id_hash (Python = source
//     of truth, proven by social_test.go ↔ tests/test_social_parity.py over a
//     shared fixture — the same anti-rig discipline as jar.go).
//   - isDenyListed + the _DEFAULT_DENY_COOKIES set (social.py).
//   - registrableSocial : the addon's _registrable_domain eTLD+1 helper
//     (DIFFERENT from policy.go's registrable() — IP literals pass through,
//     no port strip, a larger multi-label-TLD table; the graph correctness
//     depends on this exact flavour, so it is replicated verbatim and NOT
//     consolidated with policy.registrable).
//   - the 3rd-party decision (tracker_domain != src_site on eTLD+1) on BOTH the
//     response Set-Cookie path and the request Cookie path, mirroring the
//     addon's response()+request hooks.
//   - the CMP consent-platform detection → consent_state ∈ {none_seen,
//     pre_consent, post_consent} via a per-(peer,site) in-memory log.
//
// Privacy/CSPN invariant (the reason the original ran in-process): raw cookie
// VALUES NEVER leave the engine — only the truncated SHA-256 cookieIDHash is
// emitted. The edges are POSTed fire-and-forget to the portal's
// /__toolbox/social-event ingest (sibling of /__toolbox/ad-event), which calls
// social.record_edge(). Best-effort throughout; a dead/slow portal can never
// block or delay a client flow.
//
// Pure standard library — no external modules, no go.sum.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ── registrableSocial: port of social_graph._registrable_domain ─────────────
//
// Python (mitmproxy_addons/social_graph.py):
//
//	h = (host or "").lower().strip(".")
//	if not h or h.replace(".", "").isdigit(): return h     # raw IP → as-is
//	parts = h.split(".")
//	if len(parts) < 2: return h
//	last_two = ".".join(parts[-2:])
//	if last_two in _MULTI_LABEL_TLDS and len(parts) >= 3: return ".".join(parts[-3:])
//	return last_two
//
// This DIFFERS from policy.registrable (ad_ghost flavour): no port strip, IP
// literals pass through unchanged (the store later drops IP trackers via
// _is_ip), and the multi-label-TLD table below is the addon's larger set. The
// graph's 3rd-party comparison is done with THIS function, so it must match the
// addon exactly.
var socialMultiLabelTLDs = map[string]bool{
	"co.uk": true, "ac.uk": true, "gov.uk": true, "org.uk": true, "net.uk": true,
	"co.jp": true, "ne.jp": true, "ac.jp": true,
	"com.au": true, "net.au": true, "org.au": true,
	"com.br": true, "com.cn": true, "com.hk": true, "com.tw": true, "com.mx": true,
}

func registrableSocial(host string) string {
	h := strings.Trim(strings.ToLower(host), ".")
	if h == "" {
		return h
	}
	// h.replace(".","").isdigit() → all-digit (IPv4-ish) → return as-is.
	if isAllDigits(strings.ReplaceAll(h, ".", "")) {
		return h
	}
	parts := strings.Split(h, ".")
	if len(parts) < 2 {
		return h
	}
	last2 := strings.Join(parts[len(parts)-2:], ".")
	if socialMultiLabelTLDs[last2] && len(parts) >= 3 {
		return strings.Join(parts[len(parts)-3:], ".")
	}
	return last2
}

// ── cookieIDHash: BYTE-EXACT port of social.cookie_id_hash ───────────────────
//
// Python (secubox_toolbox/social.py):
//
//	h = sha256()
//	h.update(tracker_domain.lower().encode("utf-8","replace")); h.update(b"\x00")
//	h.update(cookie_name.lower().encode("utf-8","replace"));    h.update(b"\x00")
//	h.update(cookie_value.encode("utf-8","replace"))
//	return h.hexdigest()[:16]
//
// CRITICAL: tracker_domain + cookie_name are LOWER-cased; the cookie_value is
// NOT. NUL (0x00) separators between the three fields. Go strings are already
// UTF-8, and strings.ToLower is byte-identical to Python str.lower for the
// ASCII + Latin domain/name inputs the fixtures exercise (incl. the Ünîcödé
// case, verified at parity). hex of the first 8 digest bytes == hexdigest()[:16].
func cookieIDHash(trackerDomain, cookieName, cookieValue string) string {
	h := sha256.New()
	h.Write([]byte(strings.ToLower(trackerDomain)))
	h.Write([]byte{0x00})
	h.Write([]byte(strings.ToLower(cookieName)))
	h.Write([]byte{0x00})
	h.Write([]byte(cookieValue)) // value NOT lower-cased
	sum := h.Sum(nil)
	return hex.EncodeToString(sum)[:16]
}

// ── deny-list: port of social._DEFAULT_DENY_COOKIES + is_deny_listed ─────────
//
// Names whose presence on a flow is NEVER recorded as a tracker identifier
// (session / csrf / auth / cloudflare / consent / locale). Replicated verbatim
// from social.py; matched case-insensitively after trimming.
var socialDenyCookies = map[string]bool{
	// session
	"phpsessid": true, "jsessionid": true, "asp.net_sessionid": true, "ci_session": true,
	"express.sid": true, "connect.sid": true, "sails.sid": true, "django_session": true,
	"laravel_session": true, "flask_session": true, "session": true, "sessionid": true,
	// csrf
	"_csrf": true, "_csrf_token": true, "xsrf-token": true, "csrftoken": true, "csrf": true,
	"x-csrf-token": true, "anti-csrf-token": true,
	// auth (1st-party)
	"auth": true, "auth_token": true, "access_token": true, "refresh_token": true, "bearer": true,
	"remember_token": true, "remember_me": true, "_oauth2_proxy": true,
	// cloudflare / consent / locale (low signal)
	"__cf_bm": true, "cf_clearance": true, "consent": true, "cookieconsent_status": true,
	"locale": true, "lang": true, "language": true, "_locale": true,
}

// isDenyListed mirrors social.is_deny_listed (default-deny set only; the engine
// does not load the TOML extra_deny override). An empty name is deny-listed
// (Python returns True for a blank name).
func isDenyListed(cookieName string) bool {
	name := strings.ToLower(strings.TrimSpace(cookieName))
	if name == "" {
		return true
	}
	return socialDenyCookies[name]
}

// ── cookie parsers: port of _parse_set_cookie / _parse_cookie_header ─────────

// parseSetCookieNameValue mirrors social_graph._parse_set_cookie: name=value is
// the text up to the first ';'; the name is everything before the first '=',
// trimmed; the value is the rest of that first field, trimmed. Returns ok=false
// for an attribute-only / nameless / empty line.
func parseSetCookieNameValue(header string) (name, value string, ok bool) {
	field := header
	if i := strings.IndexByte(field, ';'); i >= 0 {
		field = field[:i]
	}
	eq := strings.IndexByte(field, '=')
	if eq < 0 {
		return "", "", false
	}
	name = strings.TrimSpace(field[:eq])
	value = strings.TrimSpace(field[eq+1:])
	if name == "" {
		return "", "", false
	}
	return name, value, true
}

// cookiePair is one (name,value) parsed from a request Cookie header.
type cookiePair struct{ name, value string }

// parseCookieHeader mirrors social_graph._parse_cookie_header: split on ';',
// each "name=value" yields a trimmed (name,value); nameless pairs are dropped.
func parseCookieHeader(header string) []cookiePair {
	var out []cookiePair
	for _, part := range strings.Split(header, ";") {
		eq := strings.IndexByte(part, '=')
		if eq < 0 {
			continue
		}
		name := strings.TrimSpace(part[:eq])
		value := strings.TrimSpace(part[eq+1:])
		if name != "" {
			out = append(out, cookiePair{name: name, value: value})
		}
	}
	return out
}

// extractSetCookieDomainAttr mirrors social_graph._extract_domain_attr: pull the
// "; Domain=…" attribute from a Set-Cookie line, trimmed, leading dot stripped,
// lower-cased. Returns "" when absent.
func extractSetCookieDomainAttr(setCookie string) string {
	low := strings.ToLower(setCookie)
	idx := strings.Index(low, "domain")
	for idx >= 0 {
		// require it to be an attribute (preceded by ';' after optional spaces),
		// mirroring the Python regex `;\s*domain\s*=`.
		j := idx + len("domain")
		// skip spaces, then '='
		k := j
		for k < len(setCookie) && (setCookie[k] == ' ' || setCookie[k] == '\t') {
			k++
		}
		if k < len(setCookie) && setCookie[k] == '=' {
			// confirm a ';' (or start) precedes `domain` (after spaces).
			p := idx - 1
			for p >= 0 && (setCookie[p] == ' ' || setCookie[p] == '\t') {
				p--
			}
			if p < 0 || setCookie[p] == ';' {
				rest := setCookie[k+1:]
				if e := strings.IndexByte(rest, ';'); e >= 0 {
					rest = rest[:e]
				}
				val := strings.ToLower(strings.TrimLeft(strings.TrimSpace(rest), "."))
				if val == "" {
					return ""
				}
				return val
			}
		}
		next := strings.Index(low[idx+1:], "domain")
		if next < 0 {
			return ""
		}
		idx = idx + 1 + next
	}
	return ""
}

// srcSiteFromReferer mirrors social_graph._src_site_from_referer: take Referer
// (else Origin), strip scheme/path/query, return registrableSocial of the host.
func srcSiteFromReferer(req *http.Request) string {
	ref := req.Header.Get("Referer")
	if ref == "" {
		ref = req.Header.Get("Origin")
	}
	if ref == "" {
		return ""
	}
	s := ref
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	if i := strings.IndexByte(s, '?'); i >= 0 {
		s = s[:i]
	}
	return registrableSocial(s)
}

// ── consent-state detection: port of the _consent_log machinery ──────────────
//
// CMP (Consent Management Platform) cookie name prefixes + loader URL fragments,
// verbatim from social_graph._CMP_COOKIE_PREFIXES / _CMP_LOADER_FRAGMENTS. Seen
// on a flow → the site runs a CMP (has_cmp) and, for a cookie, consent recorded
// (consented). consent_state classifies a tracker edge as pre/post/none-consent.
var cmpCookiePrefixes = []string{
	"optanonconsent", "onetrustconsent", "optanonalertboxclosed", // OneTrust
	"didomi_token", "euconsent-v2", // Didomi / IAB TCF
	"__qca", "quantcast", // Quantcast
	"sp_choice", "consentuid", "_sp_", // Sourcepoint
}

var cmpLoaderFragments = []string{
	"cdn.cookielaw.org", "onetrust.com", // OneTrust
	"sdk.privacy-center.org", "didomi.io", // Didomi
	"quantcast.mgr.consensu.org", "quantcast.com/choice", // Quantcast
	"sourcepoint.mgr.consensu.org", "sp-prod.net", // Sourcepoint
}

// consentObservation is the per-(peer,site) state, mirroring the Python dict
// {"has_cmp": bool, "consented": bool}.
type consentObservation struct {
	hasCMP    bool
	consented bool
}

// consentKey mirrors social_graph._consent_key = (mac_hash, site).
type consentKey struct{ macHash, site string }

// consentLog is the bounded in-memory per-(peer,site) observation log, mirroring
// the module-level _consent_log + its 20k soft-cap wholesale clear. The Go proxy
// is genuinely concurrent (Python relied on the GIL), so all access is
// mutex-guarded.
type consentLog struct {
	mu  sync.Mutex
	log map[consentKey]consentObservation
}

const consentLogCap = 20000 // mirrors social_graph._consent_log soft cap

func newConsentLog() *consentLog {
	return &consentLog{log: map[consentKey]consentObservation{}}
}

// update mirrors social_graph._update_consent_log: observe whether this flow
// reveals a CMP loader (URL fragment, both request and response side) or a CMP
// cookie (either direction) for the (peer,site) pair, and fold it into the log.
//   - url is flow.request.pretty_url (lower-cased here).
//   - cookieBlobs are the raw request Cookie + response Set-Cookie header lines.
func (cl *consentLog) update(macHash, site, url string, cookieBlobs []string) {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	if len(cl.log) > consentLogCap {
		cl.log = map[consentKey]consentObservation{}
	}
	key := consentKey{macHash: macHash, site: site}
	st := cl.log[key]

	lurl := strings.ToLower(url)
	for _, frag := range cmpLoaderFragments {
		if strings.Contains(lurl, frag) {
			st.hasCMP = true
			break
		}
	}
	for _, blob := range cookieBlobs {
		low := strings.ToLower(blob)
		for _, pref := range cmpCookiePrefixes {
			if strings.Contains(low, pref) {
				st.hasCMP = true
				st.consented = true
				break
			}
		}
	}
	cl.log[key] = st
}

// stateFor mirrors social_graph._consent_state_for: post_consent if a consent
// cookie was seen here, pre_consent if a CMP is present but no consent cookie
// yet, none_seen otherwise.
func (cl *consentLog) stateFor(macHash, site string) string {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	st, ok := cl.log[consentKey{macHash: macHash, site: site}]
	if !ok {
		return "none_seen"
	}
	if st.consented {
		return "post_consent"
	}
	if st.hasCMP {
		return "pre_consent"
	}
	return "none_seen"
}

// ── edge extraction: port of SocialGraph.response()+request() hook logic ──────

// socialEdge is one cross-site tracker edge, mirroring the kwargs the Python
// social.record_edge accepts; serialised straight into the ingest batch.
type socialEdge struct {
	ClientMacHash   string `json:"client_mac_hash"`
	SrcSite         string `json:"src_site"`
	TrackerDomain   string `json:"tracker_domain"`
	CookieIDHashVal string `json:"cookie_id_hash_val"`
	JA4Hash         string `json:"ja4_hash,omitempty"`
	ConsentState    string `json:"consent_state"`
}

// socialEdgesFor extracts the cross-site tracker edges for ONE MITM'd flow,
// mirroring SocialGraph.response() + the request-Cookie tail. Pure (no I/O): the
// caller emits the returned edges. macHash MUST be the WG persona hash (the
// addon only fires for known R3 peers — empty macHash yields no edges). reqHost
// is flow.request.host; reqURL is flow.request.pretty_url (for CMP loader
// detection); ja4 is the captured fingerprint (may be "").
//
// Decision logic, faithful to the addon:
//   - src_site = registrableSocial(reqHost); skip if empty.
//   - update the consent log for (macHash, src_site), derive consent_state.
//   - Set-Cookie path (first 50): for each non-deny-listed cookie, tracker_domain
//     = registrableSocial(Domain= attr OR reqHost); emit IFF tracker_domain != ""
//     and != src_site (3rd-party).
//   - Cookie path: only when a Referer/Origin context site exists and differs
//     from the tracker (= registrableSocial(reqHost)); cap 5 Cookie headers ×
//     50 pairs; emit per non-deny-listed cookie with the context site's
//     consent_state.
func socialEdgesFor(macHash string, req *http.Request, resp *http.Response, reqHost, reqURL, ja4 string, cl *consentLog) []socialEdge {
	if macHash == "" || cl == nil {
		return nil
	}
	srcSite := registrableSocial(reqHost)
	if srcSite == "" {
		return nil
	}

	// Gather the cookie blobs (both directions) for the CMP cookie check, then
	// fold the consent observation BEFORE deriving consent_state (matches the
	// addon's ordering: _update_consent_log then _consent_state_for).
	var setCookies []string
	if resp != nil {
		setCookies = resp.Header.Values("Set-Cookie")
	}
	var reqCookies []string
	if req != nil {
		reqCookies = req.Header.Values("Cookie")
	}
	blobs := make([]string, 0, len(reqCookies)+len(setCookies))
	blobs = append(blobs, reqCookies...)
	blobs = append(blobs, setCookies...)
	cl.update(macHash, srcSite, reqURL, blobs)
	consentState := cl.stateFor(macHash, srcSite)

	var edges []socialEdge

	// Set-Cookie path — first 50 lines (matches the addon's [:50]).
	for i, sc := range setCookies {
		if i >= 50 {
			break
		}
		name, value, ok := parseSetCookieNameValue(sc)
		if !ok || isDenyListed(name) {
			continue
		}
		domainAttr := extractSetCookieDomainAttr(sc)
		issuer := domainAttr
		if issuer == "" {
			issuer = reqHost
		}
		trackerDomain := registrableSocial(issuer)
		if trackerDomain == "" || trackerDomain == srcSite {
			continue // 1st-party Set-Cookie: not a cross-site tracker signal.
		}
		edges = append(edges, socialEdge{
			ClientMacHash:   macHash,
			SrcSite:         srcSite,
			TrackerDomain:   trackerDomain,
			CookieIDHashVal: cookieIDHash(trackerDomain, name, value),
			JA4Hash:         ja4,
			ConsentState:    consentState,
		})
	}

	// Request-Cookie path — only when this request is itself for a 3rd-party
	// tracker and we have a differing 1st-party context from the Referer/Origin.
	if len(reqCookies) == 0 {
		return edges
	}
	trackerDomain := registrableSocial(reqHost)
	if trackerDomain == "" {
		return edges
	}
	ctxSite := srcSiteFromReferer(req)
	if ctxSite == "" || ctxSite == trackerDomain {
		return edges
	}
	ctxConsent := cl.stateFor(macHash, ctxSite)
	for i, hdr := range reqCookies {
		if i >= 5 { // addon caps Cookie headers at [:5]
			break
		}
		pairs := parseCookieHeader(hdr)
		for j, p := range pairs {
			if j >= 50 { // and pairs at [:50]
				break
			}
			if isDenyListed(p.name) {
				continue
			}
			edges = append(edges, socialEdge{
				ClientMacHash:   macHash,
				SrcSite:         ctxSite,
				TrackerDomain:   trackerDomain,
				CookieIDHashVal: cookieIDHash(trackerDomain, p.name, p.value),
				JA4Hash:         ja4,
				ConsentState:    ctxConsent,
			})
		}
	}
	return edges
}

// ── relay: batch + POST to the portal /__toolbox/social-event ingest ─────────

const (
	socialFlushInterval = 10 * time.Second // drain cadence (sibling of adFlushInterval)
	socialBatchCap      = 5000             // max edges held between flushes (drop excess)
)

// socialEventPayload mirrors the portal /__toolbox/social-event JSON contract.
type socialEventPayload struct {
	Edges []socialEdge `json:"edges"`
}

func (p socialEventPayload) empty() bool { return len(p.Edges) == 0 }

// socialRelay buffers extracted edges and flushes them to the portal. Bounded:
// once the buffer holds socialBatchCap edges, NEW edges are dropped until the
// next flush clears it (a dead portal can never grow memory unbounded). Edges
// carry ONLY the cookieIDHash — never raw values (privacy/CSPN).
type socialRelay struct {
	mu  sync.Mutex
	buf []socialEdge
}

func newSocialRelay() *socialRelay { return &socialRelay{} }

// add appends edges to the buffer under the cap. Never blocks the flow.
func (s *socialRelay) add(edges ...socialEdge) {
	if len(edges) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range edges {
		if len(s.buf) >= socialBatchCap {
			return
		}
		s.buf = append(s.buf, e)
	}
}

// snapshot atomically reads-and-clears the buffer.
func (s *socialRelay) snapshot() socialEventPayload {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.buf) == 0 {
		return socialEventPayload{}
	}
	p := socialEventPayload{Edges: s.buf}
	s.buf = nil
	return p
}

// socialEventClient is the short-timeout fire-and-forget client for the
// social-event POST (sibling of adEventClient). Never follows redirects (SSRF
// hygiene); tight timeout so a slow portal can't stall the flusher.
var socialEventClient = &http.Client{
	Timeout:       5 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// flushOnce snapshots the buffer and, if non-empty, POSTs it to the portal's
// /__toolbox/social-event ingest. Best-effort: any error is swallowed with at
// most a log line — the engine must never block on the portal. Returns the
// flushed payload so the test can assert the snapshot/clear + shape.
func (s *socialRelay) flushOnce(portal string) socialEventPayload {
	p := s.snapshot()
	if p.empty() {
		return p
	}
	buf, err := json.Marshal(p)
	if err != nil {
		log.Printf("social-event marshal failed: %v", err)
		return p
	}
	url := portalTargetURL(portal, "/__toolbox/social-event")
	resp, err := socialEventClient.Post(url, "application/json", bytes.NewReader(buf))
	if err != nil {
		log.Printf("social-event post failed for %s: %v", url, err)
		return p
	}
	resp.Body.Close()
	return p
}

// ── proxy wiring ──────────────────────────────────────────────────────────

// socialEnabled reports whether cross-site correlation is on (--social-relay →
// Proxy.socialRelayOn, with the buffer + consent log allocated). Nil-safe so the
// CONNECT PoC / tests that build a bare Proxy can call it.
func (px *Proxy) socialEnabled() bool {
	return px != nil && px.socialRelayOn && px.social != nil && px.consent != nil
}

// emitSocial extracts the cross-site tracker edges for a MITM'd flow and buffers
// them for the batched portal POST. clientIP is the client's peer IP; the per-
// client identity is the WG persona hash (macHashOf) — NOT the raw-IP fallback,
// so non-WG flows produce no edges, exactly like the Python addon's
// _client_mac_hash gate. Gated, pure (the buffer.add is O(1) under a short
// mutex), never blocks the flow. reqURL feeds the CMP loader-fragment check.
func (px *Proxy) emitSocial(clientIP, host string, req *http.Request, resp *http.Response) {
	if !px.socialEnabled() || req == nil {
		return
	}
	macHash := macHashOf(clientIP)
	if macHash == "" {
		return // known R3 WG peers only (addon: `if not mac_hash: return`)
	}
	reqURL := req.URL.String()
	edges := socialEdgesFor(macHash, req, resp, host, reqURL, "", px.consent)
	px.social.add(edges...)
}

// runFlusher is the background flusher goroutine: every socialFlushInterval it
// drains the buffer to the portal. Start once from main(); runs for the process
// lifetime.
func (s *socialRelay) runFlusher(portal string) {
	t := time.NewTicker(socialFlushInterval)
	defer t.Stop()
	for range t.C {
		s.flushOnce(portal)
	}
}
