// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: transparency-banner loader inject (#662)
//
// Ports the LIVE transparency-banner injection from the authoritative Python
// addon (../secubox-toolbox/mitmproxy_addons/inject_banner.py) into the Go
// engine. With stream_inject ON the Python addon injects a tiny LOADER
// <script src="/__toolbox/loader.js" data-mh=.. data-wg=.. async></script> and
// SERVES /__toolbox/loader.js + /__toolbox/bundle itself for ANY origin (the
// injected same-origin URL resolves to whatever MITM'd host the client is on).
//
// To avoid re-porting the bundle/level business logic to Go, this engine
// REVERSE-PROXIES /__toolbox/* to the portal (default http://127.0.0.1:8088),
// which already serves both endpoints. The injection (injectLoader) mirrors the
// Python _loader_script + _LoaderInjector byte-for-byte on the tag shape and
// placement; the guard makes it idempotent (matches Python _GUARD).
//
// Pure standard library — no external modules.
package main

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// bannerGuard matches the Python _GUARD ("__GONDWANA_MITM_BANNER__"): an HTML
// comment marker that makes injection idempotent across stream chunks / repeat
// passes. If the body already contains it, we never inject again.
const bannerGuard = "__GONDWANA_MITM_BANNER__"

// asciiOnly drops every non-ASCII byte from s, mirroring the Python
// `s.encode("ascii", "ignore")` used on the client hash before it lands in the
// data-mh attribute. The clientHash is normally a hex mac_hash (already ASCII),
// but a non-WG fallback could carry odd bytes — strip defensively.
func asciiOnly(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] < 0x80 {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// loaderScript builds the loader <script> tag EXACTLY like the Python
// _loader_script: a guard comment followed by the same-origin loader.js tag
// carrying the client identity (data-mh) + WG flag (data-wg). wg → "1" else "0";
// clientHash is ascii-sanitised. The src is same-origin so it resolves to the
// MITM'd host and is intercepted by the /__toolbox/* short-circuit.
//
// #662 CONSENTED-DEMONSTRATION: when cspBypassed is true (we actually relaxed a
// real CSP on this page so the loader could run), the tag also carries
// data-csp="1" — the portal loader renders a 🔓 from it as the VISIBLE proof
// that the page's CSP was bypassed to inject. The attribute is OMITTED when
// cspBypassed is false so a page with no CSP shows no false proof.
func loaderScript(clientHash string, wg, cspBypassed bool) []byte {
	wgVal := "0"
	if wg {
		wgVal = "1"
	}
	mh := asciiOnly(clientHash)
	cspAttr := ""
	if cspBypassed {
		cspAttr = ` data-csp="1"`
	}
	tag := `<script src="/__toolbox/loader.js" data-mh="` + mh +
		`" data-wg="` + wgVal + `"` + cspAttr + ` async></script>`
	return []byte("<!-- " + bannerGuard + " -->" + tag)
}

// injectLoader inserts the loader <script> into an HTML body once. Placement
// mirrors the Python _LoaderInjector.__call__:
//   - guard idempotency: if the body already contains bannerGuard → unchanged.
//   - find the first (case-insensitive) "<head"; if present, find the next ">"
//     after it and insert the tag right after that ">".
//   - else find the first "<body" and insert the tag right BEFORE it.
//   - if neither is present → return the body unchanged (no inject).
//
// cspBypassed (#662): true when a real CSP was relaxed on this page so the
// loader could run; threaded into loaderScript as data-csp="1" (the 🔓 proof).
func injectLoader(body []byte, clientHash string, wg, cspBypassed bool) []byte {
	if bytes.Contains(body, []byte(bannerGuard)) {
		return body
	}
	script := loaderScript(clientHash, wg, cspBypassed)
	low := bytes.ToLower(body)

	if h := bytes.Index(low, []byte("<head")); h >= 0 {
		if j := bytes.IndexByte(body[h:], '>'); j >= 0 {
			at := h + j + 1
			out := make([]byte, 0, len(body)+len(script))
			out = append(out, body[:at]...)
			out = append(out, script...)
			out = append(out, body[at:]...)
			return out
		}
	}
	if b := bytes.Index(low, []byte("<body")); b >= 0 {
		out := make([]byte, 0, len(body)+len(script))
		out = append(out, body[:b]...)
		out = append(out, script...)
		out = append(out, body[b:]...)
		return out
	}
	return body
}

// ── inline banner (#662, supersedes injectLoader in the live path) ──────────
//
// Sites with a SERVICE WORKER (leparisien, cnn…) intercept EVERY same-origin
// request, so the legacy <script src="/__toolbox/loader.js"> tag and the
// fetch("/__toolbox/bundle") it makes are hijacked by the page's SW (404 /
// app-shell) BEFORE they reach this engine → the banner never appears. The fix
// is to INLINE the whole banner: the engine fetches the COMPLETE script body
// from the portal server-side (once per injected HTML response) and bakes it
// into a self-contained <script>…</script> with mh/wg/csp + the bundle as JS
// literals — so there is NOTHING same-origin for the SW to hijack.
//
// injectLoader + the /__toolbox/loader.js short-circuit are KEPT (not removed)
// for compatibility, but the live inject path now uses the inline banner.

// fetchInlineBanner fetches the COMPLETE inline banner script BODY from the
// portal's /__toolbox/inline endpoint (which bakes mh/wg/csp + the bundle as JS
// literals). Returns (body, true) on a 2xx; FAIL-OPEN (returns "", false) on any
// error — portal down, timeout, non-2xx, read failure — so the caller simply
// skips the inject and serves the page intact (no banner, like today's fail-open
// when the portal asset 204s). It NEVER breaks a navigation over a banner.
//
// wg → "1" else "0"; cspBypassed → csp=1 (the 🔓 proof) else 0; clientHash is
// ascii-sanitised exactly like the data-mh attribute was.
func fetchInlineBanner(portal, clientHash string, wg, cspBypassed bool) (string, bool) {
	wgVal := "0"
	if wg {
		wgVal = "1"
	}
	cspVal := "0"
	if cspBypassed {
		cspVal = "1"
	}
	q := url.Values{}
	q.Set("mh", asciiOnly(clientHash))
	q.Set("wg", wgVal)
	q.Set("csp", cspVal)
	target := strings.TrimRight(portal, "/") + "/__toolbox/inline?" + q.Encode()
	resp, err := portalClient.Get(target)
	if err != nil {
		log.Printf("inline banner fetch failed for %s: %v", target, err)
		return "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Printf("inline banner fetch non-2xx (%d) for %s", resp.StatusCode, target)
		return "", false
	}
	body, rerr := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if rerr != nil {
		log.Printf("inline banner read failed for %s: %v", target, rerr)
		return "", false
	}
	return string(body), true
}

// injectInlineBanner inserts a SELF-CONTAINED <script>scriptBody</script> into an
// HTML body once. It is idempotent via the SAME bannerGuard marker injectLoader
// uses (so a body already carrying either form is never double-injected), and it
// uses the SAME placement injectLoader did:
//   - guard idempotency: body already contains bannerGuard → unchanged.
//   - after the first (case-insensitive) "<head"'s closing '>'.
//   - else right BEFORE the first "<body".
//   - else return the body unchanged (no inject).
//
// scriptBody is the COMPLETE inline IIFE from fetchInlineBanner (NOT a src tag);
// an empty scriptBody is a no-op (returns the body unchanged) so a failed/skipped
// fetch is handled gracefully by the caller passing "".
func injectInlineBanner(body []byte, scriptBody, nonce string) []byte {
	if scriptBody == "" {
		return body
	}
	if bytes.Contains(body, []byte(bannerGuard)) {
		return body
	}
	// #728 — on a nonce-based CSP the page's nonce is stamped here so the browser
	// accepts our inline <script> WITHOUT us having to weaken the page's policy
	// (csp.go validates the value is a safe base64 attribute before passing it on).
	nonceAttr := ""
	if nonce != "" {
		nonceAttr = ` nonce="` + nonce + `"`
	}
	script := []byte("<!-- " + bannerGuard + " --><script" + nonceAttr + ">" + scriptBody + "</script>")
	low := bytes.ToLower(body)

	if h := bytes.Index(low, []byte("<head")); h >= 0 {
		if j := bytes.IndexByte(body[h:], '>'); j >= 0 {
			return spliceAt(body, script, h+j+1)
		}
	}
	if b := bytes.Index(low, []byte("<body")); b >= 0 {
		return spliceAt(body, script, b)
	}
	return body
}

// ── /__toolbox/* reverse-proxy to the portal ─────────────────────────────────

// isToolboxAssetPath reports whether a request path is one of the banner assets
// the engine must serve itself (by reverse-proxying to the portal) for ANY
// origin. STARTSWITH (not exact) is REQUIRED: the path includes the query
// string and the bundle is fetched as /__toolbox/bundle?mh=..&wg=.. — an exact
// match would never fire. Mirrors the Python request() p.startswith(...) checks.
func isToolboxAssetPath(path string) bool {
	return strings.HasPrefix(path, "/__toolbox/loader.js") ||
		strings.HasPrefix(path, "/__toolbox/bundle") ||
		// #724 — banner R0..R3 level switch: same-origin GET from the page,
		// reverse-proxied to the portal /__toolbox/set-level.
		strings.HasPrefix(path, "/__toolbox/set-level")
}

// portalTargetURL builds the absolute portal URL for an intercepted asset
// request: <portal-base> + the original request path (which already includes
// the query string). The portal base's trailing slash is trimmed so the result
// never doubles the leading "/" of the path.
func portalTargetURL(portal, pathWithQuery string) string {
	return strings.TrimRight(portal, "/") + pathWithQuery
}

// portalClient is the short-timeout HTTP client used to fetch banner assets from
// the portal. Shared (stdlib http.Client is goroutine-safe) so we don't churn
// connections per request.
var portalClient = &http.Client{
	Timeout: 5 * time.Second,
	// Never follow redirects: the portal is a fixed loopback base, so not
	// following 3xx means a misbehaving/compromised portal can't steer the
	// worker into fetching an arbitrary outbound host (SSRF hygiene). The 3xx
	// is relayed to the client as-is.
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// servePortalAsset reverse-proxies a /__toolbox/* request to the portal and
// writes the portal's response (status + Content-Type + Cache-Control + body)
// back to the client over the already-established (TLS) conn. It returns true
// once it has written a response — the caller MUST NOT then forward upstream.
//
// Fail-open: if the portal request errors (portal down, timeout, non-2xx read
// failure) we serve a minimal 204 No Content so the navigation is never broken,
// and log at most a warning. We never 502 the whole page over a banner asset.
func servePortalAsset(w io.Writer, portal, pathWithQuery string) bool {
	target := portalTargetURL(portal, pathWithQuery)
	resp, err := portalClient.Get(target)
	if err != nil {
		log.Printf("portal asset fetch failed for %s: %v", target, err)
		writeRaw(w, 204, "No Content", nil, nil)
		return true
	}
	defer resp.Body.Close()
	body, rerr := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if rerr != nil {
		log.Printf("portal asset read failed for %s: %v", target, rerr)
		writeRaw(w, 204, "No Content", nil, nil)
		return true
	}
	headers := map[string]string{}
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		headers["Content-Type"] = ct
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "" {
		headers["Cache-Control"] = cc
	}
	// writeRaw formats "HTTP/1.1 <code> <status>"; pass only the reason phrase
	// (not resp.Status, which already embeds the code → would double it).
	writeRaw(w, resp.StatusCode, http.StatusText(resp.StatusCode), headers, body)
	return true
}
