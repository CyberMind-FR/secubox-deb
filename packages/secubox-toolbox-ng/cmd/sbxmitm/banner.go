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
func loaderScript(clientHash string, wg bool) []byte {
	wgVal := "0"
	if wg {
		wgVal = "1"
	}
	mh := asciiOnly(clientHash)
	tag := `<script src="/__toolbox/loader.js" data-mh="` + mh +
		`" data-wg="` + wgVal + `" async></script>`
	return []byte("<!-- " + bannerGuard + " -->" + tag)
}

// injectLoader inserts the loader <script> into an HTML body once. Placement
// mirrors the Python _LoaderInjector.__call__:
//   - guard idempotency: if the body already contains bannerGuard → unchanged.
//   - find the first (case-insensitive) "<head"; if present, find the next ">"
//     after it and insert the tag right after that ">".
//   - else find the first "<body" and insert the tag right BEFORE it.
//   - if neither is present → return the body unchanged (no inject).
func injectLoader(body []byte, clientHash string, wg bool) []byte {
	if bytes.Contains(body, []byte(bannerGuard)) {
		return body
	}
	script := loaderScript(clientHash, wg)
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

// ── /__toolbox/* reverse-proxy to the portal ─────────────────────────────────

// isToolboxAssetPath reports whether a request path is one of the banner assets
// the engine must serve itself (by reverse-proxying to the portal) for ANY
// origin. STARTSWITH (not exact) is REQUIRED: the path includes the query
// string and the bundle is fetched as /__toolbox/bundle?mh=..&wg=.. — an exact
// match would never fire. Mirrors the Python request() p.startswith(...) checks.
func isToolboxAssetPath(path string) bool {
	return strings.HasPrefix(path, "/__toolbox/loader.js") ||
		strings.HasPrefix(path, "/__toolbox/bundle")
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
