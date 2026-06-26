// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// SecuBox-Deb :: sbxwaf :: WAF-injected health/visit widget (#747)
//
// On OUR OWN sites (the operator-configured host suffixes), the WAF injects a
// tiny "health widget" footer badge into the HTML it serves — a discreet
// SecuBox-protected mark carrying the live visit counter. It is the WAF analogue
// of the toolbox transparency banner, but for first-party sites: "this site is
// behind the SecuBox WAF, and here is its visit count".
//
// Injection is decompression-aware (gzip/br/zstd via internal/httpcodec),
// idempotent (a guard marker), and STRICTLY fail-open: any decode/encode failure
// or a missing </body> returns the original bytes untouched — a widget is never
// worth breaking a page. Only text/html responses on configured hosts are touched.
package main

import (
	"bytes"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/httpcodec"
)

// widgetMaxBody caps how large an HTML response we will buffer to inject into.
// Larger HTML pages (rare) are passed through untouched — never worth the memory.
const widgetMaxBody = 4 << 20 // 4 MiB

// applyWidget injects the SecuBox health banner loader into an upstream HTML
// response when (a) injection is enabled (origin + hosts non-empty), (b) the
// request host matches a configured first-party suffix, and (c) the response is
// text/html under the size cap. STRICTLY fail-open: any issue leaves the response
// byte-identical. Called from the reverse-proxy ModifyResponse hook.
func applyWidget(resp *http.Response, host string, origin string, hosts []string) {
	if origin == "" || len(hosts) == 0 || resp == nil || resp.Body == nil {
		return
	}
	if !widgetHostMatch(host, hosts) || !isHTMLResponse(resp.Header.Get("Content-Type")) {
		return
	}
	// Don't try to inject into a body we won't fully buffer.
	if resp.ContentLength > widgetMaxBody {
		return
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, widgetMaxBody+1))
	resp.Body.Close()
	if err != nil || int64(len(body)) > widgetMaxBody {
		// Restore whatever we read so the client still gets the bytes, fail-open.
		resp.Body = io.NopCloser(bytes.NewReader(body))
		return
	}
	out, ok := injectWidgetBody(body, resp.Header.Get("Content-Encoding"), origin)
	if !ok {
		resp.Body = io.NopCloser(bytes.NewReader(body))
		return
	}
	resp.Body = io.NopCloser(bytes.NewReader(out))
	resp.ContentLength = int64(len(out))
	resp.Header.Set("Content-Length", strconv.Itoa(len(out)))
}

// widgetGuard marks an already-injected document so a re-proxied response is not
// double-stamped.
const widgetGuard = "sbxwaf-health-banner-loader"

// healthBannerSnippet emits the loader for the SHARED SecuBox health banner
// (shared/health-banner.js) in its CDN-injected mode: it points the banner's APIs
// + asset at the canonical Hub origin (absolute URLs) so the SAME health widget
// the dashboard shows also mounts on first-party content sites. The banner script
// self-guards against double-init (window.__SBX_HEALTH_BANNER__); IS_CDN_INJECTED
// becomes true because window.SECUBOX_HEALTH_API is set.
func healthBannerSnippet(origin string) string {
	o := strings.TrimRight(origin, "/")
	return `<script id="` + widgetGuard + `">(function(){` +
		`if(window.__SBX_HEALTH_BANNER__)return;` +
		`var O=` + jsString(o) + `;` +
		`window.SECUBOX_HEALTH_API=O+'/api/v1/metrics/health/summary';` +
		`window.SECUBOX_VISITOR_ORIGIN_API=O+'/api/v1/metrics/visitor-origin';` +
		`window.SECUBOX_LIVE_HOSTS_API=O+'/api/v1/metrics/live-hosts';` +
		`window.SECUBOX_CERT_STATUS_API=O+'/api/v1/metrics/cert-status';` +
		`window.SECUBOX_COOKIE_AUDIT_SUMMARY=O+'/api/v1/cookie-audit/summary';` +
		`var s=document.createElement('script');s.src=O+'/shared/health-banner.js';s.async=true;` +
		`document.body.appendChild(s);})();</script>`
}

// jsString returns a safe single-quoted JS string literal for s (escapes the few
// metacharacters that matter inside '...'); origins are operator-config hostnames
// so this is belt-and-braces, not untrusted input.
func jsString(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `'`, `\'`, "\n", `\n`, "\r", `\r`, "<", `\x3c`)
	return "'" + r.Replace(s) + "'"
}

// injectWidgetHTML inserts the health-banner loader just before the closing
// </body> tag of a decompressed HTML document. Returns the original bytes
// unchanged when there is no </body>, the loader was already injected, OR the
// page ALREADY ships the health banner itself (a dashboard page) — so we never
// double-mount it.
func injectWidgetHTML(plain []byte, origin string) []byte {
	if bytes.Contains(plain, []byte(widgetGuard)) ||
		bytes.Contains(plain, []byte("health-banner.js")) ||
		bytes.Contains(plain, []byte("__SBX_HEALTH_BANNER__")) {
		return plain // already has the banner (loader or first-party include)
	}
	// Case-insensitive search for the LAST </body>.
	low := bytes.ToLower(plain)
	idx := bytes.LastIndex(low, []byte("</body>"))
	if idx < 0 {
		return plain // no body close → nothing safe to do
	}
	snippet := []byte(healthBannerSnippet(origin))
	out := make([]byte, 0, len(plain)+len(snippet))
	out = append(out, plain[:idx]...)
	out = append(out, snippet...)
	out = append(out, plain[idx:]...)
	return out
}

// injectWidgetBody decompresses (per Content-Encoding), injects the widget, and
// re-encodes in the SAME codec. Fail-open on any error. Returns (out, true) when
// the body was rewritten, (body, false) otherwise — the caller updates
// Content-Length to len(out) only when ok.
func injectWidgetBody(body []byte, encoding string, origin string) (out []byte, ok bool) {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "":
		inj := injectWidgetHTML(body, origin)
		return inj, len(inj) != len(body)
	case "gzip", "br", "zstd":
		plain, err := httpcodec.Decode(encoding, body)
		if err != nil {
			return body, false // fail open: serve the original compressed bytes
		}
		inj := injectWidgetHTML(plain, origin)
		if len(inj) == len(plain) {
			return body, false // nothing injected → keep original (avoid re-encode churn)
		}
		reenc, err := httpcodec.Encode(encoding, inj)
		if err != nil {
			return body, false // never serve a truncated frame
		}
		return reenc, true
	default:
		return body, false // unknown encoding we cannot decode → pass through
	}
}

// isHTMLResponse reports whether a Content-Type is an HTML document we may inject
// into (text/html, optionally with a charset parameter).
func isHTMLResponse(contentType string) bool {
	ct := strings.ToLower(strings.TrimSpace(contentType))
	return strings.HasPrefix(ct, "text/html")
}

// splitCSV splits a comma-separated flag value into trimmed, lowercased,
// non-empty entries.
func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(strings.ToLower(p)); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// widgetHostMatch reports whether host (bare, lowercased) ends with one of the
// configured first-party suffixes the operator opted into widget injection for.
func widgetHostMatch(host string, suffixes []string) bool {
	for _, s := range suffixes {
		if s == "" {
			continue
		}
		// Exact host, or a dot-boundary subdomain — NOT a bare suffix match
		// (which would wrongly match "notsecubox.in" against "secubox.in").
		if host == s || strings.HasSuffix(host, "."+s) {
			return true
		}
	}
	return false
}
