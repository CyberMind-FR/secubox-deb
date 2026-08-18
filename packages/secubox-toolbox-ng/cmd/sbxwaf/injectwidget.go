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
	"regexp"
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
func applyWidget(resp *http.Response, host string, origin string, hosts, exclus []string) {
	if origin == "" || len(hosts) == 0 || resp == nil || resp.Body == nil {
		return
	}
	if !widgetHostMatch(host, hosts) || !isHTMLResponse(resp.Header.Get("Content-Type")) {
		return
	}
	if widgetExcluded(host, exclus) {
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
// optOutMeta lets a page REFUSE the banner: <meta name="sbx-no-health-banner">.
//
// WHY A PAGE MUST BE ABLE TO SAY NO. The banner is an inline script. A page
// that ships a strict `script-src 'self'` — which a PUBLIC surface should —
// cannot execute it, so the browser blocks it and logs a violation on every
// single load. The banner does not appear either way; the only difference is
// whether the reader's console fills with errors that look like a broken site.
//
// Observed on bbs.gk2.secubox.in: the page carried this exact meta and shipped
// a strict policy, but sbxwaf had no opt-out at all — the tag was decorative,
// and the BBS logged a CSP violation on every page view. Reported as "login
// KO" by an operator, while login worked perfectly.
//
// Fail-safe direction: an unreadable or absent meta means "inject", the
// behaviour every existing page already relies on.
const optOutMeta = "sbx-no-health-banner"

// pageRefuseBanner reconnait l'opt-out <meta name="sbx-no-health-banner">.
//
// Ce refus est la porte que layout.html du BBS et les vhosts publics utilisent
// pour ecarter la banniere A LA SOURCE. Il etait DOCUMENTE mais pas implemente :
// la banniere passait quand meme, et ses styles inline heurtaient le CSP strict
// (style-src 'self') de ces pages. On tolere les variantes de graphie.
var reOptOut = regexp.MustCompile(`(?i)<meta\s+name\s*=\s*["']?sbx-no-health-banner`)

func pageRefuseBanner(plain []byte) bool { return reOptOut.Match(plain) }

func injectWidgetHTML(plain []byte, origin string) []byte {
	// Opt-out explicite de la page : on ne touche a rien.
	if pageRefuseBanner(plain) {
		return plain
	}
	if bytes.Contains(plain, []byte(widgetGuard)) ||
		bytes.Contains(plain, []byte("health-banner.js")) ||
		bytes.Contains(plain, []byte("__SBX_HEALTH_BANNER__")) {
		return plain // already has the banner (loader or first-party include)
	}
	// The page said no. Case-insensitive: HTML attribute names are not
	// case-sensitive, and a page written with `NAME=` would otherwise be
	// silently ignored.
	if bytes.Contains(bytes.ToLower(plain), []byte(optOutMeta)) {
		return plain
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
// widgetExcluded dit si un hote est une application TIERCE, dont on ne touche
// pas le HTML.
//
// CECI NE RETIRE RIEN AU WAF. L'hote reste inspecte, filtre et protege
// exactement comme avant — c'est meme pour ces applications-la que le WAF
// compte le plus : elles sont plus exposees et moins maitrisees que notre
// propre code. Seule l'INJECTION cosmetique du bandeau s'arrete.
//
// Pourquoi elle doit s'arreter : Mastodon, Nextcloud ou PeerTube servent leur
// propre politique de securite, stricte et legitime. Elle ne connait pas
// l'empreinte de notre bandeau, donc le navigateur le refuse — le script ne
// s'execute pas, et la console de l'utilisateur se remplit d'erreurs qui
// designent notre injection. On ajoute du bruit sans rien apporter.
//
// Une exclusion plutot qu'un suffixe plus etroit : ainsi tout nouveau vhost
// SecuBox recoit le bandeau sans qu'on ait a y penser, et seules les
// applications qu'on heberge sans les ecrire en sont retirees.
func widgetExcluded(host string, exclus []string) bool {
	for _, e := range exclus {
		if e == "" {
			continue
		}
		// Meme regle de frontiere que la correspondance : hote exact ou
		// sous-domaine sur un point, jamais un suffixe nu.
		if host == e || strings.HasSuffix(host, "."+e) {
			return true
		}
	}
	return false
}

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
