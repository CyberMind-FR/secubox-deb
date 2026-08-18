// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: CONSENTED-DEMONSTRATION CSP relax (#662)
//
// The R3 toolbox appliance is literally "VILLAGE3B — Qui te piste?": a consented
// man-in-the-middle on the operator's OWN R3 traffic whose whole point is to
// SHOW the user what a MITM can do. A strict Content-Security-Policy would stop
// the transparency-banner loader (<script src="/__toolbox/loader.js">) from
// executing — so on the R3/wg inject path (and ONLY there, gated by the
// --csp-bypass-demo flag) we deliberately relax the page's CSP just enough to
// let that one same-origin loader script run, then the injected tag carries
// data-csp="1" and the portal banner renders a 🔓 — the VISIBLE proof that the
// page's CSP was bypassed to inject. This is intentional, demonstrative, and
// toggleable; it is never applied to non-injected responses.
//
// relaxCSPForLoader rewrites BOTH the enforced and the report-only CSP headers.
// For the script-governing directive it ensures 'self' + 'unsafe-inline' are
// present and strips 'strict-dynamic' (which would make host/'self'/'unsafe-
// inline' ignored) and 'none'. ONLY the script directive is touched — img-src,
// style-src, connect-src, etc. are left exactly as the origin set them: we relax
// the minimum the loader needs, nothing more. It returns true iff a real CSP was
// present and modified — that is the proof condition for the 🔓.
//
// Pure standard library.
package main

import (
	"net/http"
	"regexp"
	"strings"
)

// #740 — Trusted Types delivered via a <meta http-equiv="Content-Security-Policy">
// tag (the common case on franceinfo/leparisien/20minutes/cnn) is NOT touched by
// the response-header relax, so the banner's innerHTML still throws. Strip the
// two TT directives out of any meta CSP so the banner (and its TT policy) renders.
var metaCSPTagRe = regexp.MustCompile(`(?is)<meta[^>]+http-equiv\s*=\s*["']?content-security-policy["']?[^>]*>`)
var ttDirectiveRe = regexp.MustCompile(`(?i)(?:require-trusted-types-for|trusted-types)\b[^;"'>]*;?`)

// stripMetaTrustedTypes removes require-trusted-types-for / trusted-types from
// every <meta http-equiv="Content-Security-Policy"> in the body (header CSP is
// handled separately by relaxCSPForLoader).
func stripMetaTrustedTypes(body []byte) []byte {
	if !metaCSPTagRe.Match(body) {
		return body
	}
	return metaCSPTagRe.ReplaceAllFunc(body, func(tag []byte) []byte {
		return ttDirectiveRe.ReplaceAll(tag, nil)
	})
}

// #740 — nonce-borrow. A nonce-based CSP (script-src 'nonce-XXX') makes
// 'unsafe-inline' INOPERATIVE (CSP spec), so relaxing the header can never let
// the inline banner run — and rewriting the policy breaks the page (x/twitter
// blocked its own bundles). Instead we extract the page's nonce and stamp it on
// the injected banner <script>: it then runs as a first-class trusted script
// with the policy left 100% intact. THE robust fix for strict-CSP sites.
var nonceRe = regexp.MustCompile(`(?i)'nonce-([A-Za-z0-9+/_=-]+)'`)

func extractCSPNonce(h http.Header) string {
	for _, name := range cspHeaderNames {
		for _, v := range h.Values(name) {
			if m := nonceRe.FindStringSubmatch(v); m != nil {
				return m[1]
			}
		}
	}
	return ""
}

// cspHeaderNames are the two response headers that carry a Content-Security-
// Policy. Both are rewritten: a report-only policy doesn't block scripts, but
// relaxing it too keeps the demonstration consistent (no console violations).
var cspHeaderNames = []string{
	"Content-Security-Policy",
	"Content-Security-Policy-Report-Only",
}

// loaderAllowSources are the source-expressions the same-origin loader script
// needs. 'self' lets /__toolbox/loader.js (same origin as the page) load;
// 'unsafe-inline' is added defensively so an inline shim is never blocked.
var loaderAllowSources = []string{"'self'", "'unsafe-inline'"}

// cspDropSources are source-expressions removed from the script directive:
//   - 'strict-dynamic' propagates trust only to scripts loaded by an already-
//     trusted (nonce/hash) script and makes host-source / 'self' / 'unsafe-
//     inline' IGNORED — leaving it in would defeat the relax.
//   - 'none' forbids every source; it must go for the loader to run.
var cspDropSources = map[string]bool{"'strict-dynamic'": true, "'none'": true}

// relaxCSPForLoader rewrites every CSP / CSP-Report-Only header value so a
// same-origin /__toolbox/loader.js <script> is allowed to execute, and reports
// whether any CSP header was present AND modified (the 🔓 proof condition).
//
// Robust by construction: it never panics on malformed input (empty values,
// stray semicolons, value-less directives all parse to harmless no-ops). If no
// CSP header is present at all, it changes nothing and returns false.
func relaxCSPForLoader(h http.Header) (nonce string, modified bool) {
	for _, name := range cspHeaderNames {
		vals := h.Values(name)
		if len(vals) == 0 {
			continue
		}
		out := make([]string, 0, len(vals))
		anyBypass := false
		for _, v := range vals {
			relaxed, n, bypassed := relaxCSPValue(v)
			if bypassed {
				// A policy that was ONLY a Trusted Types directive (e.g. YouTube's
				// standalone "require-trusted-types-for 'script'" header) serialises
				// to empty after the drop — emit no header line rather than a bare
				// "Content-Security-Policy:" (which is harmless but untidy).
				if strings.TrimSpace(relaxed) != "" {
					out = append(out, relaxed)
				}
				// Surface the FIRST nonce we found to borrow: the caller stamps it
				// on the injected <script nonce=…> so our inline banner is accepted
				// by a nonce-based CSP without us having to weaken the page's policy.
				if n != "" && nonce == "" {
					nonce = n
				}
				anyBypass = true
			} else {
				out = append(out, v) // not blocking → keep the original verbatim (minimal touch)
			}
		}
		if anyBypass {
			h.Del(name)
			for _, v := range out {
				h.Add(name, v)
			}
			modified = true
		}
	}
	return nonce, modified
}

// relaxCSPValue relaxes a single CSP header value (one header line; a policy is
// a ';'-separated list of directives). It relaxes ONLY the effective script
// directive and ONLY when that directive would block the same-origin loader; it
// returns the rewritten value and whether such a blocking CSP was actually
// bypassed (the 🔓 proof condition). A value with no blocking script directive
// is returned effectively unchanged with bypassed=false.
func relaxCSPValue(value string) (out string, nonce string, bypassed bool) {
	rawDirectives := strings.Split(value, ";")

	// Locate the script-governing directives. script-src and script-src-elem
	// govern <script> directly; if NEITHER is present, default-src is the
	// fallback that governs scripts, so that is the one we relax.
	var idxScriptSrc, idxScriptSrcElem, idxDefaultSrc = -1, -1, -1
	type dir struct {
		name   string   // lower-cased directive name ("" for a blank fragment)
		tokens []string // raw value tokens after the name
	}
	dirs := make([]dir, 0, len(rawDirectives))
	ttDropped := false
	for _, raw := range rawDirectives {
		fields := strings.Fields(raw)
		if len(fields) == 0 {
			continue // blank fragment (leading/trailing/double ';') → drop
		}
		name := strings.ToLower(fields[0])
		// Trusted Types (e.g. YouTube: "require-trusted-types-for 'script'")
		// blocks the transparency banner's DOM injection even when the loader
		// script itself is allowed to run — the banner silently never mounts.
		// Drop these two directives so the banner can render; the page keeps all
		// its other CSP protections (script-src is only minimally relaxed below).
		if name == "require-trusted-types-for" || name == "trusted-types" {
			ttDropped = true
			continue
		}
		d := dir{name: name, tokens: fields[1:]}
		switch name {
		case "script-src":
			idxScriptSrc = len(dirs)
		case "script-src-elem":
			idxScriptSrcElem = len(dirs)
		case "default-src":
			idxDefaultSrc = len(dirs)
		}
		dirs = append(dirs, d)
	}

	// Find the EFFECTIVE directive governing a <script src> element: per CSP,
	// script-src-elem wins, else script-src, else default-src. Only that one
	// decides whether the same-origin loader is blocked — and only it is relaxed.
	effective := -1
	switch {
	case idxScriptSrcElem >= 0:
		effective = idxScriptSrcElem
	case idxScriptSrc >= 0:
		effective = idxScriptSrc
	case idxDefaultSrc >= 0:
		effective = idxDefaultSrc
	}

	// Relax + flag the bypass ONLY when the effective directive would actually
	// BLOCK the same-origin loader. If the page already allows it (e.g. 'self' /
	// '*' / https: and no 'strict-dynamic'), or imposes no script restriction at
	// all, we touch nothing and report no bypass — so the 🔓 is honest proof that
	// a blocking CSP was defeated, not just that a CSP existed.
	if effective >= 0 && scriptDirectiveBlocksInline(dirs[effective].tokens) {
		// Prefer the SURGICAL path: borrow the page's own nonce and stamp it on
		// our injected <script nonce=…> (the caller does that) — the page's CSP,
		// its nonces and its hashes all keep working untouched. Only when there is
		// no nonce to borrow do we fall back to forcing 'unsafe-inline' (which
		// requires dropping nonce/hash/strict-dynamic so the browser honours it).
		if n := scriptNonce(dirs[effective].tokens); n != "" {
			nonce = n
		} else {
			dirs[effective].tokens = relaxScriptTokensInline(dirs[effective].tokens)
		}
		bypassed = true
	}
	// Dropping Trusted Types also counts as a relax (the banner couldn't mount
	// otherwise) — flag the bypass so the page is treated as injected.
	bypassed = bypassed || ttDropped

	// Re-serialise: "name token token; name token; ...".
	parts := make([]string, 0, len(dirs))
	for _, d := range dirs {
		if len(d.tokens) > 0 {
			parts = append(parts, d.name+" "+strings.Join(d.tokens, " "))
		} else {
			parts = append(parts, d.name)
		}
	}
	return strings.Join(parts, "; "), nonce, bypassed
}

// scriptDirectiveBlocksInline reports whether a script-governing directive would
// BLOCK our injected INLINE <script> banner (the live path inlines the banner so
// a site's service worker has no same-origin request to hijack — see banner.go).
//
// Per CSP, an inline <script> executes only if it carries a matching nonce/hash,
// OR 'unsafe-inline' is present AND the directive has NO nonce-source, NO hash-
// source and NO 'strict-dynamic' (ANY of those three make 'unsafe-inline' be
// IGNORED). So the directive ALREADY permits a bare inline script (→ not
// blocking, no relax, no false 🔓) exactly when it has 'unsafe-inline' and none
// of {nonce, hash, strict-dynamic}. Otherwise it blocks our banner — and we
// either borrow its nonce or force 'unsafe-inline' (see relaxCSPValue).
func scriptDirectiveBlocksInline(tokens []string) bool {
	if len(tokens) == 0 {
		return true // empty script directive forbids all scripts
	}
	hasUnsafeInline, hasNonceOrHash, hasStrictDynamic, hasNone := false, false, false, false
	for _, tk := range tokens {
		low := strings.ToLower(tk)
		switch {
		case low == "'none'":
			hasNone = true
		case low == "'unsafe-inline'":
			hasUnsafeInline = true
		case low == "'strict-dynamic'":
			hasStrictDynamic = true
		case isNonceOrHash(low):
			hasNonceOrHash = true
		}
	}
	if hasNone {
		return true
	}
	if hasUnsafeInline && !hasNonceOrHash && !hasStrictDynamic {
		return false // a bare inline script already runs → leave the CSP alone
	}
	return true
}

// isNonceOrHash reports whether a (lower-cased) source-expression is a nonce-
// source or a hash-source — the two kinds whose presence makes 'unsafe-inline'
// ignored by the browser.
func isNonceOrHash(low string) bool {
	return strings.HasPrefix(low, "'nonce-") ||
		strings.HasPrefix(low, "'sha256-") ||
		strings.HasPrefix(low, "'sha384-") ||
		strings.HasPrefix(low, "'sha512-")
}

// nonceValueOK reports whether v is a safe nonce value to stamp into an HTML
// attribute: base64 / base64url charset only. This refuses any value that could
// break out of the nonce="…" attribute (quotes, '>', spaces, control bytes) — a
// hostile origin can choose its own nonce, so we never echo it unvalidated.
func nonceValueOK(v string) bool {
	if v == "" {
		return false
	}
	for _, c := range v {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '+' || c == '/' || c == '=' || c == '-' || c == '_':
		default:
			return false
		}
	}
	return true
}

// scriptNonce returns the VALUE of the first 'nonce-…' source in a directive
// (the text between "'nonce-" and the closing "'"), or "" if there is none or it
// is not a safe attribute value. Nonces are case-SENSITIVE, so the value is read
// from the original token, not a lower-cased copy.
func scriptNonce(tokens []string) string {
	for _, tk := range tokens {
		if !strings.HasPrefix(strings.ToLower(tk), "'nonce-") || !strings.HasSuffix(tk, "'") {
			continue
		}
		v := tk[len("'nonce-") : len(tk)-1]
		if nonceValueOK(v) {
			return v
		}
	}
	return ""
}

// relaxScriptTokensInline is the NO-NONCE fallback: it rewrites a script-
// governing directive so a bare inline <script> is honoured. It drops
// 'strict-dynamic' / 'none' AND every nonce/hash source (each of which would
// otherwise make 'unsafe-inline' ignored), then ensures 'self' + 'unsafe-inline'
// are present. Existing host / scheme sources are preserved so the page's own
// external scripts keep loading.
func relaxScriptTokensInline(tokens []string) []string {
	kept := make([]string, 0, len(tokens)+len(loaderAllowSources))
	have := map[string]bool{}
	for _, tk := range tokens {
		// Source-expressions are matched case-insensitively for the keywords we
		// touch; hosts are preserved verbatim. Nonces/hashes are dropped so the
		// added 'unsafe-inline' is actually honoured by the browser.
		low := strings.ToLower(tk)
		if cspDropSources[low] || isNonceOrHash(low) {
			continue
		}
		if !have[low] {
			kept = append(kept, tk)
			have[low] = true
		}
	}
	for _, src := range loaderAllowSources {
		if !have[src] {
			kept = append(kept, src)
			have[src] = true
		}
	}
	return kept
}
