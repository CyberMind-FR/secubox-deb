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
	"strings"
)

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
func relaxCSPForLoader(h http.Header) bool {
	modified := false
	for _, name := range cspHeaderNames {
		vals := h.Values(name)
		if len(vals) == 0 {
			continue
		}
		out := make([]string, 0, len(vals))
		anyBypass := false
		for _, v := range vals {
			relaxed, bypassed := relaxCSPValue(v)
			if bypassed {
				out = append(out, relaxed)
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
	return modified
}

// relaxCSPValue relaxes a single CSP header value (one header line; a policy is
// a ';'-separated list of directives). It relaxes ONLY the effective script
// directive and ONLY when that directive would block the same-origin loader; it
// returns the rewritten value and whether such a blocking CSP was actually
// bypassed (the 🔓 proof condition). A value with no blocking script directive
// is returned effectively unchanged with bypassed=false.
func relaxCSPValue(value string) (out string, bypassed bool) {
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
	ttStripped := false
	for _, raw := range rawDirectives {
		fields := strings.Fields(raw)
		if len(fields) == 0 {
			continue // blank fragment (leading/trailing/double ';') → drop
		}
		name := strings.ToLower(fields[0])
		// #740 — Trusted Types (`require-trusted-types-for 'script'` / `trusted-types`)
		// block the banner's DOM injection (createElement + innerHTML are TT sinks)
		// REGARDLESS of script-src — this is why the banner vanished on strict
		// sites like franceinfo. Drop them so the inline banner can render.
		if name == "require-trusted-types-for" || name == "trusted-types" {
			ttStripped = true
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
	if effective >= 0 && scriptDirectiveBlocksLoader(dirs[effective].tokens) {
		dirs[effective].tokens = relaxScriptTokens(dirs[effective].tokens)
		bypassed = true
	}
	// Stripping Trusted Types is itself a bypass (the banner couldn't render
	// otherwise) — report it so the page's CSP is rewritten + flagged 🔓.
	bypassed = bypassed || ttStripped

	// Re-serialise: "name token token; name token; ...".
	parts := make([]string, 0, len(dirs))
	for _, d := range dirs {
		if len(d.tokens) > 0 {
			parts = append(parts, d.name+" "+strings.Join(d.tokens, " "))
		} else {
			parts = append(parts, d.name)
		}
	}
	return strings.Join(parts, "; "), bypassed
}

// scriptDirectiveBlocksLoader reports whether a script-governing directive (its
// value tokens) would BLOCK a same-origin external <script src="/__toolbox/
// loader.js">. It blocks when:
//   - 'none' (forbids everything), or an empty directive (also forbids all), or
//   - 'strict-dynamic' is present (host-source / 'self' / 'unsafe-inline' become
//     IGNORED, so a plain src script with no matching nonce/hash is refused), or
//   - none of 'self' / '*' / https: / http: is present (only specific foreign
//     hosts are allowed, which don't cover the page's own origin).
// It does NOT block when 'self' / '*' / a scheme-source allows same-origin AND
// 'strict-dynamic' is absent — then the loader already runs and we leave the CSP
// untouched (no false 🔓).
func scriptDirectiveBlocksLoader(tokens []string) bool {
	if len(tokens) == 0 {
		return true // empty script directive forbids all scripts
	}
	allowsSameOrigin := false
	for _, tk := range tokens {
		switch strings.ToLower(tk) {
		case "'none'", "'strict-dynamic'":
			return true
		case "'self'", "*", "https:", "http:":
			allowsSameOrigin = true
		}
	}
	return !allowsSameOrigin
}

// relaxScriptTokens rewrites the value tokens of a script-governing directive:
// drop 'strict-dynamic' / 'none', then ensure 'self' + 'unsafe-inline' are
// present (appended once). Existing host sources / nonces / hashes are kept.
func relaxScriptTokens(tokens []string) []string {
	kept := make([]string, 0, len(tokens)+len(loaderAllowSources))
	have := map[string]bool{}
	for _, tk := range tokens {
		// Source-expressions are matched case-insensitively for the keywords we
		// touch ('strict-dynamic' / 'none' / 'self' / 'unsafe-inline'); hosts,
		// nonces and hashes are preserved verbatim.
		low := strings.ToLower(tk)
		if cspDropSources[low] {
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
