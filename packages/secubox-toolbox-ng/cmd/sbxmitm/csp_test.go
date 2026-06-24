// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: CONSENTED-DEMONSTRATION CSP relax tests (#662/#728)
//
// The R3 toolbox is literally "VILLAGE3B — Qui te piste?": a consented MITM on
// the operator's own traffic that SHOWS the user what a man-in-the-middle can
// do. The live path INLINES the transparency banner (service workers hijack a
// same-origin <script src>), so relaxCSPForLoader makes a page's CSP accept an
// inline <script>: it BORROWS the page's own nonce when there is one (surgical —
// the policy is left intact and the caller stamps that nonce), else it forces
// 'unsafe-inline' (dropping nonce/hash/strict-dynamic so the browser honours it).
// It also drops Trusted Types (which blocks the banner's DOM injection). When it
// changes a blocking CSP it returns modified=true and the borrowed nonce; the
// injected tag then carries data-csp="1" the portal renders as the 🔓 proof.
package main

import (
	"net/http"
	"strings"
	"testing"
)

// helper: build a one-header http.Header for the CSP under test.
func cspHeader(name, value string) http.Header {
	h := http.Header{}
	h.Set(name, value)
	return h
}

func TestRelaxCSPNoNonceForcesUnsafeInline(t *testing.T) {
	// A strict script-src with only a remote host and no inline allowance: no
	// nonce to borrow → fall back to 'self'+'unsafe-inline'; the host is kept.
	h := cspHeader("Content-Security-Policy", "script-src github.githubassets.com; img-src *")
	nonce, mod := relaxCSPForLoader(h)
	if !mod {
		t.Fatal("a CSP that blocks the inline banner must be reported modified (true)")
	}
	if nonce != "" {
		t.Fatalf("no nonce in the policy → borrowed nonce must be empty, got %q", nonce)
	}
	got := h.Get("Content-Security-Policy")
	if !strings.Contains(got, "'self'") || !strings.Contains(got, "'unsafe-inline'") {
		t.Fatalf("script-src must now allow 'self'+'unsafe-inline': %q", got)
	}
	if !strings.Contains(got, "img-src *") {
		t.Fatalf("unrelated directive img-src must be preserved: %q", got)
	}
	if !strings.Contains(got, "github.githubassets.com") {
		t.Fatalf("existing host source must be preserved: %q", got)
	}
}

func TestRelaxCSPBorrowsNonceAndLeavesPolicyIntact(t *testing.T) {
	// The surgical path: a nonce-based CSP (the YouTube/news shape). We must
	// RETURN the nonce (for the caller to stamp on <script nonce=…>) and leave the
	// directive's nonce + strict-dynamic in place — the page's CSP keeps working.
	h := cspHeader("Content-Security-Policy",
		"script-src 'nonce-AbC123def==' 'unsafe-inline' 'strict-dynamic' https: 'unsafe-eval'")
	nonce, mod := relaxCSPForLoader(h)
	if !mod {
		t.Fatal("a nonce-based CSP that blocks our bare inline script must be modified=true")
	}
	if nonce != "AbC123def==" {
		t.Fatalf("must borrow the page nonce value, got %q", nonce)
	}
	got := h.Get("Content-Security-Policy")
	if !strings.Contains(got, "'nonce-AbC123def=='") {
		t.Fatalf("borrowed-nonce path must leave the nonce in the policy: %q", got)
	}
	if !strings.Contains(got, "'strict-dynamic'") {
		t.Fatalf("borrowed-nonce path must NOT strip strict-dynamic: %q", got)
	}
}

func TestRelaxCSPNoNonceStripsStrictDynamicAndNone(t *testing.T) {
	// strict-dynamic with NO nonce to borrow → fall back: strict-dynamic and
	// 'none' must go (both make 'unsafe-inline' ineffective) and self+unsafe-inline
	// added.
	h := cspHeader("Content-Security-Policy", "script-src 'strict-dynamic'")
	nonce, mod := relaxCSPForLoader(h)
	if !mod || nonce != "" {
		t.Fatalf("strict-dynamic (no nonce) → modified=true, nonce=\"\"; got mod=%v nonce=%q", mod, nonce)
	}
	got := h.Get("Content-Security-Policy")
	if strings.Contains(got, "strict-dynamic") {
		t.Fatalf("'strict-dynamic' must be removed in the no-nonce fallback: %q", got)
	}
	if !strings.Contains(got, "'self'") || !strings.Contains(got, "'unsafe-inline'") {
		t.Fatalf("'self'+'unsafe-inline' must be present: %q", got)
	}
}

func TestRelaxCSPHashAlsoBlocksInline(t *testing.T) {
	// A hash-source ALSO makes 'unsafe-inline' ignored, so even a directive that
	// lists 'unsafe-inline' blocks our bare inline script. With no nonce, the
	// fallback drops the hash so 'unsafe-inline' becomes effective.
	h := cspHeader("Content-Security-Policy", "script-src 'self' 'unsafe-inline' 'sha256-abc123'")
	nonce, mod := relaxCSPForLoader(h)
	if !mod || nonce != "" {
		t.Fatalf("hash-pinned CSP → modified=true, nonce=\"\"; got mod=%v nonce=%q", mod, nonce)
	}
	got := h.Get("Content-Security-Policy")
	if strings.Contains(strings.ToLower(got), "sha256-") {
		t.Fatalf("hash-source must be dropped so unsafe-inline is honoured: %q", got)
	}
	if !strings.Contains(got, "'unsafe-inline'") {
		t.Fatalf("'unsafe-inline' must remain: %q", got)
	}
}

func TestRelaxCSPRemovesNone(t *testing.T) {
	h := cspHeader("Content-Security-Policy", "default-src 'none'; script-src 'none'")
	if _, mod := relaxCSPForLoader(h); !mod {
		t.Fatal("'none' CSP must be reported modified (true)")
	}
	got := h.Get("Content-Security-Policy")
	if !strings.Contains(got, "'self'") || !strings.Contains(got, "'unsafe-inline'") {
		t.Fatalf("script-src must allow the inline banner after 'none' removed: %q", got)
	}
}

func TestRelaxCSPNoHeaderUnchanged(t *testing.T) {
	h := http.Header{}
	h.Set("Content-Type", "text/html")
	if nonce, mod := relaxCSPForLoader(h); mod || nonce != "" {
		t.Fatalf("no CSP header → must return (\"\", false); got (%q, %v)", nonce, mod)
	}
	if len(h) != 1 || h.Get("Content-Type") != "text/html" {
		t.Fatalf("headers must be untouched when there is no CSP: %v", h)
	}
}

func TestRelaxCSPReportOnlyRewritten(t *testing.T) {
	h := cspHeader("Content-Security-Policy-Report-Only", "script-src 'strict-dynamic'")
	if _, mod := relaxCSPForLoader(h); !mod {
		t.Fatal("report-only CSP must be reported modified (true)")
	}
	got := h.Get("Content-Security-Policy-Report-Only")
	if strings.Contains(got, "strict-dynamic") || !strings.Contains(got, "'self'") {
		t.Fatalf("report-only header must be relaxed: %q", got)
	}
}

func TestRelaxCSPBothHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("Content-Security-Policy", "script-src 'none'")
	h.Set("Content-Security-Policy-Report-Only", "script-src 'strict-dynamic'")
	if _, mod := relaxCSPForLoader(h); !mod {
		t.Fatal("both CSP headers present → true")
	}
	if !strings.Contains(h.Get("Content-Security-Policy"), "'self'") {
		t.Fatalf("enforced header not relaxed: %q", h.Get("Content-Security-Policy"))
	}
	if !strings.Contains(h.Get("Content-Security-Policy-Report-Only"), "'self'") {
		t.Fatalf("report-only header not relaxed: %q", h.Get("Content-Security-Policy-Report-Only"))
	}
}

func TestRelaxCSPDropsTrustedTypes(t *testing.T) {
	// YouTube sends a STANDALONE "require-trusted-types-for 'script'" header, which
	// blocks the banner's DOM injection. It must be dropped, and a policy that was
	// ONLY that directive must serialise to no header line (not a bare empty one).
	h := http.Header{}
	h.Add("Content-Security-Policy", "require-trusted-types-for 'script'")
	h.Add("Content-Security-Policy", "object-src 'none'; script-src 'nonce-Zx9' 'strict-dynamic'")
	nonce, mod := relaxCSPForLoader(h)
	if !mod {
		t.Fatal("Trusted Types + nonce CSP must be modified=true")
	}
	if nonce != "Zx9" {
		t.Fatalf("must still borrow the nonce alongside the TT drop, got %q", nonce)
	}
	vs := h.Values("Content-Security-Policy")
	if len(vs) != 1 {
		t.Fatalf("the TT-only header line must be dropped, leaving 1 value, got %d: %#v", len(vs), vs)
	}
	if strings.Contains(strings.ToLower(strings.Join(vs, " ")), "trusted-types") {
		t.Fatalf("trusted-types directives must be gone: %v", vs)
	}
}

func TestRelaxCSPMalformedNoPanic(t *testing.T) {
	cases := []string{
		";;;",
		"   ",
		"script-src",
		"script-src;",
		";script-src 'self'",
		"default-src 'self' 'self' 'self'",
		"script-src 'strict-dynamic' 'strict-dynamic'",
		"script-src 'nonce-'", // empty nonce value → must not be borrowed
		"require-trusted-types-for",
	}
	for _, v := range cases {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("relaxCSPForLoader panicked on %q: %v", v, r)
				}
			}()
			h := cspHeader("Content-Security-Policy", v)
			relaxCSPForLoader(h) // must not panic
		}()
	}
}

func TestRelaxCSPDefaultSrcFallback(t *testing.T) {
	// No script-src/script-src-elem → default-src governs scripts; a blocking
	// default-src (host only, no inline) must be relaxed.
	h := cspHeader("Content-Security-Policy", "default-src cdn.example.com")
	if _, mod := relaxCSPForLoader(h); !mod {
		t.Fatal("blocking default-src-only CSP must be reported modified (true)")
	}
	got := h.Get("Content-Security-Policy")
	if !strings.Contains(got, "'self'") || !strings.Contains(got, "'unsafe-inline'") {
		t.Fatalf("default-src must gain 'self'+'unsafe-inline' for the inline banner: %q", got)
	}
}

func TestRelaxCSPAlreadyAllowedNotFlagged(t *testing.T) {
	// The honesty test: a CSP that ALREADY permits a bare inline script (has
	// 'unsafe-inline' and NO nonce/hash/strict-dynamic), or has no script-governing
	// directive at all, must NOT be flagged and must be left byte-for-byte intact —
	// no false 🔓.
	for _, v := range []string{
		"script-src 'self' 'unsafe-inline' https://js.stripe.com",
		"script-src 'unsafe-inline'",
		"default-src 'unsafe-inline'",
		"img-src *; style-src 'self'", // no script-governing directive at all
	} {
		h := cspHeader("Content-Security-Policy", v)
		nonce, mod := relaxCSPForLoader(h)
		if mod || nonce != "" {
			t.Fatalf("already-permissive CSP must NOT be flagged: %q (mod=%v nonce=%q)", v, mod, nonce)
		}
		if h.Get("Content-Security-Policy") != v {
			t.Fatalf("non-blocking CSP must be left verbatim: in=%q out=%q", v, h.Get("Content-Security-Policy"))
		}
	}
}

func TestRelaxCSPEmptyHeaderValue(t *testing.T) {
	h := cspHeader("Content-Security-Policy", "")
	if nonce, mod := relaxCSPForLoader(h); mod || nonce != "" {
		t.Fatalf("empty CSP value → (\"\", false); got (%q, %v)", nonce, mod)
	}
}

func TestNonceValueOKRejectsAttributeBreakout(t *testing.T) {
	// A hostile origin chooses its own nonce; an attribute-breakout attempt must
	// be refused so we never stamp it into nonce="…".
	bad := []string{`x" onload="alert(1)`, "a b", "a>b", "a'b", "", "héllo"}
	for _, v := range bad {
		if nonceValueOK(v) {
			t.Fatalf("nonceValueOK must reject %q", v)
		}
	}
	for _, v := range []string{"AbC123", "a-_+/==", "Zx9"} {
		if !nonceValueOK(v) {
			t.Fatalf("nonceValueOK must accept base64 value %q", v)
		}
	}
}

// ── injectLoader data-csp gating (external loader, kept for compat) ───────────

func TestInjectLoaderDataCSPWhenBypassed(t *testing.T) {
	out := string(injectLoader([]byte(`<head></head>`), "mh1", true, true))
	if !strings.Contains(out, `data-csp="1"`) {
		t.Fatalf("cspBypassed=true must stamp data-csp=\"1\": %s", out)
	}
}

func TestInjectLoaderNoDataCSPWhenNotBypassed(t *testing.T) {
	out := string(injectLoader([]byte(`<head></head>`), "mh1", true, false))
	if strings.Contains(out, "data-csp") {
		t.Fatalf("cspBypassed=false must NOT emit data-csp: %s", out)
	}
}

// ── inline banner nonce stamping (#728) ──────────────────────────────────────

func TestInjectInlineBannerStampsNonce(t *testing.T) {
	out := string(injectInlineBanner([]byte(`<head></head>`), "BANNER();", "AbC123=="))
	if !strings.Contains(out, `<script nonce="AbC123==">BANNER();</script>`) {
		t.Fatalf("inline banner must carry the borrowed nonce: %s", out)
	}
}

func TestInjectInlineBannerNoNonceNoAttr(t *testing.T) {
	out := string(injectInlineBanner([]byte(`<head></head>`), "BANNER();", ""))
	if strings.Contains(out, "nonce=") {
		t.Fatalf("no nonce → no nonce attribute: %s", out)
	}
	if !strings.Contains(out, "<script>BANNER();</script>") {
		t.Fatalf("inline banner must still be injected without a nonce: %s", out)
	}
}
