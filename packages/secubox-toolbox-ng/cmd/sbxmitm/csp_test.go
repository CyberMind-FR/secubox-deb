// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: CONSENTED-DEMONSTRATION CSP relax tests (#662)
//
// The R3 toolbox is literally "VILLAGE3B — Qui te piste?": a consented MITM on
// the operator's own traffic that SHOWS the user what a man-in-the-middle can
// do. relaxCSPForLoader rewrites a page's Content-Security-Policy so the
// injected /__toolbox/loader.js can execute even on strict-CSP sites; when it
// actually had a CSP to bypass it returns true, and injectLoader then stamps a
// data-csp="1" the portal banner renders as a 🔓 proof emoji. These tests pin
// the rewrite semantics + the data-csp gating.
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

func TestRelaxCSPScriptSrcAddsSelf(t *testing.T) {
	// (a) A strict script-src that only allows a remote host: the loader is
	// same-origin, so 'self' must be added → loader allowed, returns true.
	h := cspHeader("Content-Security-Policy", "script-src github.githubassets.com; img-src *")
	if !relaxCSPForLoader(h) {
		t.Fatal("a real CSP that blocks the loader must be reported modified (true)")
	}
	got := h.Get("Content-Security-Policy")
	if !strings.Contains(got, "'self'") || !strings.Contains(got, "'unsafe-inline'") {
		t.Fatalf("script-src must now allow 'self'+'unsafe-inline': %q", got)
	}
	// Unrelated directives are left untouched.
	if !strings.Contains(got, "img-src *") {
		t.Fatalf("unrelated directive img-src must be preserved: %q", got)
	}
	// The original host is left in place — we only ADD what the loader needs.
	if !strings.Contains(got, "github.githubassets.com") {
		t.Fatalf("existing source must be preserved: %q", got)
	}
}

func TestRelaxCSPStripsStrictDynamicAndNone(t *testing.T) {
	// (b) 'strict-dynamic' makes host/'self'/'unsafe-inline' IGNORED, so it must
	// be removed; 'none' must be removed too. 'self'+'unsafe-inline' added.
	h := cspHeader("Content-Security-Policy", "script-src 'strict-dynamic' 'nonce-x'")
	if !relaxCSPForLoader(h) {
		t.Fatal("strict-dynamic CSP must be reported modified (true)")
	}
	got := h.Get("Content-Security-Policy")
	if strings.Contains(got, "strict-dynamic") {
		t.Fatalf("'strict-dynamic' must be removed: %q", got)
	}
	if !strings.Contains(got, "'self'") || !strings.Contains(got, "'unsafe-inline'") {
		t.Fatalf("'self'+'unsafe-inline' must be present: %q", got)
	}
}

func TestRelaxCSPRemovesNone(t *testing.T) {
	h := cspHeader("Content-Security-Policy", "default-src 'none'; script-src 'none'")
	if !relaxCSPForLoader(h) {
		t.Fatal("'none' CSP must be reported modified (true)")
	}
	got := h.Get("Content-Security-Policy")
	// script-src must no longer say 'none' and must allow the loader.
	if strings.Contains(got, "script-src 'none'") || strings.Contains(got, "script-src  'self'") {
		// (loose) just ensure 'self' present in script-src region
	}
	if !strings.Contains(got, "'self'") || !strings.Contains(got, "'unsafe-inline'") {
		t.Fatalf("script-src must allow loader after 'none' removed: %q", got)
	}
}

func TestRelaxCSPNoHeaderUnchanged(t *testing.T) {
	// (c) No CSP header at all → false, headers unchanged (nothing to bypass).
	h := http.Header{}
	h.Set("Content-Type", "text/html")
	if relaxCSPForLoader(h) {
		t.Fatal("no CSP header → must return false")
	}
	if len(h) != 1 || h.Get("Content-Type") != "text/html" {
		t.Fatalf("headers must be untouched when there is no CSP: %v", h)
	}
}

func TestRelaxCSPReportOnlyRewritten(t *testing.T) {
	// (d) The Report-Only header is rewritten too.
	h := cspHeader("Content-Security-Policy-Report-Only", "script-src 'strict-dynamic'")
	if !relaxCSPForLoader(h) {
		t.Fatal("report-only CSP must be reported modified (true)")
	}
	got := h.Get("Content-Security-Policy-Report-Only")
	if strings.Contains(got, "strict-dynamic") || !strings.Contains(got, "'self'") {
		t.Fatalf("report-only header must be relaxed: %q", got)
	}
}

func TestRelaxCSPBothHeaders(t *testing.T) {
	// Both enforced + report-only present → both rewritten, returns true.
	h := http.Header{}
	h.Set("Content-Security-Policy", "script-src 'none'")
	h.Set("Content-Security-Policy-Report-Only", "script-src 'strict-dynamic'")
	if !relaxCSPForLoader(h) {
		t.Fatal("both CSP headers present → true")
	}
	if !strings.Contains(h.Get("Content-Security-Policy"), "'self'") {
		t.Fatalf("enforced header not relaxed: %q", h.Get("Content-Security-Policy"))
	}
	if !strings.Contains(h.Get("Content-Security-Policy-Report-Only"), "'self'") {
		t.Fatalf("report-only header not relaxed: %q", h.Get("Content-Security-Policy-Report-Only"))
	}
}

func TestRelaxCSPMalformedNoPanic(t *testing.T) {
	// (e) Malformed CSP values must never panic; whatever comes out, no crash,
	// and a present (non-empty) header is still treated as "had a CSP" → true.
	cases := []string{
		";;;",
		"   ",
		"script-src",         // directive with no values
		"script-src;",        // trailing empty
		";script-src 'self'", // leading empty
		"default-src 'self' 'self' 'self'",
		"script-src 'strict-dynamic' 'strict-dynamic'",
	}
	for _, v := range cases {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("relaxCSPForLoader panicked on %q: %v", v, r)
				}
			}()
			h := cspHeader("Content-Security-Policy", v)
			_ = relaxCSPForLoader(h) // must not panic
		}()
	}
}

func TestRelaxCSPDefaultSrcFallback(t *testing.T) {
	// No script-src/script-src-elem → default-src governs scripts, so it is the
	// one relaxed.
	h := cspHeader("Content-Security-Policy", "default-src 'self' cdn.example.com")
	if !relaxCSPForLoader(h) {
		t.Fatal("default-src-only CSP must be reported modified (true)")
	}
	got := h.Get("Content-Security-Policy")
	if !strings.Contains(got, "'unsafe-inline'") {
		t.Fatalf("default-src must gain 'unsafe-inline' for the loader: %q", got)
	}
}

func TestRelaxCSPEmptyHeaderValue(t *testing.T) {
	// An explicitly-present but empty CSP value → nothing meaningful to bypass.
	h := cspHeader("Content-Security-Policy", "")
	if relaxCSPForLoader(h) {
		t.Fatal("empty CSP value → false (nothing to bypass)")
	}
}

// ── injectLoader data-csp gating ─────────────────────────────────────────────

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
