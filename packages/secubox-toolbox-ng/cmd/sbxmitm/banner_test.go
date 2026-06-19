// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: transparency-banner loader inject tests (#662)
//
// Mirrors the authoritative Python tests of inject_banner._loader_script /
// _LoaderInjector / the /__toolbox/* request() short-circuit. The portal
// reverse-proxy integration (a live portal) is validated on-board, NOT here;
// these unit tests cover the pure injection logic + the path/url helpers.
package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// inlineTestScript is a stand-in for the COMPLETE inline banner body that
// fetchInlineBanner pulls from the portal. The Go engine treats it as an opaque
// string (the JS literal-baking is the portal's job, covered by the Python
// tests); these tests only assert placement / idempotency / fail-open. Shared
// across banner_test, gzip_test, compress_test, cosmetic_test.
const inlineTestScript = `(function(){window.__SBX_LOADER__=1;})();`

func TestInjectLoaderGuardIdempotent(t *testing.T) {
	// Body already carrying the guard → returned byte-for-byte unchanged.
	body := []byte("<html><head><!-- " + bannerGuard + " --><script></script></head><body>hi</body></html>")
	out := injectLoader(body, "abc123", false, false)
	if string(out) != string(body) {
		t.Fatalf("guarded body must be unchanged.\n got: %s", out)
	}
}

func TestInjectLoaderHeadInsertion(t *testing.T) {
	body := []byte(`<html><head lang="en"><title>x</title></head><body>hi</body></html>`)
	out := string(injectLoader(body, "deadbeef", true, false))
	// The tag must land right AFTER the first <head ...>'s closing '>'.
	headOpen := `<head lang="en">`
	idx := strings.Index(out, headOpen)
	if idx < 0 {
		t.Fatalf("head open lost: %s", out)
	}
	after := out[idx+len(headOpen):]
	wantTag := `<!-- ` + bannerGuard + ` --><script src="/__toolbox/loader.js" data-mh="deadbeef" data-wg="1" async></script>`
	if !strings.HasPrefix(after, wantTag) {
		t.Fatalf("tag not inserted right after <head>'s '>'.\n got: %s", after)
	}
	// <title> must still follow the injected tag (we inserted, not replaced).
	if !strings.Contains(out, wantTag+`<title>x</title>`) {
		t.Fatalf("original head content displaced: %s", out)
	}
}

func TestInjectLoaderBodyFallback(t *testing.T) {
	// No <head> → insert right BEFORE the first <body>.
	body := []byte(`<html><body class="x">hi</body></html>`)
	out := string(injectLoader(body, "cafe", false, false))
	wantTag := `<!-- ` + bannerGuard + ` --><script src="/__toolbox/loader.js" data-mh="cafe" data-wg="0" async></script>`
	if !strings.Contains(out, wantTag+`<body class="x">`) {
		t.Fatalf("tag not inserted right before <body>.\n got: %s", out)
	}
}

func TestInjectLoaderNeitherHeadNorBody(t *testing.T) {
	body := []byte(`<p>just a fragment</p>`)
	out := injectLoader(body, "x", true, false)
	if string(out) != string(body) {
		t.Fatalf("no head/body → must be unchanged.\n got: %s", out)
	}
}

func TestInjectLoaderWGAttr(t *testing.T) {
	cases := []struct {
		wg   bool
		want string
	}{
		{true, `data-wg="1"`},
		{false, `data-wg="0"`},
	}
	for _, c := range cases {
		out := string(injectLoader([]byte(`<head></head>`), "mh1", c.wg, false))
		if !strings.Contains(out, c.want) {
			t.Fatalf("wg=%v: want %q in %s", c.wg, c.want, out)
		}
	}
}

func TestInjectLoaderNonASCIIHashStripped(t *testing.T) {
	// Non-ascii bytes in the client hash are dropped (Python .encode("ascii","ignore")).
	out := string(injectLoader([]byte(`<head></head>`), "abécÿ12", false, false))
	if !strings.Contains(out, `data-mh="abc12"`) {
		t.Fatalf("non-ascii bytes not stripped: %s", out)
	}
}

func TestInjectLoaderHeadCaseInsensitive(t *testing.T) {
	body := []byte(`<HTML><HEAD></HEAD><BODY>hi</BODY></HTML>`)
	out := string(injectLoader(body, "z", false, false))
	if !strings.Contains(out, `<HEAD><!-- `+bannerGuard) {
		t.Fatalf("case-insensitive <HEAD> match failed: %s", out)
	}
}

func TestIsToolboxAssetPath(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/__toolbox/loader.js", true},
		{"/__toolbox/loader.js?v=2", true},
		{"/__toolbox/bundle", true},
		{"/__toolbox/bundle?mh=abc&wg=1", true},
		{"/__toolbox/other", false},
		{"/index.html", false},
		{"/", false},
		{"", false},
		{"/__toolboxbundle", false},
	}
	for _, c := range cases {
		if got := isToolboxAssetPath(c.path); got != c.want {
			t.Errorf("isToolboxAssetPath(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestPortalTargetURL(t *testing.T) {
	cases := []struct {
		portal, path, want string
	}{
		{"http://127.0.0.1:8088", "/__toolbox/loader.js", "http://127.0.0.1:8088/__toolbox/loader.js"},
		{"http://127.0.0.1:8088", "/__toolbox/bundle?mh=abc&wg=1", "http://127.0.0.1:8088/__toolbox/bundle?mh=abc&wg=1"},
		// Trailing slash on the portal base must not double up.
		{"http://127.0.0.1:8088/", "/__toolbox/loader.js", "http://127.0.0.1:8088/__toolbox/loader.js"},
	}
	for _, c := range cases {
		if got := portalTargetURL(c.portal, c.path); got != c.want {
			t.Errorf("portalTargetURL(%q,%q) = %q, want %q", c.portal, c.path, got, c.want)
		}
	}
}

// ── #662 inline banner (SW-immune; supersedes injectLoader in the live path) ──

func TestInjectInlineBannerEmptyScriptNoop(t *testing.T) {
	// scriptBody == "" (fetch failed/skipped) → no inject, body unchanged.
	body := []byte(`<html><head></head><body>hi</body></html>`)
	out := injectInlineBanner(body, "")
	if string(out) != string(body) {
		t.Fatalf("empty scriptBody must be a no-op.\n got: %s", out)
	}
}

func TestInjectInlineBannerGuardIdempotent(t *testing.T) {
	// Body already carrying the guard → returned byte-for-byte unchanged.
	body := []byte("<html><head><!-- " + bannerGuard + " --><script></script></head><body>hi</body></html>")
	out := injectInlineBanner(body, inlineTestScript)
	if string(out) != string(body) {
		t.Fatalf("guarded body must be unchanged.\n got: %s", out)
	}
}

func TestInjectInlineBannerHeadInsertion(t *testing.T) {
	body := []byte(`<html><head lang="en"><title>x</title></head><body>hi</body></html>`)
	out := string(injectInlineBanner(body, inlineTestScript))
	headOpen := `<head lang="en">`
	idx := strings.Index(out, headOpen)
	if idx < 0 {
		t.Fatalf("head open lost: %s", out)
	}
	after := out[idx+len(headOpen):]
	// An INLINE <script> (not <script src), carrying the body verbatim, right
	// after the <head>'s '>'.
	wantTag := `<!-- ` + bannerGuard + ` --><script>` + inlineTestScript + `</script>`
	if !strings.HasPrefix(after, wantTag) {
		t.Fatalf("inline tag not inserted right after <head>'s '>'.\n got: %s", after)
	}
	if strings.Contains(out, "<script src=") {
		t.Fatalf("inline banner must NOT be a <script src> tag: %s", out)
	}
	if !strings.Contains(out, wantTag+`<title>x</title>`) {
		t.Fatalf("original head content displaced: %s", out)
	}
}

func TestInjectInlineBannerBodyFallback(t *testing.T) {
	body := []byte(`<html><body class="x">hi</body></html>`)
	out := string(injectInlineBanner(body, inlineTestScript))
	wantTag := `<!-- ` + bannerGuard + ` --><script>` + inlineTestScript + `</script>`
	if !strings.Contains(out, wantTag+`<body class="x">`) {
		t.Fatalf("inline tag not inserted right before <body>.\n got: %s", out)
	}
}

func TestInjectInlineBannerNeitherHeadNorBody(t *testing.T) {
	body := []byte(`<p>just a fragment</p>`)
	out := injectInlineBanner(body, inlineTestScript)
	if string(out) != string(body) {
		t.Fatalf("no head/body → must be unchanged.\n got: %s", out)
	}
}

func TestInjectInlineBannerCaseInsensitiveHead(t *testing.T) {
	body := []byte(`<HTML><HEAD></HEAD><BODY>hi</BODY></HTML>`)
	out := string(injectInlineBanner(body, inlineTestScript))
	if !strings.Contains(out, `<HEAD><!-- `+bannerGuard) {
		t.Fatalf("case-insensitive <HEAD> match failed: %s", out)
	}
}

func TestFetchInlineBannerOK(t *testing.T) {
	// Portal returns a body + 200 → fetchInlineBanner returns (body, true) and
	// echoes mh/wg/csp into the query.
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte(inlineTestScript))
	}))
	defer srv.Close()

	body, ok := fetchInlineBanner(srv.URL, "deadbeef", true, true)
	if !ok {
		t.Fatal("fetchInlineBanner must report ok=true on a 200")
	}
	if body != inlineTestScript {
		t.Fatalf("fetchInlineBanner body mismatch: %q", body)
	}
	for _, want := range []string{"mh=deadbeef", "wg=1", "csp=1"} {
		if !strings.Contains(gotQuery, want) {
			t.Fatalf("query %q missing %q", gotQuery, want)
		}
	}
}

func TestFetchInlineBannerWGCSPZero(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		_, _ = w.Write([]byte(inlineTestScript))
	}))
	defer srv.Close()
	if _, ok := fetchInlineBanner(srv.URL, "x", false, false); !ok {
		t.Fatal("ok=true expected")
	}
	for _, want := range []string{"wg=0", "csp=0"} {
		if !strings.Contains(gotQuery, want) {
			t.Fatalf("query %q missing %q", gotQuery, want)
		}
	}
}

func TestFetchInlineBannerFailOpenDeadPortal(t *testing.T) {
	// A dead portal (closed listener) → fail-open: ("", false) → caller skips the
	// inject and serves the page intact. No panic, no error surfaced.
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close() // close BEFORE the fetch → dial error

	body, ok := fetchInlineBanner(url, "x", false, false)
	if ok {
		t.Fatal("dead portal must fail open (ok=false)")
	}
	if body != "" {
		t.Fatalf("fail-open body must be empty, got %q", body)
	}
}

func TestFetchInlineBannerNon2xxFailOpen(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	defer srv.Close()
	body, ok := fetchInlineBanner(srv.URL, "x", false, false)
	if ok || body != "" {
		t.Fatalf("non-2xx must fail open: ok=%v body=%q", ok, body)
	}
}
