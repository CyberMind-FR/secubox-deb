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
	"strings"
	"testing"
)

func TestInjectLoaderGuardIdempotent(t *testing.T) {
	// Body already carrying the guard → returned byte-for-byte unchanged.
	body := []byte("<html><head><!-- " + bannerGuard + " --><script></script></head><body>hi</body></html>")
	out := injectLoader(body, "abc123", false)
	if string(out) != string(body) {
		t.Fatalf("guarded body must be unchanged.\n got: %s", out)
	}
}

func TestInjectLoaderHeadInsertion(t *testing.T) {
	body := []byte(`<html><head lang="en"><title>x</title></head><body>hi</body></html>`)
	out := string(injectLoader(body, "deadbeef", true))
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
	out := string(injectLoader(body, "cafe", false))
	wantTag := `<!-- ` + bannerGuard + ` --><script src="/__toolbox/loader.js" data-mh="cafe" data-wg="0" async></script>`
	if !strings.Contains(out, wantTag+`<body class="x">`) {
		t.Fatalf("tag not inserted right before <body>.\n got: %s", out)
	}
}

func TestInjectLoaderNeitherHeadNorBody(t *testing.T) {
	body := []byte(`<p>just a fragment</p>`)
	out := injectLoader(body, "x", true)
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
		out := string(injectLoader([]byte(`<head></head>`), "mh1", c.wg))
		if !strings.Contains(out, c.want) {
			t.Fatalf("wg=%v: want %q in %s", c.wg, c.want, out)
		}
	}
}

func TestInjectLoaderNonASCIIHashStripped(t *testing.T) {
	// Non-ascii bytes in the client hash are dropped (Python .encode("ascii","ignore")).
	out := string(injectLoader([]byte(`<head></head>`), "abécÿ12", false))
	if !strings.Contains(out, `data-mh="abc12"`) {
		t.Fatalf("non-ascii bytes not stripped: %s", out)
	}
}

func TestInjectLoaderHeadCaseInsensitive(t *testing.T) {
	body := []byte(`<HTML><HEAD></HEAD><BODY>hi</BODY></HTML>`)
	out := string(injectLoader(body, "z", false))
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
