// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

package main

import (
	"bytes"
	"strings"
	"testing"
)

const testOrigin = "https://admin.gk2.secubox.in"

func TestInjectWidgetHTMLBeforeBodyClose(t *testing.T) {
	in := []byte(`<html><head></head><body><h1>hi</h1></body></html>`)
	out := injectWidgetHTML(in, testOrigin)
	s := string(out)
	if !strings.Contains(s, widgetGuard) {
		t.Fatalf("loader guard absent:\n%s", s)
	}
	// The loader points the banner asset/API at the Hub origin (O+'/path' at runtime).
	if !strings.Contains(s, "/shared/health-banner.js") {
		t.Fatalf("health-banner asset path absent:\n%s", s)
	}
	if !strings.Contains(s, testOrigin) {
		t.Fatalf("Hub origin absent from loader:\n%s", s)
	}
	if !strings.Contains(s, "SECUBOX_HEALTH_API") {
		t.Fatalf("health API override absent:\n%s", s)
	}
	// The loader must land BEFORE the closing </body>.
	gi := strings.Index(s, widgetGuard)
	bi := strings.LastIndex(strings.ToLower(s), "</body>")
	if gi < 0 || bi < 0 || gi > bi {
		t.Fatalf("loader not before </body> (guard=%d body=%d)", gi, bi)
	}
	if !strings.Contains(s, "<h1>hi</h1>") {
		t.Fatalf("original content displaced:\n%s", s)
	}
}

func TestInjectWidgetIdempotent(t *testing.T) {
	in := []byte(`<body>x</body>`)
	once := injectWidgetHTML(in, testOrigin)
	twice := injectWidgetHTML(once, testOrigin)
	if !bytes.Equal(once, twice) {
		t.Fatalf("second injection must be a no-op (idempotent)")
	}
	if n := strings.Count(string(twice), widgetGuard); n != 1 {
		t.Fatalf("expected exactly 1 loader, got %d", n)
	}
}

func TestInjectWidgetSkipsPageThatAlreadyHasBanner(t *testing.T) {
	// A dashboard page already including the banner must NOT be double-mounted.
	in := []byte(`<body><script src="/shared/health-banner.js"></script></body>`)
	out := injectWidgetHTML(in, testOrigin)
	if !bytes.Equal(in, out) {
		t.Fatalf("page already shipping health-banner.js must be left untouched")
	}
}

func TestInjectWidgetNoBodyPassthrough(t *testing.T) {
	in := []byte(`{"json":true}`) // no </body>
	out := injectWidgetHTML(in, testOrigin)
	if !bytes.Equal(in, out) {
		t.Fatalf("non-HTML (no </body>) must pass through unchanged")
	}
}

func TestInjectWidgetBodyGzipRoundTrip(t *testing.T) {
	html := []byte(`<html><body>content</body></html>`)
	out, ok := injectWidgetBody(html, "", testOrigin)
	if !ok || !bytes.Contains(out, []byte(widgetGuard)) {
		t.Fatalf("identity inject must report ok + contain loader")
	}
}

func TestWidgetHostMatch(t *testing.T) {
	hosts := []string{"gk2.secubox.in", "cybermind.fr"}
	for _, h := range []string{"blog.gk2.secubox.in", "gk2.secubox.in", "www.cybermind.fr"} {
		if !widgetHostMatch(h, hosts) {
			t.Fatalf("%q should match first-party suffixes", h)
		}
	}
	for _, h := range []string{"evil.com", "notsecubox.in"} {
		if widgetHostMatch(h, hosts) {
			t.Fatalf("%q must NOT match", h)
		}
	}
}
