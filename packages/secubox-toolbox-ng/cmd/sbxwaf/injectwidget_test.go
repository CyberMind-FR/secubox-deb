// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestInjectWidgetHTMLBeforeBodyClose(t *testing.T) {
	in := []byte(`<html><head></head><body><h1>hi</h1></body></html>`)
	out := injectWidgetHTML(in, 1234)
	s := string(out)
	if !strings.Contains(s, widgetGuard) {
		t.Fatalf("widget guard absent:\n%s", s)
	}
	if !strings.Contains(s, "1234 visites") {
		t.Fatalf("visit count not rendered:\n%s", s)
	}
	// The widget must land BEFORE the closing </body>.
	gi := strings.Index(s, widgetGuard)
	bi := strings.LastIndex(strings.ToLower(s), "</body>")
	if gi < 0 || bi < 0 || gi > bi {
		t.Fatalf("widget not before </body> (guard=%d body=%d)", gi, bi)
	}
	// Original content preserved.
	if !strings.Contains(s, "<h1>hi</h1>") {
		t.Fatalf("original content displaced:\n%s", s)
	}
}

func TestInjectWidgetIdempotent(t *testing.T) {
	in := []byte(`<body>x</body>`)
	once := injectWidgetHTML(in, 5)
	twice := injectWidgetHTML(once, 5)
	if !bytes.Equal(once, twice) {
		t.Fatalf("second injection must be a no-op (idempotent)")
	}
	if n := strings.Count(string(twice), widgetGuard); n != 1 {
		t.Fatalf("expected exactly 1 widget, got %d", n)
	}
}

func TestInjectWidgetNoBodyPassthrough(t *testing.T) {
	in := []byte(`{"json":true}`) // no </body>
	out := injectWidgetHTML(in, 9)
	if !bytes.Equal(in, out) {
		t.Fatalf("non-HTML (no </body>) must pass through unchanged")
	}
}

func TestInjectWidgetBodyGzipRoundTrip(t *testing.T) {
	html := []byte(`<html><body>content</body></html>`)
	out, ok := injectWidgetBody(html, "", 42)
	if !ok || !bytes.Contains(out, []byte(widgetGuard)) {
		t.Fatalf("identity inject must report ok + contain widget")
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
