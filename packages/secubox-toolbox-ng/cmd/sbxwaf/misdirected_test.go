// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWriteMisdirected(t *testing.T) {
	rec := httptest.NewRecorder()
	writeMisdirected(rec, "wigbee.gk2.secubox.in")
	res := rec.Result()
	if res.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("status = %d, want 421", res.StatusCode)
	}
	if ct := res.Header.Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Fatalf("content-type = %q, want text/html", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "wigbee.gk2.secubox.in") {
		t.Fatal("body must contain the requested host")
	}
	if !strings.Contains(body, "421") {
		t.Fatal("body must contain the 421 code")
	}
}

func TestWriteMisdirectedEscapesHost(t *testing.T) {
	rec := httptest.NewRecorder()
	writeMisdirected(rec, "<script>alert(1)</script>.evil")
	body := rec.Body.String()
	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Fatal("host must be HTML-escaped — reflected XSS from the Host header")
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Fatal("expected the host to appear HTML-escaped")
	}
}
