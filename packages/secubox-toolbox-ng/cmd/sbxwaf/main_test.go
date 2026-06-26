// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: sbxwaf — reverse-proxy skeleton tests
package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestProxyPassthrough verifies that a request whose Host is in the route map
// is forwarded to the backend and the response carries X-SecuBox-WAF: inspected.
func TestProxyPassthrough(t *testing.T) {
	// Stand up a stub backend that echoes a known body.
	const wantBody = "hello from backend"
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, wantBody)
	}))
	defer backend.Close()

	// Parse the backend host:port from its URL (strip "http://").
	backendAddr := strings.TrimPrefix(backend.URL, "http://")

	// Build a Server with one route: app.example.com → backend.
	srv := &Server{
		routeLookup: func(host string) (ip string, port int, ok bool) {
			if host == "app.example.com" {
				// Parse host:port from backendAddr.
				h, p, err := splitHostPort(backendAddr)
				if err != nil {
					return "", 0, false
				}
				return h, p, true
			}
			return "", 0, false
		},
	}

	// Build the handler and drive it with httptest.
	handler := srv.handler()

	req := httptest.NewRequest(http.MethodGet, "http://app.example.com/path", nil)
	req.Host = "app.example.com"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	res := rec.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}

	body, _ := io.ReadAll(res.Body)
	if string(body) != wantBody {
		t.Fatalf("expected body %q, got %q", wantBody, string(body))
	}

	wafHeader := res.Header.Get("X-SecuBox-WAF")
	if wafHeader != "inspected" {
		t.Fatalf("expected X-SecuBox-WAF: inspected, got %q", wafHeader)
	}
}

// TestProxyUnmapped verifies that a request to an unmapped Host gets 421.
func TestProxyUnmapped(t *testing.T) {
	srv := &Server{
		routeLookup: func(host string) (ip string, port int, ok bool) {
			return "", 0, false
		},
	}

	handler := srv.handler()
	req := httptest.NewRequest(http.MethodGet, "http://unknown.example.com/", nil)
	req.Host = "unknown.example.com"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusMisdirectedRequest {
		t.Fatalf("expected 421, got %d", rec.Code)
	}
}
