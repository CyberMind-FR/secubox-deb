// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: sbxwaf — request inspection + skip-list tests
//
// TDD for Task 2.2: wiring Rules.Match into the handler with CIDR/static/NC
// skip-lists and body preservation.
package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// buildSQLiRules writes a minimal waf-rules.json with a UNION SELECT pattern
// and returns the path. Caller cleanup handled by t.TempDir().
func buildSQLiRulesFile(t *testing.T) string {
	t.Helper()
	doc := map[string]any{
		"categories": map[string]any{
			"sqli": map[string]any{
				"name":     "SQL Injection",
				"severity": "high",
				"enabled":  true,
				"patterns": []any{
					map[string]any{"id": "sqli1", "pattern": `union\s+select`, "desc": "UNION SELECT"},
				},
			},
		},
	}
	f, err := os.CreateTemp(t.TempDir(), "waf-rules*.json")
	if err != nil {
		t.Fatalf("create temp rules: %v", err)
	}
	if err := json.NewEncoder(f).Encode(doc); err != nil {
		t.Fatalf("encode rules: %v", err)
	}
	f.Close()
	return f.Name()
}

// newInspectServer builds a Server wired with rules and a stub backend.
// backendURL is the httptest.Server URL the routeLookup will target.
func newInspectServer(t *testing.T, rulesPath string, backendAddr string) *Server {
	t.Helper()
	srv := &Server{
		routeLookup: func(host string) (ip string, port int, ok bool) {
			h, p, err := splitHostPort(backendAddr)
			if err != nil {
				return "", 0, false
			}
			return h, p, true
		},
		rules: LoadRules(rulesPath),
	}
	return srv
}

// TestInspectBlocksAttack: public IP + UNION SELECT in query → 403.
func TestInspectBlocksAttack(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	}))
	defer backend.Close()

	rulesPath := buildSQLiRulesFile(t)
	backendAddr := backend.URL[len("http://"):]
	srv := newInspectServer(t, rulesPath, backendAddr)

	handler := srv.handler()
	// Public IP, attack query: union+select (URL-encoded, '+' = space after decode)
	req := httptest.NewRequest(http.MethodGet, "http://app.example.com/?q=1+union+select+1,2,3", nil)
	req.Host = "app.example.com"
	req.RemoteAddr = "1.2.3.4:12345" // public IP — no trusted bypass
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for WAF hit from public IP, got %d", rec.Code)
	}
}

// TestInspectPrivateIPBypass: same attack from private IP → proxied (not 403).
func TestInspectPrivateIPBypass(t *testing.T) {
	const wantBody = "backend ok"
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, wantBody)
	}))
	defer backend.Close()

	rulesPath := buildSQLiRulesFile(t)
	backendAddr := backend.URL[len("http://"):]
	srv := newInspectServer(t, rulesPath, backendAddr)

	handler := srv.handler()
	req := httptest.NewRequest(http.MethodGet, "http://app.example.com/?q=1+union+select+1,2,3", nil)
	req.Host = "app.example.com"
	req.RemoteAddr = "192.168.1.50:12345" // private RFC1918 — bypass WAF
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code == http.StatusForbidden {
		t.Fatalf("private IP should bypass WAF inspection, got 403")
	}
	body, _ := io.ReadAll(rec.Result().Body)
	if string(body) != wantBody {
		t.Fatalf("expected backend body %q, got %q", wantBody, string(body))
	}
}

// TestInspectStaticAssetSkip: static asset path with attack query → not blocked.
func TestInspectStaticAssetSkip(t *testing.T) {
	const wantBody = "js ok"
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, wantBody)
	}))
	defer backend.Close()

	rulesPath := buildSQLiRulesFile(t)
	backendAddr := backend.URL[len("http://"):]
	srv := newInspectServer(t, rulesPath, backendAddr)

	handler := srv.handler()
	req := httptest.NewRequest(http.MethodGet, "http://app.example.com/app.js?q=1+union+select+1,2", nil)
	req.Host = "app.example.com"
	req.RemoteAddr = "1.2.3.4:12345" // public IP — but .js asset skips inspection
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code == http.StatusForbidden {
		t.Fatalf("static asset should skip WAF inspection, got 403")
	}
	body, _ := io.ReadAll(rec.Result().Body)
	if string(body) != wantBody {
		t.Fatalf("expected backend body %q, got %q", wantBody, string(body))
	}
}

// TestInspectNCBypass: NC mobile auth path with payload → not blocked.
func TestInspectNCBypass(t *testing.T) {
	const wantBody = "nc login ok"
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, wantBody)
	}))
	defer backend.Close()

	rulesPath := buildSQLiRulesFile(t)
	backendAddr := backend.URL[len("http://"):]
	srv := newInspectServer(t, rulesPath, backendAddr)

	handler := srv.handler()
	// NC mobile token path — even with an attack-looking body should not be blocked
	req := httptest.NewRequest(http.MethodPost, "http://app.example.com/index.php/login/v2/", bytes.NewBufferString("data=union+select+1,2"))
	req.Host = "app.example.com"
	req.RemoteAddr = "1.2.3.4:12345" // public IP
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code == http.StatusForbidden {
		t.Fatalf("NC bypass path should not be blocked, got 403")
	}
	body, _ := io.ReadAll(rec.Result().Body)
	if string(body) != wantBody {
		t.Fatalf("expected backend body %q, got %q", wantBody, string(body))
	}
}

// TestInspectLargeBodyForwardedIntact: a POST body larger than defaultMaxBodyInspect
// (1 MiB + 4 KiB) must arrive at the backend byte-for-byte intact.
// This is the regression test for the LimitReader truncation bug: the old code
// restored only the capped prefix to r.Body, silently dropping the tail.
func TestInspectLargeBodyForwardedIntact(t *testing.T) {
	// Build a benign body of exactly defaultMaxBodyInspect + 4 KiB (no attack pattern).
	// The WAF will inspect the first 1 MiB and pass it; the tail must survive too.
	const extraBytes = 4 * 1024
	bodySize := defaultMaxBodyInspect + extraBytes
	fullBody := make([]byte, bodySize)
	for i := range fullBody {
		fullBody[i] = byte('A' + (i % 26)) // deterministic fill, no attack pattern
	}

	var receivedBody []byte
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "received")
	}))
	defer backend.Close()

	rulesPath := buildSQLiRulesFile(t)
	backendAddr := backend.URL[len("http://"):]
	srv := newInspectServer(t, rulesPath, backendAddr)

	handler := srv.handler()
	req := httptest.NewRequest(http.MethodPost, "http://app.example.com/upload", bytes.NewReader(fullBody))
	req.Host = "app.example.com"
	req.RemoteAddr = "1.2.3.4:12345" // public IP — inspection runs
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code == http.StatusForbidden {
		t.Fatalf("benign large POST should not be blocked, got 403")
	}
	if len(receivedBody) != bodySize {
		t.Fatalf("backend received %d bytes, want %d (body was truncated)", len(receivedBody), bodySize)
	}
	if !bytes.Equal(receivedBody, fullBody) {
		// Find first differing byte for a useful diagnostic.
		for i := range fullBody {
			if i >= len(receivedBody) || receivedBody[i] != fullBody[i] {
				t.Fatalf("body mismatch at byte %d: got 0x%02x, want 0x%02x", i,
					func() byte {
						if i < len(receivedBody) {
							return receivedBody[i]
						}
						return 0
					}(), fullBody[i])
			}
		}
	}
}

// TestInspectLargeBodyAttackInFirstMiB: attack payload within the first 1 MiB
// of a large body must still be caught (inspection still works with streaming).
func TestInspectLargeBodyAttackInFirstMiB(t *testing.T) {
	// 512 KiB of attack prefix + 512 KiB + 4 KiB of padding.
	const extraBytes = 4 * 1024
	bodySize := defaultMaxBodyInspect + extraBytes
	body := make([]byte, bodySize)
	attackSnippet := []byte("union select 1,2,3")
	copy(body[:len(attackSnippet)], attackSnippet)
	// Fill the rest with harmless bytes.
	for i := len(attackSnippet); i < bodySize; i++ {
		body[i] = 'B'
	}

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	}))
	defer backend.Close()

	rulesPath := buildSQLiRulesFile(t)
	backendAddr := backend.URL[len("http://"):]
	srv := newInspectServer(t, rulesPath, backendAddr)

	handler := srv.handler()
	req := httptest.NewRequest(http.MethodPost, "http://app.example.com/upload", bytes.NewReader(body))
	req.Host = "app.example.com"
	req.RemoteAddr = "1.2.3.4:12345" // public IP
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for attack in first 1 MiB of large body, got %d", rec.Code)
	}
}

// TestInspectBodyForwarded: a POST whose body was read for inspection is still
// received intact by the backend.
func TestInspectBodyForwarded(t *testing.T) {
	const postBody = "name=alice&value=harmless"
	var receivedBody []byte

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "received")
	}))
	defer backend.Close()

	rulesPath := buildSQLiRulesFile(t)
	backendAddr := backend.URL[len("http://"):]
	srv := newInspectServer(t, rulesPath, backendAddr)

	handler := srv.handler()
	req := httptest.NewRequest(http.MethodPost, "http://app.example.com/submit", bytes.NewBufferString(postBody))
	req.Host = "app.example.com"
	req.RemoteAddr = "1.2.3.4:12345" // public IP — inspection runs but no hit
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code == http.StatusForbidden {
		t.Fatalf("benign POST should not be blocked, got 403")
	}
	if string(receivedBody) != postBody {
		t.Fatalf("backend received body %q, want %q (body not restored after read)", receivedBody, postBody)
	}
}
