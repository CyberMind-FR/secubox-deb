// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: sbxwaf — reverse-proxy skeleton tests
package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

// TestTrustedHostSkipsWAF verifies that a request to a trusted host is NOT
// blocked even when the payload would normally trigger the WAF.
// Mirrors Python check_request whitelist (secubox_waf.py:761-763).
func TestTrustedHostSkipsWAF(t *testing.T) {
	// Load real WAF rules so the attack payload would be caught on an untrusted host.
	rules := LoadRules(testdataPath("waf-rules.json"))

	const trustedHost = "git.gk2.secubox.in"

	// Backend that always returns 200 — should be reached for trusted hosts.
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	}))
	defer backend.Close()

	backendAddr := strings.TrimPrefix(backend.URL, "http://")
	h, p, err := splitHostPort(backendAddr)
	if err != nil {
		t.Fatalf("splitHostPort: %v", err)
	}

	banState := NewBan(300*1e9, 3)

	srv := &Server{
		rules: rules,
		ban:   banState,
		trustedHosts: parseTrustedHosts(trustedHost),
		routeLookup: func(host string) (string, int, bool) {
			return h, p, true
		},
	}
	handler := srv.handler()

	// Attack payload in query string (percent-encoded so httptest.NewRequest accepts it).
	// "union+select+1,2,3" → would be caught as SQLi on an untrusted host.
	req := httptest.NewRequest(http.MethodGet, "http://"+trustedHost+"/search?q=union+select+1%2C2%2C3", nil)
	req.Host = trustedHost
	// Simulate a non-private remote addr so privateCIDR doesn't skip first.
	req.RemoteAddr = "203.0.113.99:12345"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("trusted host with attack payload: expected 200 (bypass), got %d (WAF blocked — false positive on trusted host)",
			rec.Code)
	}

	// Sanity check: same payload on an UNTRUSTED host must be blocked (warns on first hit).
	srvUntrusted := &Server{
		rules:        rules,
		ban:          NewBan(300*1e9, 3),
		trustedHosts: parseTrustedHosts(""), // empty — no trusted hosts
		routeLookup: func(host string) (string, int, bool) {
			return h, p, true
		},
	}
	handlerUntrusted := srvUntrusted.handler()
	req2 := httptest.NewRequest(http.MethodGet, "http://untrusted.example.com/search?q=union+select+1%2C2%2C3", nil)
	req2.Host = "untrusted.example.com"
	req2.RemoteAddr = "203.0.113.99:12345"
	rec2 := httptest.NewRecorder()
	handlerUntrusted.ServeHTTP(rec2, req2)
	if rec2.Code == http.StatusOK {
		t.Fatal("untrusted host with SQLi payload must be blocked — test sanity check failed")
	}
}

// TestIsTrustedHost verifies isTrustedHost matching logic (with/without port).
func TestIsTrustedHost(t *testing.T) {
	srv := &Server{
		trustedHosts: parseTrustedHosts("git.gk2.secubox.in,10.100.0.1:9080"),
	}

	cases := []struct {
		host string
		want bool
	}{
		{"git.gk2.secubox.in", true},
		{"GIT.GK2.SECUBOX.IN", true},  // case-insensitive
		{"10.100.0.1:9080", true},      // host:port exact match
		{"untrusted.example.com", false},
		{"", false},
	}
	for _, tc := range cases {
		got := srv.isTrustedHost(tc.host)
		if got != tc.want {
			t.Errorf("isTrustedHost(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}

// TestParseTrustedHosts verifies parseTrustedHosts parses comma-separated input.
func TestParseTrustedHosts(t *testing.T) {
	m := parseTrustedHosts("a.example.com, b.example.com,c.example.com")
	for _, h := range []string{"a.example.com", "b.example.com", "c.example.com"} {
		if _, ok := m[h]; !ok {
			t.Errorf("expected %q in trusted set", h)
		}
	}
	if len(m) != 3 {
		t.Errorf("expected 3 entries, got %d", len(m))
	}
}

// ─── detect mode (Task 2) ────────────────────────────────────────────────────
//
// newDetectTestServer builds a Server wired the same way TestHandlerWarningThenBan
// (threatlog_test.go) and TestTrustedHostSkipsWAF (above) do: a routeLookup
// closure pointing at a stub backend, real Rules loaded from rulesPath, and a
// Ban tracker. There is no shared "newTestServer" helper in this package —
// every handler test in this file constructs *Server directly — so the detect
// tests follow that same pattern instead of inventing a new helper.
func newDetectTestServer(t *testing.T, backendURL, rulesPath string) *Server {
	t.Helper()
	backendAddr := strings.TrimPrefix(backendURL, "http://")
	h, p, err := splitHostPort(backendAddr)
	if err != nil {
		t.Fatalf("splitHostPort: %v", err)
	}
	return &Server{
		routeLookup: func(host string) (string, int, bool) {
			return h, p, true
		},
		rules: LoadRules(rulesPath),
		ban:   NewBan(300*time.Second, 3),
	}
}

// detectTestReq builds a request for /mgmt/tm/util/bash against app.example.com
// from a given public (non-RFC1918) client IP, so privateCIDR does not skip
// WAF inspection (mirrors the "203.0.113.x" TEST-NET-3 convention used
// elsewhere in this package, e.g. TestTrustedHostSkipsWAF / TestHandlerWarningThenBan).
func detectTestReq(clientIP string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "http://app.example.com/mgmt/tm/util/bash", nil)
	req.Host = "app.example.com"
	req.RemoteAddr = clientIP + ":12345"
	return req
}

// A detect category matches but the request MUST pass through, and NOTHING may
// be banned. A detect category must be as harmless as enabled:false, minus the
// log line.
func TestDetectModeLetsRequestThroughAndDoesNotBan(t *testing.T) {
	rulesPath := writeRulesFile(t, `{"cve_2024":{"name":"CVE","severity":"critical","mode":"detect",
		"patterns":[{"id":"cve-1","pattern":"/mgmt/tm/util/bash","desc":"F5 RCE"}]}}`)

	upstreamHit := false
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHit = true
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "upstream reached")
	}))
	defer backend.Close()

	const testClientIP = "203.0.113.77"
	s := newDetectTestServer(t, backend.URL, rulesPath)
	handler := s.handler()

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, detectTestReq(testClientIP))

	if rec.Code == http.StatusForbidden {
		t.Fatalf("detect mode returned 403; it must let the request through")
	}
	if !upstreamHit {
		t.Fatal("detect mode did not reach the upstream; the request was swallowed")
	}
	if s.ban != nil && s.ban.Count(testClientIP) != 0 {
		t.Fatalf("detect mode incremented the ban counter (%d); detect must never punish",
			s.ban.Count(testClientIP))
	}
}

// The same pattern in block mode must still block — the detect path must not
// leak into the default behaviour.
func TestBlockModeStillBlocks(t *testing.T) {
	rulesPath := writeRulesFile(t, `{"cve_2024":{"name":"CVE","severity":"critical","mode":"block",
		"patterns":[{"id":"cve-1","pattern":"/mgmt/tm/util/bash","desc":"F5 RCE"}]}}`)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream must never be reached in block mode")
	}))
	defer backend.Close()

	s := newDetectTestServer(t, backend.URL, rulesPath)
	rec := httptest.NewRecorder()
	s.handler().ServeHTTP(rec, detectTestReq("203.0.113.78"))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("block mode: got %d, want 403", rec.Code)
	}
}

// A category with no mode must block — non-regression for the 17 shipped ones.
func TestAbsentModeStillBlocks(t *testing.T) {
	rulesPath := writeRulesFile(t, `{"cve_2024":{"name":"CVE","severity":"critical",
		"patterns":[{"id":"cve-1","pattern":"/mgmt/tm/util/bash","desc":"F5 RCE"}]}}`)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream must never be reached when mode is absent (defaults to block)")
	}))
	defer backend.Close()

	s := newDetectTestServer(t, backend.URL, rulesPath)
	rec := httptest.NewRecorder()
	s.handler().ServeHTTP(rec, detectTestReq("203.0.113.79"))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("absent mode: got %d, want 403", rec.Code)
	}
}

// The threat record must say "detect" — otherwise stats conflate "blocked" with
// "would have blocked" and the 198k threat counter becomes a lie.
func TestDetectModeLogsActionDetect(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "threats.jsonl")
	rulesPath := writeRulesFile(t, `{"cve_2024":{"name":"CVE","severity":"critical","mode":"detect",
		"patterns":[{"id":"cve-1","pattern":"/mgmt/tm/util/bash","desc":"F5 RCE"}]}}`)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	s := newDetectTestServer(t, backend.URL, rulesPath)
	s.threatLog = NewThreatLog(logPath)

	s.handler().ServeHTTP(httptest.NewRecorder(), detectTestReq("203.0.113.80"))

	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("threat log not written: %v", err)
	}
	if !strings.Contains(string(raw), `"detect"`) {
		t.Fatalf("threat record must carry action=detect, got: %s", raw)
	}
	if strings.Contains(string(raw), `"banned"`) || strings.Contains(string(raw), `"warning"`) {
		t.Fatalf("detect must not be logged as warning/banned, got: %s", raw)
	}
}
