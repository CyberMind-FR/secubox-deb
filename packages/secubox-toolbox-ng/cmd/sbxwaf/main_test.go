// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: sbxwaf — reverse-proxy skeleton tests
package main

import (
	"io"
	"net"
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

// TestOnDemandProxiesToWaker verifies that a request for a host with no
// route, but present in the on-demand vhosts set, is reverse-proxied to the
// waker (unix socket) instead of getting a 421 — and that the Director
// rewrites the path to /_wake/<host>.
func TestOnDemandProxiesToWaker(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "waker.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen unix %s: %v", sockPath, err)
	}
	defer ln.Close()

	var gotPath string
	waker := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotPath = r.URL.Path
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, "waking up…")
		}),
	}
	go waker.Serve(ln) //nolint:errcheck
	defer waker.Close()

	srv := &Server{
		routeLookup: func(host string) (string, int, bool) { return "", 0, false },
		onDemand:    &OnDemand{entries: map[string]bool{"sleepy.example.com": true}},
		wakerSocket: sockPath,
	}

	handler := srv.handler()
	req := httptest.NewRequest(http.MethodGet, "http://sleepy.example.com/", nil)
	req.Host = "sleepy.example.com"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 from waker splash, got %d", rec.Code)
	}
	if gotPath != "/_wake/sleepy.example.com" {
		t.Fatalf("expected waker path /_wake/sleepy.example.com, got %q", gotPath)
	}

	// TestProxyUnmapped (above) already proves a host NOT in the on-demand set
	// still gets 421 from this same handler code path.
}

// TestOnDemandProxiesWithMixedCaseHost verifies that a mixed/upper-case Host
// header — which OnDemand.Contains already matches case-insensitively — is
// normalized to lowercase by the waker Director too, so the wake key sent to
// the waker matches the lowercase portal_domain stored in on-demand-vhosts.json.
// Without this normalization the waker's exact-match lookup on the mixed-case
// path would miss and the wake would never fire (permanent splash).
func TestOnDemandProxiesWithMixedCaseHost(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "waker3.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen unix %s: %v", sockPath, err)
	}
	defer ln.Close()

	var gotPath string
	waker := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotPath = r.URL.Path
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, "waking up…")
		}),
	}
	go waker.Serve(ln) //nolint:errcheck
	defer waker.Close()

	srv := &Server{
		routeLookup: func(host string) (string, int, bool) { return "", 0, false },
		// Stored lowercase, exactly as the on-demand-vhosts.json generator emits it.
		onDemand:    &OnDemand{entries: map[string]bool{"sleepy.example.com": true}},
		wakerSocket: sockPath,
	}

	handler := srv.handler()
	// Mixed-case Host header — a hand-typed URL or script caller.
	req := httptest.NewRequest(http.MethodGet, "http://Sleepy.Example.COM/", nil)
	req.Host = "Sleepy.Example.COM"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 from waker splash, got %d", rec.Code)
	}
	if gotPath != "/_wake/sleepy.example.com" {
		t.Fatalf("expected canonical lowercase waker path /_wake/sleepy.example.com, got %q", gotPath)
	}
}

// TestOnDemandVisitsExcluded verifies that a request served by the waker
// splash is NOT tallied into the legitimate visit-stats (mirrors the existing
// 403/421 exclusion).
func TestOnDemandVisitsExcluded(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "waker2.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen unix %s: %v", sockPath, err)
	}
	defer ln.Close()

	waker := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, "waking up…")
		}),
	}
	go waker.Serve(ln) //nolint:errcheck
	defer waker.Close()

	visits := NewVisitStats("") // no on-disk flush, just the in-memory counter
	srv := &Server{
		routeLookup: func(host string) (string, int, bool) { return "", 0, false },
		onDemand:    &OnDemand{entries: map[string]bool{"sleepy.example.com": true}},
		wakerSocket: sockPath,
		visits:      visits,
	}

	handler := srv.handler()
	req := httptest.NewRequest(http.MethodGet, "http://sleepy.example.com/", nil)
	req.Host = "sleepy.example.com"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 from waker splash, got %d", rec.Code)
	}
	if got := visits.Total(); got != 0 {
		t.Fatalf("waker splash must not be tallied as a legitimate visit; total = %d", got)
	}
}

// TestVhostSignalsRecordedForRealOnDemandRequest verifies the handler()
// Begin/End hook (#896 Task 15): a request to an on-demand vhost that DOES
// have a live route is bracketed — active_conns is back to 0 (End ran) and
// last_request_ts is set once the request completes.
func TestVhostSignalsRecordedForRealOnDemandRequest(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()
	backendAddr := strings.TrimPrefix(backend.URL, "http://")

	vs := NewVhostSignals("") // no on-disk flush, inspect state directly
	srv := &Server{
		routeLookup: func(host string) (string, int, bool) {
			h, p, err := splitHostPort(backendAddr)
			if err != nil {
				return "", 0, false
			}
			return h, p, true
		},
		onDemand:     &OnDemand{entries: map[string]bool{"sleepy.example.com": true}},
		vhostSignals: vs,
	}

	handler := srv.handler()
	req := httptest.NewRequest(http.MethodGet, "http://sleepy.example.com/", nil)
	req.Host = "sleepy.example.com"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 from the real backend, got %d", rec.Code)
	}

	snap := vs.snapshot()
	entry, ok := snap["sleepy.example.com"]
	if !ok {
		t.Fatal("expected sleepy.example.com to be recorded in vhost signals")
	}
	if entry.ActiveConns != 0 {
		t.Fatalf("expected active_conns=0 once the (synchronous) request completed, got %d", entry.ActiveConns)
	}
	if entry.LastRequestTS == 0 {
		t.Fatal("expected a non-zero last_request_ts")
	}
}

// TestVhostSignalsExcludedForWakerBranch verifies that a request served by
// the waker splash (the vhost is asleep, no live route) is NOT recorded into
// vhost signals — recording it would make a sleeping vhost look like it just
// received a real hit, defeating the idle check (mirrors the analogous
// TestOnDemandVisitsExcluded for the #747 visit-stats aggregator).
func TestVhostSignalsExcludedForWakerBranch(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "waker-vhostsignals.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen unix %s: %v", sockPath, err)
	}
	defer ln.Close()

	waker := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, "waking up…")
		}),
	}
	go waker.Serve(ln) //nolint:errcheck
	defer waker.Close()

	vs := NewVhostSignals("")
	srv := &Server{
		routeLookup:  func(host string) (string, int, bool) { return "", 0, false },
		onDemand:     &OnDemand{entries: map[string]bool{"sleepy.example.com": true}},
		wakerSocket:  sockPath,
		vhostSignals: vs,
	}

	handler := srv.handler()
	req := httptest.NewRequest(http.MethodGet, "http://sleepy.example.com/", nil)
	req.Host = "sleepy.example.com"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 from waker splash, got %d", rec.Code)
	}
	if snap := vs.snapshot(); len(snap) != 0 {
		t.Fatalf("waker splash must not be recorded in vhost signals; got %+v", snap)
	}
}

// TestVhostSignalsExcludedForWAFBlock is the regression test for a Task 15
// review finding: an on-demand vhost WITH a live backend that the WAF blocks
// (403 warning/ban) must NOT update its vhost signal. Public on-demand
// vhosts sit under near-constant internet scanning (masscan/shodan/bots)
// that trips block-mode rules; if that blocked traffic kept refreshing
// last_request_ts, last_request_age would never cross idle_threshold and
// auto-sleep would never fire for the vhost — defeating the feature for its
// primary deployment. The fix moves the Begin/End hook to AFTER the WAF-
// inspection block's 403 early-returns (see the placement comment in
// handler()); before the fix, this test failed because Begin ran before
// s.rules.MatchModes/writeWarning ever had a chance to return early.
func TestVhostSignalsExcludedForWAFBlock(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "backend ok")
	}))
	defer backend.Close()
	backendAddr := strings.TrimPrefix(backend.URL, "http://")

	rulesPath := buildSQLiRulesFile(t) // reuse helper from inspect_test.go
	vs := NewVhostSignals("")
	srv := &Server{
		routeLookup: func(host string) (string, int, bool) {
			h, p, err := splitHostPort(backendAddr)
			if err != nil {
				return "", 0, false
			}
			return h, p, true
		},
		rules:        LoadRules(rulesPath),
		ban:          NewBan(300*time.Second, 3),
		onDemand:     &OnDemand{entries: map[string]bool{"sleepy.example.com": true}},
		vhostSignals: vs,
	}

	handler := srv.handler()
	// UNION SELECT in the query → triggers the sqli rule (same payload as
	// TestHandlerWarningThenBan) against an on-demand vhost that DOES have a
	// live route — the WAF must still block it before ever reaching the
	// backend or touching the vhost signal.
	req := httptest.NewRequest(http.MethodGet,
		"http://sleepy.example.com/?q=1+union+select+1,2,3", nil)
	req.Host = "sleepy.example.com"
	req.RemoteAddr = "203.0.113.42:12345" // public IP (TEST-NET-3, non-RFC1918)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected the WAF to block this SQLi payload with 403, got %d", rec.Code)
	}
	if snap := vs.snapshot(); len(snap) != 0 {
		t.Fatalf("a WAF-blocked (warning/ban) request must not update vhost signals; got %+v", snap)
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
		rules:        rules,
		ban:          banState,
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
		{"GIT.GK2.SECUBOX.IN", true}, // case-insensitive
		{"10.100.0.1:9080", true},    // host:port exact match
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

// ─── escalate mode (Task 2) ─────────────────────────────────────────────────

// escalate observes the first N-1 probes: they PASS (like detect) and do NOT
// ban. Only the Nth probe from the same IP bans.
func TestEscalateObservesThenBansAtThreshold(t *testing.T) {
	rulesPath := writeRulesFile(t, `{"probes":{"name":"P","severity":"high","mode":"escalate",
		"patterns":[{"id":"f5-1","pattern":"/mgmt/tm/util/bash","desc":"F5 probe"}]}}`)

	backendHits := 0
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendHits++
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	s := newDetectTestServer(t, backend.URL, rulesPath)
	s.escalateBan = NewBan(time.Hour, 3) // threshold 3
	handler := s.handler()

	// Probes 1 and 2: observed, pass through, backend reached.
	for i := 1; i <= 2; i++ {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, detectTestReq("203.0.113.60"))
		if rec.Code == http.StatusForbidden {
			t.Fatalf("probe %d: got 403, escalate must observe (pass) before the threshold", i)
		}
	}
	if backendHits != 2 {
		t.Fatalf("expected 2 observed probes to reach the backend, got %d", backendHits)
	}
	if s.escalateBan.Count("203.0.113.60") < 2 {
		t.Fatal("escalate did not count the observed probes")
	}

	// Probe 3: threshold reached → ban (403).
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, detectTestReq("203.0.113.60"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("probe 3 (threshold): got %d, want 403 (ban)", rec.Code)
	}
}

// escalate must NOT touch the block counter (s.ban): the two signals are
// separate. Probing an escalate category must not advance s.ban.
func TestEscalateUsesItsOwnCounterNotTheBlockBan(t *testing.T) {
	rulesPath := writeRulesFile(t, `{"probes":{"name":"P","severity":"high","mode":"escalate",
		"patterns":[{"id":"f5-1","pattern":"/mgmt/tm/util/bash","desc":"F5 probe"}]}}`)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	s := newDetectTestServer(t, backend.URL, rulesPath)
	s.escalateBan = NewBan(time.Hour, 3)
	handler := s.handler()

	handler.ServeHTTP(httptest.NewRecorder(), detectTestReq("203.0.113.61"))
	handler.ServeHTTP(httptest.NewRecorder(), detectTestReq("203.0.113.61"))

	if s.ban != nil && s.ban.Count("203.0.113.61") != 0 {
		t.Fatalf("escalate advanced the block counter s.ban (%d); the counters must be separate",
			s.ban.Count("203.0.113.61"))
	}
	if s.escalateBan.Count("203.0.113.61") != 2 {
		t.Fatalf("escalate counter = %d, want 2", s.escalateBan.Count("203.0.113.61"))
	}
}

// With no escalate counter, an escalate category behaves like detect: it
// observes and never bans — never like block.
func TestEscalateWithNilCounterBehavesLikeDetect(t *testing.T) {
	rulesPath := writeRulesFile(t, `{"probes":{"name":"P","severity":"high","mode":"escalate",
		"patterns":[{"id":"f5-1","pattern":"/mgmt/tm/util/bash","desc":"F5 probe"}]}}`)
	reached := false
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	s := newDetectTestServer(t, backend.URL, rulesPath)
	s.escalateBan = nil // no counter
	handler := s.handler()

	for i := 0; i < 5; i++ {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, detectTestReq("203.0.113.62"))
		if rec.Code == http.StatusForbidden {
			t.Fatalf("nil escalate counter must observe (pass), never ban; got 403 on probe %d", i+1)
		}
	}
	if !reached {
		t.Fatal("nil escalate counter: request was swallowed")
	}
}

// The ban at threshold logs action="banned" (counted as a block); the observed
// probes log action="detect" (excluded from the block counters).
func TestEscalateLogsDetectWhileObservingAndBannedAtThreshold(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "threats.jsonl")
	rulesPath := writeRulesFile(t, `{"probes":{"name":"P","severity":"high","mode":"escalate",
		"patterns":[{"id":"f5-1","pattern":"/mgmt/tm/util/bash","desc":"F5 probe"}]}}`)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	s := newDetectTestServer(t, backend.URL, rulesPath)
	s.escalateBan = NewBan(time.Hour, 2) // threshold 2 for a short test
	s.threatLog = NewThreatLog(logPath)
	handler := s.handler()

	handler.ServeHTTP(httptest.NewRecorder(), detectTestReq("203.0.113.63")) // observe → "detect"
	handler.ServeHTTP(httptest.NewRecorder(), detectTestReq("203.0.113.63")) // threshold → "banned"

	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("threat log not written: %v", err)
	}
	if !strings.Contains(string(raw), `"detect"`) {
		t.Fatalf("observed probe must log action=detect, got: %s", raw)
	}
	if !strings.Contains(string(raw), `"banned"`) {
		t.Fatalf("threshold probe must log action=banned, got: %s", raw)
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

// A live edit to the rules file must take effect through ServeHTTP WITHOUT a
// restart — the whole point of wiring s.rules.Maybe() into the request path.
// Without it, an operator flipping a category to detect would see no change
// until the WAF that fronts every vhost is restarted.
func TestServerHotReloadsRuleModeWithoutRestart(t *testing.T) {
	// Start in block mode.
	rulesPath := writeRulesFile(t, `{"cve_2024":{"name":"CVE","severity":"critical","mode":"block",
		"patterns":[{"id":"cve-1","pattern":"/mgmt/tm/util/bash","desc":"F5 RCE"}]}}`)

	reached := false
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	s := newDetectTestServer(t, backend.URL, rulesPath)

	// First request: block mode → 403, backend not reached.
	handler := s.handler()
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, detectTestReq("203.0.113.50"))
	if rec1.Code != http.StatusForbidden {
		t.Fatalf("before reload (block): got %d, want 403", rec1.Code)
	}
	if reached {
		t.Fatal("before reload: backend reached in block mode")
	}

	// Operator flips the same category to detect on disk.
	if err := os.WriteFile(rulesPath, []byte(`{"_meta":{"version":"t"},"categories":{"cve_2024":{"name":"CVE","severity":"critical","mode":"detect","patterns":[{"id":"cve-1","pattern":"/mgmt/tm/util/bash","desc":"F5 RCE"}]}}}`), 0o644); err != nil {
		t.Fatalf("rewrite rules: %v", err)
	}
	// Bump mtime past filesystem granularity so the watcher notices.
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(rulesPath, future, future); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	// Second request through ServeHTTP (which now calls s.rules.Maybe()):
	// detect mode → passes through, backend reached, no restart.
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, detectTestReq("203.0.113.51"))
	if rec2.Code == http.StatusForbidden {
		t.Fatalf("after reload (detect): got 403; the live edit did not take effect without a restart")
	}
	if !reached {
		t.Fatal("after reload: backend not reached; detect mode did not apply")
	}
}
