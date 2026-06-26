// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: sbxwaf :: errpages_test — TDD for Task 7.1
// Tests for synthetic 502/503/504 themed error pages ported from secubox_waf.py.
package main

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestErrorPageSubstitutesHost verifies that errorPage(502, host) replaces
// the {host} placeholder in the template and does NOT leave it as a literal.
func TestErrorPageSubstitutesHost(t *testing.T) {
	const host = "app.example.com"
	body := errorPage(502, host)

	if len(body) == 0 {
		t.Fatal("errorPage(502, ...) returned empty body")
	}
	if !strings.Contains(string(body), host) {
		t.Fatalf("expected body to contain %q after substitution", host)
	}
	if strings.Contains(string(body), "{host}") {
		t.Fatal("body still contains literal {host} placeholder — substitution failed")
	}
	// 502 page has a machine-readable marker: the error-code div shows "502"
	if !strings.Contains(string(body), "502") {
		t.Fatal("expected body to contain the 502 error code marker")
	}
}

// TestErrorPageAllCodes checks that 502/503/504 each return a non-empty body
// with a code-specific marker (the error-code div content from the templates).
func TestErrorPageAllCodes(t *testing.T) {
	cases := []struct {
		code   int
		marker string // string that must appear in the page
	}{
		{502, "502"},
		{503, "503"},
		{504, "504"},
	}
	for _, tc := range cases {
		body := errorPage(tc.code, "test.host.local")
		if len(body) == 0 {
			t.Errorf("errorPage(%d) returned empty body", tc.code)
			continue
		}
		if !strings.Contains(string(body), tc.marker) {
			t.Errorf("errorPage(%d): body does not contain marker %q", tc.code, tc.marker)
		}
	}
}

// TestErrorPageUnknownCodeFallback checks that an unknown code returns a sane
// (non-empty) body — must not panic or return nil.
func TestErrorPageUnknownCodeFallback(t *testing.T) {
	body := errorPage(599, "fallback.example.com")
	if len(body) == 0 {
		t.Fatal("errorPage(599) returned empty body — expected a non-empty fallback")
	}
}

// TestHandlerServesThemed502OnDeadBackend routes a request to a port where
// nothing is listening (connection refused) and asserts:
//   - status 502
//   - X-SecuBox-WAF: error-502
//   - body contains the themed 502 marker ("502")
func TestHandlerServesThemed502OnDeadBackend(t *testing.T) {
	// Find an unused local port (bind then close immediately — race is
	// acceptable here since the test is the only user and the port is ephemeral).
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not bind ephemeral port: %v", err)
	}
	deadAddr := l.Addr().String()
	l.Close() // immediately close — the port is now "dead" (refused)

	deadHost, deadPortStr, _ := net.SplitHostPort(deadAddr)
	var deadPort int
	if _, err := io.Discard.Write(nil); err == nil { // no-op; parse port below
	}
	if _, err := strings.NewReader(deadPortStr).Read(nil); err == nil {
	}
	// Parse port via strconv-style logic — use net.LookupPort is overkill; cast.
	for _, b := range []byte(deadPortStr) {
		deadPort = deadPort*10 + int(b-'0')
	}

	srv := &Server{
		routeLookup: func(host string) (string, int, bool) {
			if host == "dead.example.com" {
				return deadHost, deadPort, true
			}
			return "", 0, false
		},
	}

	handler := srv.handler()
	req := httptest.NewRequest(http.MethodGet, "http://dead.example.com/", nil)
	req.Host = "dead.example.com"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	res := rec.Result()
	if res.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", res.StatusCode)
	}

	wafHdr := res.Header.Get("X-SecuBox-WAF")
	if wafHdr != "error-502" {
		t.Fatalf("expected X-SecuBox-WAF: error-502, got %q", wafHdr)
	}

	body, _ := io.ReadAll(res.Body)
	if !strings.Contains(string(body), "502") {
		t.Fatalf("expected themed 502 body, got: %q", string(body)[:min(200, len(body))])
	}
	// Must NOT contain the raw placeholder.
	if strings.Contains(string(body), "{host}") {
		t.Fatal("response body still contains {host} literal — substitution failed")
	}
}

// TestHandlerServes504OnUpstreamTimeout routes to a backend that sleeps past a
// short per-request upstream timeout and asserts 504 + X-SecuBox-WAF: error-504.
func TestHandlerServes504OnUpstreamTimeout(t *testing.T) {
	// Backend that sleeps 2s — our timeout will be 50ms so it times out.
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer slow.Close()

	backendAddr := strings.TrimPrefix(slow.URL, "http://")
	bHost, bPort, err := splitHostPort(backendAddr)
	if err != nil {
		t.Fatalf("splitHostPort: %v", err)
	}

	srv := &Server{
		upstreamTimeout: 50 * time.Millisecond, // very short → guaranteed timeout
		routeLookup: func(host string) (string, int, bool) {
			if host == "slow.example.com" {
				return bHost, bPort, true
			}
			return "", 0, false
		},
	}

	handler := srv.handler()
	req := httptest.NewRequest(http.MethodGet, "http://slow.example.com/", nil)
	req.Host = "slow.example.com"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	res := rec.Result()
	if res.StatusCode != http.StatusGatewayTimeout {
		t.Fatalf("expected 504, got %d", res.StatusCode)
	}

	wafHdr := res.Header.Get("X-SecuBox-WAF")
	if wafHdr != "error-504" {
		t.Fatalf("expected X-SecuBox-WAF: error-504, got %q", wafHdr)
	}

	body, _ := io.ReadAll(res.Body)
	if !strings.Contains(string(body), "504") {
		t.Fatalf("expected themed 504 body, got: %q", string(body)[:min(200, len(body))])
	}
}

// TestErrorPageEscapesHost verifies that a Host value containing HTML-special
// characters is escaped before being inserted into the page, preventing a
// reflected XSS via an attacker-controlled Host header.
//
// Note: the 502 template itself contains a legitimate <script> block for the
// retry countdown timer — that is expected.  What must NOT appear is the
// attacker-injected payload "><script>alert(1)</script> reflected verbatim.
// html.EscapeString escapes <, >, &, " and ' — plain text like "alert(1)"
// within the already-escaped tags is safe and will remain in the output.
func TestErrorPageEscapesHost(t *testing.T) {
	maliciousHost := "\"><script>alert(1)</script>"
	body := string(errorPage(502, maliciousHost))

	// The raw, unescaped payload must not appear verbatim.
	// If it does, the host value was reflected unescaped — XSS.
	if strings.Contains(body, maliciousHost) {
		t.Fatal("body contains the raw malicious Host value unescaped — reflected XSS vulnerability")
	}

	// The injected closing quote + opening angle must not appear — this is
	// the breakout vector that allows injecting a new tag context.
	if strings.Contains(body, "\"><script>") {
		t.Fatal(`body contains unescaped "><script> from Host header — tag-injection XSS vulnerability`)
	}

	// Must contain the escaped form so the host value is still rendered safely.
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Fatal("body does not contain escaped &lt;script&gt; — escaping may be missing or incorrect")
	}

	// Must not contain the bare placeholder.
	if strings.Contains(body, "{host}") {
		t.Fatal("body still contains literal {host} placeholder — substitution failed")
	}
}

// TestErrorPageSubstitutesHostNormal confirms that a well-formed host (no
// special chars) is preserved unchanged after escaping — escaping must not
// mangle safe values.
func TestErrorPageSubstitutesHostNormal(t *testing.T) {
	const host = "app.example.com"
	body := string(errorPage(502, host))

	if !strings.Contains(body, host) {
		t.Fatalf("expected body to contain %q after substitution, but it was absent", host)
	}
	if strings.Contains(body, "{host}") {
		t.Fatal("body still contains literal {host} placeholder — substitution failed")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
