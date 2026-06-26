// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: sbxwaf :: threatlog_test — TDD for Task 3.2
//
// Tests:
//   - TestThreatLogAppendsJSON: two records produce 2 parseable JSON lines with
//     correct fields and action values.
//   - TestHandlerWarningThenBan: 3 identical attacking requests from the same
//     public IP: first two return 403 with WARNING marker, third returns 403 with
//     BAN marker; threat log accumulates 3 records (warning, warning, banned).
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ─── ThreatLog unit tests ────────────────────────────────────────────────────

// TestThreatLogAppendsJSON verifies that Record appends one JSON line per call,
// that each line is independently parseable, and that key fields match.
func TestThreatLogAppendsJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "waf-threats.log")

	tl := NewThreatLog(path)

	rec1 := ThreatRecord{
		ClientIP: "1.2.3.4",
		Host:     "example.com",
		Method:   "GET",
		Path:     "/foo",
		Category: "sqli",
		Severity: "high",
		RuleID:   "sqli1",
		Action:   "warning",
		UA:       "testclient/1.0",
	}
	rec2 := ThreatRecord{
		ClientIP: "1.2.3.4",
		Host:     "example.com",
		Method:   "GET",
		Path:     "/foo",
		Category: "sqli",
		Severity: "high",
		RuleID:   "sqli1",
		Action:   "banned",
		UA:       "testclient/1.0",
	}

	tl.Record(rec1)
	tl.Record(rec2)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read threat log: %v", err)
	}

	lines := splitNonEmpty(string(data))
	if len(lines) != 2 {
		t.Fatalf("expected 2 JSON lines, got %d:\n%s", len(lines), string(data))
	}

	// Parse and verify each line.
	wantActions := []string{"warning", "banned"}
	for i, line := range lines {
		var obj map[string]string
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			t.Fatalf("line %d not valid JSON: %v\nline: %q", i+1, err, line)
		}
		if obj["client_ip"] != "1.2.3.4" {
			t.Errorf("line %d: client_ip want 1.2.3.4, got %q", i+1, obj["client_ip"])
		}
		if obj["category"] != "sqli" {
			t.Errorf("line %d: category want sqli, got %q", i+1, obj["category"])
		}
		if obj["action"] != wantActions[i] {
			t.Errorf("line %d: action want %q, got %q", i+1, wantActions[i], obj["action"])
		}
		if obj["timestamp"] == "" {
			t.Errorf("line %d: timestamp must not be empty", i+1)
		}
		if obj["host"] != "example.com" {
			t.Errorf("line %d: host want example.com, got %q", i+1, obj["host"])
		}
		if obj["method"] != "GET" {
			t.Errorf("line %d: method want GET, got %q", i+1, obj["method"])
		}
		if obj["path"] != "/foo" {
			t.Errorf("line %d: path want /foo, got %q", i+1, obj["path"])
		}
		if obj["severity"] != "high" {
			t.Errorf("line %d: severity want high, got %q", i+1, obj["severity"])
		}
	}
}

// TestThreatLogBestEffortOnBadPath verifies that Record does NOT panic when the
// log directory doesn't exist — it silently logs to stderr and continues.
func TestThreatLogBestEffortOnBadPath(t *testing.T) {
	tl := NewThreatLog("/nonexistent-dir/waf-threats.log")
	// Must not panic.
	tl.Record(ThreatRecord{
		ClientIP: "1.2.3.4",
		Action:   "warning",
	})
}

// ─── Handler integration: WARNING then BAN ───────────────────────────────────

// TestHandlerWarningThenBan drives a Server with WAF rules and ban wired in.
// Same public IP sends the same attack 3 times (threshold=3):
//   - hits 1 and 2: HTTP 403, body contains "<!-- sbxwaf-warning -->" marker
//   - hit 3: HTTP 403, body contains "<!-- sbxwaf-banned -->" marker
//
// The threat log must accumulate 3 records: warning, warning, banned.
func TestHandlerWarningThenBan(t *testing.T) {
	// Stub backend (should never be reached when WAF fires).
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("backend ok"))
	}))
	defer backend.Close()

	rulesPath := buildSQLiRulesFile(t) // reuse helper from inspect_test.go
	dir := t.TempDir()
	logPath := filepath.Join(dir, "waf-threats.log")

	backendAddr := strings.TrimPrefix(backend.URL, "http://")

	srv := &Server{
		routeLookup: func(host string) (ip string, port int, ok bool) {
			h, p, err := splitHostPort(backendAddr)
			if err != nil {
				return "", 0, false
			}
			return h, p, true
		},
		rules:     LoadRules(rulesPath),
		ban:       NewBan(300*time.Second, 3),
		threatLog: NewThreatLog(logPath),
	}

	handler := srv.handler()

	// Attack request helper — UNION SELECT in query → triggers sqli rule.
	makeReq := func() *http.Request {
		req := httptest.NewRequest(http.MethodGet,
			"http://app.example.com/?q=1+union+select+1,2,3", nil)
		req.Host = "app.example.com"
		req.RemoteAddr = "203.0.113.42:12345" // public IP (TEST-NET-3, non-RFC1918)
		return req
	}

	// Hit 1 → WARNING
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, makeReq())
	if rec1.Code != http.StatusForbidden {
		t.Fatalf("hit 1: expected 403, got %d", rec1.Code)
	}
	body1 := rec1.Body.String()
	if !strings.Contains(body1, "<!-- sbxwaf-warning -->") {
		t.Errorf("hit 1: expected warning marker in body, got:\n%s", body1)
	}
	if strings.Contains(body1, "<!-- sbxwaf-banned -->") {
		t.Errorf("hit 1: must NOT contain banned marker")
	}

	// Hit 2 → WARNING
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, makeReq())
	if rec2.Code != http.StatusForbidden {
		t.Fatalf("hit 2: expected 403, got %d", rec2.Code)
	}
	body2 := rec2.Body.String()
	if !strings.Contains(body2, "<!-- sbxwaf-warning -->") {
		t.Errorf("hit 2: expected warning marker in body, got:\n%s", body2)
	}

	// Hit 3 → BAN
	rec3 := httptest.NewRecorder()
	handler.ServeHTTP(rec3, makeReq())
	if rec3.Code != http.StatusForbidden {
		t.Fatalf("hit 3: expected 403, got %d", rec3.Code)
	}
	body3 := rec3.Body.String()
	if !strings.Contains(body3, "<!-- sbxwaf-banned -->") {
		t.Errorf("hit 3: expected banned marker in body, got:\n%s", body3)
	}
	if strings.Contains(body3, "<!-- sbxwaf-warning -->") {
		t.Errorf("hit 3: must NOT contain warning marker")
	}

	// Verify threat log: 3 records with correct actions.
	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read threat log: %v", err)
	}
	logLines := splitNonEmpty(string(logData))
	if len(logLines) != 3 {
		t.Fatalf("expected 3 threat log entries, got %d:\n%s", len(logLines), string(logData))
	}

	wantActions := []string{"warning", "warning", "banned"}
	for i, line := range logLines {
		var obj map[string]string
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			t.Fatalf("log line %d not valid JSON: %v", i+1, err)
		}
		if obj["action"] != wantActions[i] {
			t.Errorf("log line %d: action want %q, got %q", i+1, wantActions[i], obj["action"])
		}
		if obj["client_ip"] != "203.0.113.42" {
			t.Errorf("log line %d: client_ip want 203.0.113.42, got %q", i+1, obj["client_ip"])
		}
	}
}

// ─── helpers ─────────────────────────────────────────────────────────────────

// splitNonEmpty splits s by newlines and returns only non-empty lines.
func splitNonEmpty(s string) []string {
	sc := bufio.NewScanner(bytes.NewBufferString(s))
	var out []string
	for sc.Scan() {
		if line := sc.Text(); line != "" {
			out = append(out, line)
		}
	}
	return out
}
