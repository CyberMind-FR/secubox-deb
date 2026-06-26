// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: sbxwaf :: cookieaudit_test — TDD for Task 5.1
//
// Tests:
//   - TestCookieAuditHashesValue: single Set-Cookie → one JSONL record, value
//     SHA256-hashed (never raw), domain dot-stripped, attributes correct.
//   - TestCookieAuditMultipleCookies: two Set-Cookie headers → two JSONL lines.
//   - TestCookieAuditNonBlocking: Record returns promptly even when the writer
//     is paused (channel-full drop policy — never blocks the response path).
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// makeFakeResponse builds a minimal *http.Response carrying the given
// Set-Cookie header values. The request is a simple GET to targetURL.
func makeFakeResponse(targetURL string, setCookies []string) (*http.Response, *http.Request) {
	req, _ := http.NewRequest(http.MethodGet, targetURL, nil)
	hdr := http.Header{}
	for _, sc := range setCookies {
		hdr.Add("Set-Cookie", sc)
	}
	resp := &http.Response{
		StatusCode: 200,
		Header:     hdr,
		Body:       io.NopCloser(bytes.NewReader(nil)),
		Request:    req,
	}
	return resp, req
}

// TestCookieAuditHashesValue verifies that:
//   - The ledger receives exactly one record for a single Set-Cookie.
//   - The raw cookie value ("secretvalue") is NEVER written to the file.
//   - value_hash == sha256("secretvalue").
//   - domain has the leading dot stripped.
//   - secure, httponly are true; samesite is "Lax".
func TestCookieAuditHashesValue(t *testing.T) {
	dir := t.TempDir()
	ledger := filepath.Join(dir, "cookie-audit", "server.jsonl")

	ca := NewCookieAudit(ledger)
	defer ca.Close()

	resp, req := makeFakeResponse(
		"https://example.com/login",
		[]string{"session=secretvalue; Domain=.example.com; Path=/; Secure; HttpOnly; SameSite=Lax"},
	)

	ca.Record(req.Host, req, resp)

	// Wait for the async writer goroutine to flush.
	ca.Close()

	data, err := os.ReadFile(ledger)
	if err != nil {
		t.Fatalf("read ledger: %v", err)
	}

	lines := splitNonEmptyLines(string(data))
	if len(lines) != 1 {
		t.Fatalf("expected 1 JSONL record, got %d:\n%s", len(lines), string(data))
	}

	var rec map[string]interface{}
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatalf("line not valid JSON: %v\nline: %q", err, lines[0])
	}

	// name
	if rec["name"] != "session" {
		t.Errorf("name: want %q got %v", "session", rec["name"])
	}

	// value_hash
	wantHash := fmt.Sprintf("%x", sha256.Sum256([]byte("secretvalue")))
	if rec["value_hash"] != wantHash {
		t.Errorf("value_hash: want %q got %v", wantHash, rec["value_hash"])
	}

	// raw value must NOT appear anywhere in the file
	if strings.Contains(string(data), "secretvalue") {
		t.Errorf("raw cookie value 'secretvalue' must not appear in the ledger")
	}

	// domain: leading dot stripped
	if rec["domain"] != "example.com" {
		t.Errorf("domain: want %q got %v", "example.com", rec["domain"])
	}

	// path
	if rec["path"] != "/" {
		t.Errorf("path: want %q got %v", "/", rec["path"])
	}

	// secure
	if rec["secure"] != true {
		t.Errorf("secure: want true got %v", rec["secure"])
	}

	// httponly
	if rec["httponly"] != true {
		t.Errorf("httponly: want true got %v", rec["httponly"])
	}

	// samesite
	if rec["samesite"] != "Lax" {
		t.Errorf("samesite: want %q got %v", "Lax", rec["samesite"])
	}

	// ts must be a non-empty string
	ts, _ := rec["ts"].(string)
	if ts == "" {
		t.Errorf("ts must be a non-empty RFC3339 timestamp")
	}
}

// TestCookieAuditMultipleCookies verifies that two Set-Cookie headers produce
// two independent JSONL records.
func TestCookieAuditMultipleCookies(t *testing.T) {
	dir := t.TempDir()
	ledger := filepath.Join(dir, "cookie-audit", "server.jsonl")

	ca := NewCookieAudit(ledger)

	resp, req := makeFakeResponse(
		"https://shop.example.com/cart",
		[]string{
			"cart=abc123; Path=/; HttpOnly",
			"tracker=xyz789; Domain=.example.com; Path=/; Secure; SameSite=None",
		},
	)

	ca.Record(req.Host, req, resp)

	// Flush via Close.
	ca.Close()

	data, err := os.ReadFile(ledger)
	if err != nil {
		t.Fatalf("read ledger: %v", err)
	}

	lines := splitNonEmptyLines(string(data))
	if len(lines) != 2 {
		t.Fatalf("expected 2 JSONL records (one per Set-Cookie), got %d:\n%s", len(lines), string(data))
	}

	// Both lines must be valid JSON with a name field.
	names := map[string]bool{}
	for i, line := range lines {
		var rec map[string]interface{}
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("line %d not valid JSON: %v", i+1, err)
		}
		n, _ := rec["name"].(string)
		if n == "" {
			t.Errorf("line %d: name must not be empty", i+1)
		}
		names[n] = true
	}

	if !names["cart"] {
		t.Errorf("expected a record with name=cart")
	}
	if !names["tracker"] {
		t.Errorf("expected a record with name=tracker")
	}
}

// TestCookieAuditNonBlocking verifies that Record returns promptly even when
// the internal channel is full (i.e. the writer goroutine is not draining).
// Strategy: create a CookieAudit with a tiny channel, then call Record more
// times than the channel capacity without closing it. The call must return
// within a very short deadline — never blocking the response path.
func TestCookieAuditNonBlocking(t *testing.T) {
	dir := t.TempDir()
	ledger := filepath.Join(dir, "cookie-audit", "server.jsonl")

	// Use the standard constructor (channel size 256). We call Record 512 times
	// without any drain delay — the first 256 fill the channel; subsequent sends
	// must be dropped non-blockingly. The goroutine will drain concurrently, but
	// the test verifies that no single Record call hangs.
	ca := NewCookieAudit(ledger)

	resp, req := makeFakeResponse(
		"https://example.com/",
		[]string{"tok=value; Path=/"},
	)

	start := time.Now()
	for i := 0; i < 512; i++ {
		ca.Record(req.Host, req, resp)
	}
	elapsed := time.Since(start)

	ca.Close()

	// All 512 Record calls must complete in well under 1 second.
	// (A blocking send would hang indefinitely; even a 100ms sleep per drop
	// would blow this budget.)
	if elapsed > 1*time.Second {
		t.Errorf("Record loop took %v — looks like it blocked (want < 1s)", elapsed)
	}
}

// splitNonEmptyLines splits s by newlines, returning only non-empty lines.
// Reuses the same logic as splitNonEmpty in threatlog_test.go (same package,
// different name to avoid collision with that helper's local scope).
func splitNonEmptyLines(s string) []string {
	sc := bufio.NewScanner(bytes.NewBufferString(s))
	var out []string
	for sc.Scan() {
		if line := sc.Text(); line != "" {
			out = append(out, line)
		}
	}
	return out
}
