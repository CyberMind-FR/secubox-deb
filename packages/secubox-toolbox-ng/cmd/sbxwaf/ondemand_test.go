// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: sbxwaf — on-demand-vhosts.json loader tests
package main

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

// writeOnDemand writes a JSON array of vhost strings to a temp file and
// returns the path.
func writeOnDemand(t *testing.T, hosts []string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "ondemand*.json")
	if err != nil {
		t.Fatalf("create temp: %v", err)
	}
	if err := json.NewEncoder(f).Encode(hosts); err != nil {
		t.Fatalf("encode on-demand vhosts: %v", err)
	}
	f.Close()
	return f.Name()
}

// TestOnDemandContains verifies the basic load + Contains contract: exact
// match, case-insensitivity, and port-stripping (mirrors Routes.Lookup).
func TestOnDemandContains(t *testing.T) {
	path := writeOnDemand(t, []string{"sleepy.example.com", "Dashboard.Example.Org"})

	o := LoadOnDemand(path)

	if !o.Contains("sleepy.example.com") {
		t.Fatal("expected sleepy.example.com to be on-demand")
	}
	if !o.Contains("SLEEPY.EXAMPLE.COM") {
		t.Fatal("expected case-insensitive match")
	}
	if !o.Contains("dashboard.example.org") {
		t.Fatal("expected lowercased match against a mixed-case stored entry")
	}
	if !o.Contains("sleepy.example.com:8080") {
		t.Fatal("expected port-stripped match")
	}
	if o.Contains("unknown.example.com") {
		t.Fatal("unknown.example.com should not be on-demand")
	}
}

// TestOnDemandHotReload verifies that an mtime change triggers a set swap,
// mirroring TestRoutesHotReload.
func TestOnDemandHotReload(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/on-demand-vhosts.json"

	data, _ := json.Marshal([]string{"a.example.com"})
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write initial: %v", err)
	}

	o := LoadOnDemand(path)
	if !o.Contains("a.example.com") {
		t.Fatal("initial: a.example.com should be present")
	}
	if o.Contains("b.example.com") {
		t.Fatal("initial: b.example.com should be absent")
	}

	data, _ = json.Marshal([]string{"a.example.com", "b.example.com"})
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write updated: %v", err)
	}
	// Bump mtime explicitly so the test is not timing-sensitive (matches
	// TestRoutesHotReload).
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatalf("chtimes: %v", err)
	}
	o.Maybe()

	if !o.Contains("b.example.com") {
		t.Fatal("after reload: b.example.com should be present")
	}
	if !o.Contains("a.example.com") {
		t.Fatal("after reload: a.example.com should still be present")
	}
}

// TestOnDemandMissingFile verifies best-effort semantics: a missing file
// yields an empty (never-matching) set instead of panicking.
func TestOnDemandMissingFile(t *testing.T) {
	o := LoadOnDemand("/nonexistent/on-demand-vhosts.json")
	if o.Contains("anything.example.com") {
		t.Fatal("missing file should yield an empty set")
	}
}
