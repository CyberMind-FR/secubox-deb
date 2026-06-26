// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: sbxwaf — routes loader tests
package main

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

// writeRoutes writes a haproxy-routes.json content to a temp file and returns
// the path.  The caller is responsible for os.Remove.
func writeRoutes(t *testing.T, routes map[string]any) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "routes*.json")
	if err != nil {
		t.Fatalf("create temp: %v", err)
	}
	if err := json.NewEncoder(f).Encode(routes); err != nil {
		t.Fatalf("encode routes: %v", err)
	}
	f.Close()
	return f.Name()
}

// TestRoutesLookup verifies the basic load + lookup contract.
func TestRoutesLookup(t *testing.T) {
	path := writeRoutes(t, map[string]any{
		"gitea.example.com":   []any{"127.0.0.1", 3000},
		"nextcloud.local":     []any{"10.0.0.1", 443},
		"malformed.example":   "not-an-array",              // skipped
		"short.example":       []any{"127.0.0.1"},          // skipped (only 1 element)
		"badport.example":     []any{"127.0.0.1", "notint"}, // skipped
	})

	r := LoadRoutes(path)

	// Known host → correct backend.
	ip, port, ok := r.Lookup("gitea.example.com")
	if !ok || ip != "127.0.0.1" || port != 3000 {
		t.Fatalf("Lookup(gitea.example.com) = (%q, %d, %v); want (127.0.0.1, 3000, true)", ip, port, ok)
	}

	// Second known host.
	ip, port, ok = r.Lookup("nextcloud.local")
	if !ok || ip != "10.0.0.1" || port != 443 {
		t.Fatalf("Lookup(nextcloud.local) = (%q, %d, %v); want (10.0.0.1, 443, true)", ip, port, ok)
	}

	// Unknown host → ok=false.
	_, _, ok = r.Lookup("unknown.example.com")
	if ok {
		t.Fatal("Lookup(unknown.example.com) expected ok=false, got true")
	}

	// Malformed entries must not panic and must be absent.
	_, _, ok = r.Lookup("malformed.example")
	if ok {
		t.Fatal("Lookup(malformed.example) expected ok=false (skipped), got true")
	}
	_, _, ok = r.Lookup("short.example")
	if ok {
		t.Fatal("Lookup(short.example) expected ok=false (only 1 element), got true")
	}
	_, _, ok = r.Lookup("badport.example")
	if ok {
		t.Fatal("Lookup(badport.example) expected ok=false (bad port), got true")
	}
}

// TestRoutesLookupCaseAndPort verifies that host lookup lowercases + strips port.
func TestRoutesLookupCaseAndPort(t *testing.T) {
	path := writeRoutes(t, map[string]any{
		"gitea.example.com": []any{"127.0.0.1", 3000},
	})

	r := LoadRoutes(path)

	// Upper-case variant.
	_, _, ok := r.Lookup("GITEA.EXAMPLE.COM")
	if !ok {
		t.Fatal("Lookup(GITEA.EXAMPLE.COM) should match (case-insensitive)")
	}

	// Host:port variant — strip port before lookup.
	_, _, ok = r.Lookup("gitea.example.com:8080")
	if !ok {
		t.Fatal("Lookup(gitea.example.com:8080) should match after stripping port")
	}
}

// TestRoutesHotReload verifies that an mtime change triggers a map swap.
func TestRoutesHotReload(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/routes.json"

	// Initial content: only gitea.
	initial := map[string]any{
		"gitea.example.com": []any{"127.0.0.1", 3000},
	}
	data, _ := json.Marshal(initial)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write initial: %v", err)
	}

	r := LoadRoutes(path)

	_, _, ok := r.Lookup("gitea.example.com")
	if !ok {
		t.Fatal("initial: gitea should be present")
	}
	_, _, ok = r.Lookup("new.example.com")
	if ok {
		t.Fatal("initial: new.example.com should be absent")
	}

	// Rewrite file with new content.
	updated := map[string]any{
		"gitea.example.com": []any{"127.0.0.1", 3000},
		"new.example.com":   []any{"192.168.0.1", 8080},
	}
	data, _ = json.Marshal(updated)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write updated: %v", err)
	}

	// Bump mtime explicitly so the test is not timing-sensitive (filesystem
	// granularity can be 1s on some systems).
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	// Trigger reload — the watcher has throttle=0 so Maybe() fires immediately.
	r.Maybe()

	// New route must be visible.
	ip, port, ok := r.Lookup("new.example.com")
	if !ok || ip != "192.168.0.1" || port != 8080 {
		t.Fatalf("after reload: Lookup(new.example.com) = (%q, %d, %v); want (192.168.0.1, 8080, true)", ip, port, ok)
	}

	// Old route still present.
	_, _, ok = r.Lookup("gitea.example.com")
	if !ok {
		t.Fatal("after reload: gitea.example.com should still be present")
	}
}
