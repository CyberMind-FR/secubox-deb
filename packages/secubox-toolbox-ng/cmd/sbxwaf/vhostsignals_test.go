// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: sbxwaf — per-vhost signal emitter tests (#896)
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestVhostSignalsBeginEnd verifies the core Begin/End contract: Begin sets a
// non-zero last-seen timestamp and bumps the in-flight counter; End
// decrements it and prunes the map entry once it reaches zero, while
// preserving lastSeen (the idle-age math on the profiles side needs the
// timestamp of the last request to survive long after active_conns drops
// back to zero).
func TestVhostSignalsBeginEnd(t *testing.T) {
	v := NewVhostSignals("") // no on-disk flush needed for this test

	v.Begin("sleepy.example.com")
	v.mu.Lock()
	ts := v.lastSeen["sleepy.example.com"]
	active := v.active["sleepy.example.com"]
	v.mu.Unlock()
	if ts == 0 {
		t.Fatal("expected Begin to set a non-zero last-seen timestamp")
	}
	if active != 1 {
		t.Fatalf("expected active=1 after one Begin, got %d", active)
	}

	// A second concurrent request to the same vhost.
	v.Begin("sleepy.example.com")
	v.mu.Lock()
	active = v.active["sleepy.example.com"]
	v.mu.Unlock()
	if active != 2 {
		t.Fatalf("expected active=2 after two Begins, got %d", active)
	}

	v.End("sleepy.example.com")
	v.mu.Lock()
	active = v.active["sleepy.example.com"]
	v.mu.Unlock()
	if active != 1 {
		t.Fatalf("expected active=1 after one End, got %d", active)
	}

	v.End("sleepy.example.com")
	v.mu.Lock()
	_, stillPresent := v.active["sleepy.example.com"]
	lastSeenAfter := v.lastSeen["sleepy.example.com"]
	v.mu.Unlock()
	if stillPresent {
		t.Fatal("expected the active-conns entry to be pruned once the count reaches 0")
	}
	if lastSeenAfter != ts {
		t.Fatal("expected lastSeen to be preserved after active count drops to 0 (idle-age math needs it)")
	}
}

// TestVhostSignalsEndWithoutBeginNeverGoesPositive guards against a
// mismatched End (defer fired without a matching Begin, or double-fired)
// making active_conns look positive forever — that would permanently block
// auto-sleep for the vhost.
func TestVhostSignalsEndWithoutBeginNeverGoesPositive(t *testing.T) {
	v := NewVhostSignals("")
	v.End("never-begun.example.com")
	v.mu.Lock()
	_, present := v.active["never-begun.example.com"]
	v.mu.Unlock()
	if present {
		t.Fatal("an End with no matching Begin must not leave a positive/zero active entry behind")
	}
}

// TestVhostSignalsFlushWritesJSON verifies the on-disk snapshot shape the
// profiles-side reader (api/sleeper_daemon.py::_signal_reader) consumes:
// {"<vhost>": {"last_request_ts": <unix secs>, "active_conns": <n>}}.
func TestVhostSignalsFlushWritesJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vhost-signals.json")
	v := NewVhostSignals(path)

	v.Begin("sleepy.example.com")
	v.writeSnapshot()

	buf, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read snapshot: %v", err)
	}
	var got map[string]vhostSignalEntry
	if err := json.Unmarshal(buf, &got); err != nil {
		t.Fatalf("unmarshal snapshot: %v", err)
	}
	entry, ok := got["sleepy.example.com"]
	if !ok {
		t.Fatal("expected sleepy.example.com in the snapshot")
	}
	if entry.ActiveConns != 1 {
		t.Fatalf("expected active_conns=1, got %d", entry.ActiveConns)
	}
	if entry.LastRequestTS == 0 {
		t.Fatal("expected a non-zero last_request_ts")
	}
}

// TestVhostSignalsFlushReflectsEndedRequest verifies that once a request
// completes (End called), the NEXT flush reports active_conns=0 while still
// keeping the vhost's last_request_ts — exactly what should_sleep() needs to
// decide "idle" (active_conns == 0 AND last_request_age >= threshold).
func TestVhostSignalsFlushReflectsEndedRequest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vhost-signals.json")
	v := NewVhostSignals(path)

	v.Begin("sleepy.example.com")
	v.End("sleepy.example.com")
	v.writeSnapshot()

	buf, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read snapshot: %v", err)
	}
	var got map[string]vhostSignalEntry
	if err := json.Unmarshal(buf, &got); err != nil {
		t.Fatalf("unmarshal snapshot: %v", err)
	}
	entry, ok := got["sleepy.example.com"]
	if !ok {
		t.Fatal("expected sleepy.example.com to remain in the snapshot after End")
	}
	if entry.ActiveConns != 0 {
		t.Fatalf("expected active_conns=0 after End, got %d", entry.ActiveConns)
	}
	if entry.LastRequestTS == 0 {
		t.Fatal("expected last_request_ts to survive after active_conns drops to 0")
	}
}

// TestVhostSignalsEmptyPathDisablesFlush verifies path=="" (the convention
// used elsewhere — NewVisitStats("")) never attempts a disk write.
func TestVhostSignalsEmptyPathDisablesFlush(t *testing.T) {
	v := NewVhostSignals("")
	v.Begin("sleepy.example.com")
	v.writeSnapshot() // must be a safe no-op, not a panic on an empty path
}
