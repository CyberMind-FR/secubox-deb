// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: media buffer janitor tests (#812)
//
// Pure standard library.
package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestJanitorEvictsExpiredKeepsMetatag proves the time-eviction half of the
// janitor: once now passes first_ts+retentionSecs, the session directory (the
// actual bytes) is removed but the metatag survives with expired:true and
// buffer_ref flipped to JSON null (never re-serialised as "").
func TestJanitorEvictsExpiredKeepsMetatag(t *testing.T) {
	root := t.TempDir()
	b := NewMediaBuffer(root, true, 512<<20)
	b.retentionSecs = 60

	w := b.Capture("mac1", "h", "https://h/v.mp4", "/v.mp4", "video/mp4", "down", 3)
	if w == nil {
		t.Fatal("Capture returned nil")
	}
	w.Write([]byte("abc"))
	w.Close(3)

	sess := lastJSONL(t, filepath.Join(root, "media-buffer.jsonl"))["session_id"].(string)
	if _, err := os.Stat(filepath.Join(root, sess)); err != nil {
		t.Fatalf("session dir should exist before sweep: %v", err)
	}

	// advance 61s past first_ts
	b.SweepOnce(b.nowFn() + 61)

	if _, err := os.Stat(filepath.Join(root, sess)); !os.IsNotExist(err) {
		t.Fatal("session dir should be evicted")
	}

	m := lastJSONL(t, filepath.Join(root, "media-buffer.jsonl"))
	if m["expired"] != true {
		t.Fatalf("metatag not flipped to expired: %v", m)
	}
	if _, present := m["buffer_ref"]; !present || m["buffer_ref"] != nil {
		t.Fatalf("buffer_ref should be present and JSON null, got: %v", m["buffer_ref"])
	}
	// Rest of the record must survive the flip intact.
	if m["mac_hash"] != "mac1" || m["host"] != "h" || m["direction"] != "down" {
		t.Fatalf("flip must preserve the rest of the record: %v", m)
	}
}

// TestJanitorNotYetExpiredSurvives proves SweepOnce leaves a fresh (not yet
// past retention) session alone.
func TestJanitorNotYetExpiredSurvives(t *testing.T) {
	root := t.TempDir()
	b := NewMediaBuffer(root, true, 512<<20)
	b.retentionSecs = 3600

	w := b.Capture("mac1", "h", "https://h/v.mp4", "/v.mp4", "video/mp4", "down", 3)
	w.Write([]byte("abc"))
	w.Close(3)
	sess := lastJSONL(t, filepath.Join(root, "media-buffer.jsonl"))["session_id"].(string)

	b.SweepOnce(b.nowFn())

	if _, err := os.Stat(filepath.Join(root, sess)); err != nil {
		t.Fatalf("fresh session should survive a sweep: %v", err)
	}
	m := lastJSONL(t, filepath.Join(root, "media-buffer.jsonl"))
	if m["expired"] == true {
		t.Fatal("fresh session must not be flipped expired")
	}
}

// sessionDirs returns the names of the immediate subdirectories of root
// (session dirs), excluding the metatag log file.
func sessionDirs(t *testing.T, root string) []string {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("ReadDir(%s): %v", root, err)
	}
	var dirs []string
	for _, e := range entries {
		if e.IsDir() {
			dirs = append(dirs, e.Name())
		}
	}
	return dirs
}

// TestJanitorLRUEvictsUnderCeiling proves the size-ceiling half of the
// janitor: with a tiny sizeCeilBytes, two live (not-yet-expired) captures are
// pared down oldest-first until the buffer root is back under the ceiling.
func TestJanitorLRUEvictsUnderCeiling(t *testing.T) {
	root := t.TempDir()
	b := NewMediaBuffer(root, true, 512<<20)
	b.retentionSecs = 3600 // nothing expires by time in this test
	b.sizeCeilBytes = 12   // small enough that one 10-byte object already fills it

	w1 := b.Capture("mac1", "h", "https://h/old.mp4", "/old.mp4", "video/mp4", "down", 10)
	w1.Write([]byte("0123456789")) // 10 bytes, oldest
	w1.Close(10)
	oldSess := lastJSONL(t, filepath.Join(root, "media-buffer.jsonl"))["session_id"].(string)

	time.Sleep(1100 * time.Millisecond) // ensure a distinct, later first_ts (unix-second resolution)

	w2 := b.Capture("mac2", "h", "https://h/new.mp4", "/new.mp4", "video/mp4", "down", 10)
	w2.Write([]byte("9876543210")) // another 10 bytes -> total 20 > ceiling 12
	w2.Close(10)
	newSess := lastJSONL(t, filepath.Join(root, "media-buffer.jsonl"))["session_id"].(string)

	if oldSess == newSess {
		t.Fatal("test setup: sessions must differ")
	}

	b.SweepOnce(b.nowFn())

	dirs := sessionDirs(t, root)
	foundOld, foundNew := false, false
	for _, d := range dirs {
		if d == oldSess {
			foundOld = true
		}
		if d == newSess {
			foundNew = true
		}
	}
	if foundOld {
		t.Fatal("oldest session should have been LRU-evicted first")
	}
	if !foundNew {
		t.Fatal("newest session should have survived (only the oldest needed eviction to clear the ceiling)")
	}

	// old session's metatag must be flipped even though it was time-fresh —
	// LRU eviction flips the same way as time-expiry.
	recs := allJSONLByID(t, filepath.Join(root, "media-buffer.jsonl"))
	oldRec := recs[findRecordSession(t, recs, oldSess)]
	if oldRec["expired"] != true || oldRec["buffer_ref"] != nil {
		t.Fatalf("LRU-evicted record must be flipped expired/null: %v", oldRec)
	}
	newRec := recs[findRecordSession(t, recs, newSess)]
	if newRec["expired"] == true {
		t.Fatalf("surviving record must not be flipped: %v", newRec)
	}
}

// TestJanitorIdempotentDoubleSweep proves running SweepOnce twice in a row
// (mirroring 4 concurrent worker processes each ticking their own janitor) is
// harmless: no error, no double-eviction weirdness, no duplicate-line
// corruption breaking the dedup-by-id read.
func TestJanitorIdempotentDoubleSweep(t *testing.T) {
	root := t.TempDir()
	b := NewMediaBuffer(root, true, 512<<20)
	b.retentionSecs = 60

	w := b.Capture("mac1", "h", "https://h/v.mp4", "/v.mp4", "video/mp4", "down", 3)
	w.Write([]byte("abc"))
	w.Close(3)

	now := b.nowFn() + 61
	b.SweepOnce(now)
	b.SweepOnce(now) // second sweep — must not panic, error, or resurrect anything

	m := lastJSONL(t, filepath.Join(root, "media-buffer.jsonl"))
	if m["expired"] != true || m["buffer_ref"] != nil {
		t.Fatalf("record must remain flipped after a duplicate sweep: %v", m)
	}
}

// TestRunJanitorTicksAndStops proves RunJanitor invokes SweepOnce on its own
// (via a short-period override reachable only through the exported behaviour:
// we drive it by constructing a buffer with a 60s retention and a nowFn wired
// far enough in the future that even the FIRST tick evicts) and that it exits
// promptly once its context is cancelled (no goroutine leak).
func TestRunJanitorTicksAndStops(t *testing.T) {
	root := t.TempDir()
	b := NewMediaBuffer(root, true, 512<<20)
	b.retentionSecs = 1
	// nowFn already far enough ahead that the very first tick's SweepOnce call
	// finds the object expired.
	future := time.Now().Unix() + 1000
	b.nowFn = func() int64 { return future }
	b.janitorTick = 20 * time.Millisecond // test-only fast tick (see mediabuffer_janitor.go)

	w := b.Capture("mac1", "h", "https://h/v.mp4", "/v.mp4", "video/mp4", "down", 3)
	w.Write([]byte("abc"))
	w.Close(3)
	sess := lastJSONL(t, filepath.Join(root, "media-buffer.jsonl"))["session_id"].(string)

	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() {
		b.RunJanitor(ctx)
		close(stopped)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(filepath.Join(root, sess)); os.IsNotExist(err) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := os.Stat(filepath.Join(root, sess)); !os.IsNotExist(err) {
		t.Fatal("RunJanitor never evicted the expired session")
	}

	cancel()
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("RunJanitor did not exit after ctx cancellation — goroutine leak")
	}
}

// allJSONLByID parses every line of path and returns the LAST record per id
// (dedup by id, last line wins — mirrors the Python reader's convention).
func allJSONLByID(t *testing.T, path string) map[string]map[string]interface{} {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	out := make(map[string]map[string]interface{})
	for _, line := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		if line == "" {
			continue
		}
		var m map[string]interface{}
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			continue
		}
		id, _ := m["id"].(string)
		if id == "" {
			continue
		}
		out[id] = m
	}
	return out
}

// findRecordSession returns the id whose LAST recorded session_id equals
// sess. Used because eviction rewrites buffer_ref to null, so we must match
// on the id captured from the ORIGINAL (pre-flip) line.
func findRecordSession(t *testing.T, recs map[string]map[string]interface{}, sess string) string {
	t.Helper()
	// The flipped record no longer carries session_id in a way we can match
	// (buffer_ref is null); recs is keyed by id but we only know sess. Re-scan
	// using the id embedded via a side channel is unnecessary here because
	// mediaBufferRecord.SessionID is still serialised on every line (flip only
	// nils buffer_ref, not session_id) — so match directly on session_id.
	for id, m := range recs {
		if sid, _ := m["session_id"].(string); sid == sess {
			return id
		}
	}
	t.Fatalf("no record found for session %s", sess)
	return ""
}
