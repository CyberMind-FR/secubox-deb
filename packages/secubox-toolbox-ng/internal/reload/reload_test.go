// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: internal/reload — mtime hot-reload tests
package reload

import (
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// writeFile writes content to path (used in tests).
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// bumpMtime forces the file's mtime forward by d, making coarse-granularity
// filesystems and sub-second test runs reliable.
func bumpMtime(t *testing.T, path string, d time.Duration) {
	t.Helper()
	ft := time.Now().Add(d)
	if err := os.Chtimes(path, ft, ft); err != nil {
		t.Fatalf("chtimes %s: %v", path, err)
	}
}

// TestWatcherBasic: a Target whose Apply stores into a captured var; Maybe();
// assert the var holds the loaded set; mutate the file + bump mtime; Maybe()
// again; assert the var updated.
func TestWatcherBasic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "list.txt")
	writeFile(t, path, "alpha\nbeta\n")

	var mu sync.Mutex
	var captured map[string]bool

	tgt := Target{
		Path:      path,
		LastMtime: 0,
		Load: func(p string) any {
			return LoadLines(p, true)
		},
		Apply: func(v any) {
			mu.Lock()
			captured = v.(map[string]bool)
			mu.Unlock()
		},
	}

	w := NewWatcher(0, tgt) // throttle=0: always stat
	w.Maybe()

	mu.Lock()
	got := len(captured)
	mu.Unlock()
	if got != 2 {
		t.Fatalf("after first Maybe: captured has %d entries, want 2", got)
	}

	// Mutate file and bump mtime so the watcher sees a change.
	writeFile(t, path, "alpha\nbeta\ngamma\n")
	bumpMtime(t, path, 2*time.Second)

	w.Maybe()

	mu.Lock()
	got = len(captured)
	mu.Unlock()
	if got != 3 {
		t.Fatalf("after second Maybe: captured has %d entries, want 3 (got %d)", 3, got)
	}
}

// TestWatcherThrottle: with a non-zero throttle window, a change made right
// after a Maybe() is NOT observed until the window elapses.
func TestWatcherThrottle(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "list.txt")
	writeFile(t, path, "initial\n")

	var mu sync.Mutex
	var captured map[string]bool

	tgt := Target{
		Path:      path,
		LastMtime: 0,
		Load: func(p string) any {
			return LoadLines(p, true)
		},
		Apply: func(v any) {
			mu.Lock()
			captured = v.(map[string]bool)
			mu.Unlock()
		},
	}

	w := NewWatcher(time.Hour, tgt) // very long throttle → never re-stat during test
	w.Maybe()                       // prime the throttle clock + load initial

	mu.Lock()
	got := len(captured)
	mu.Unlock()
	if got != 1 {
		t.Fatalf("after first Maybe: captured has %d entries, want 1", got)
	}

	// Mutate the file — the watcher should NOT see this because throttle is active.
	writeFile(t, path, "initial\nnewhost\n")
	bumpMtime(t, path, 2*time.Second)

	w.Maybe() // must be suppressed by throttle

	mu.Lock()
	got = len(captured)
	mu.Unlock()
	if got != 1 {
		t.Fatalf("throttled: captured has %d entries, want 1 (change should not be seen)", got)
	}
}

// TestStatMtime: verify StatMtime returns non-zero for an existing file and
// zero for a missing file.
func TestStatMtime(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "existing.txt")
	writeFile(t, path, "x\n")

	if m := StatMtime(path); m == 0 {
		t.Fatal("StatMtime(existing) = 0, want non-zero")
	}
	if m := StatMtime(filepath.Join(dir, "nonexistent.txt")); m != 0 {
		t.Fatalf("StatMtime(missing) = %d, want 0", m)
	}
}

// TestLoadLinesStripComments: verify comment stripping is applied when
// stripComments=true and NOT applied when false.
func TestLoadLinesStripComments(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "list.txt")
	writeFile(t, path, "alpha\n#comment\nbeta # inline\n")

	withStrip := LoadLines(path, true)
	if withStrip["#comment"] || withStrip["beta # inline"] {
		t.Fatal("stripComments=true: raw comment lines should not appear")
	}
	if !withStrip["alpha"] || !withStrip["beta"] {
		t.Fatalf("stripComments=true: expected {alpha, beta}, got %v", withStrip)
	}

	// Without stripping: "#comment" stays as-is; "beta # inline" stays verbatim.
	noStrip := LoadLines(path, false)
	if !noStrip["#comment"] {
		t.Fatal("stripComments=false: '#comment' should appear verbatim")
	}
	// "beta # inline" trimmed only by TrimSpace → "beta # inline"
	if !noStrip["beta # inline"] {
		t.Fatalf("stripComments=false: 'beta # inline' should appear verbatim, got %v", noStrip)
	}
}

// TestLoadLinesMissingFile: a missing file returns an empty set (best-effort).
func TestLoadLinesMissingFile(t *testing.T) {
	got := LoadLines("/nonexistent/path/file.txt", true)
	if len(got) != 0 {
		t.Fatalf("missing file: expected empty set, got %v", got)
	}
}

// TestWatcherMultipleTargets: two targets watched simultaneously; each fires
// its own Apply independently when its file changes.
func TestWatcherMultipleTargets(t *testing.T) {
	dir := t.TempDir()
	path1 := filepath.Join(dir, "list1.txt")
	path2 := filepath.Join(dir, "list2.txt")
	writeFile(t, path1, "a\n")
	writeFile(t, path2, "x\n")

	var mu sync.Mutex
	var cap1, cap2 map[string]bool

	tgt1 := Target{
		Path: path1,
		Load: func(p string) any { return LoadLines(p, true) },
		Apply: func(v any) {
			mu.Lock()
			cap1 = v.(map[string]bool)
			mu.Unlock()
		},
	}
	tgt2 := Target{
		Path: path2,
		Load: func(p string) any { return LoadLines(p, true) },
		Apply: func(v any) {
			mu.Lock()
			cap2 = v.(map[string]bool)
			mu.Unlock()
		},
	}

	w := NewWatcher(0, tgt1, tgt2)
	w.Maybe()

	mu.Lock()
	l1, l2 := len(cap1), len(cap2)
	mu.Unlock()
	if l1 != 1 || l2 != 1 {
		t.Fatalf("initial load: want cap1=1 cap2=1, got %d %d", l1, l2)
	}

	// Only mutate path2 — cap1 should stay at 1, cap2 should grow.
	writeFile(t, path2, "x\ny\n")
	bumpMtime(t, path2, 2*time.Second)

	w.Maybe()

	mu.Lock()
	l1, l2 = len(cap1), len(cap2)
	mu.Unlock()
	if l1 != 1 {
		t.Fatalf("after path2 change: cap1 should still be 1, got %d", l1)
	}
	if l2 != 2 {
		t.Fatalf("after path2 change: cap2 should be 2, got %d", l2)
	}
}

// TestWatcherConcurrent: hammer Maybe() from multiple goroutines while a
// background goroutine rewrites the file. Under -race, must be data-race-free.
func TestWatcherConcurrent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "list.txt")
	writeFile(t, path, "seed\n")

	var count int64

	tgt := Target{
		Path: path,
		Load: func(p string) any { return LoadLines(p, true) },
		Apply: func(v any) {
			atomic.AddInt64(&count, 1)
		},
	}

	w := NewWatcher(0, tgt)
	stop := make(chan struct{})
	var wg sync.WaitGroup

	// Writer goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			writeFile(t, path, "seed\nextra\n")
			bumpMtime(t, path, time.Duration(i+1)*time.Second)
		}
	}()

	// Reader goroutines
	for r := 0; r < 8; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 500; j++ {
				w.Maybe()
			}
		}()
	}

	time.Sleep(30 * time.Millisecond)
	close(stop)
	wg.Wait()
}
