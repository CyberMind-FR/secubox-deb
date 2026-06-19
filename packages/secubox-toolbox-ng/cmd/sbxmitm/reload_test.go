// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: policy live-reload tests (#662 auto-learn loop)
//
// The #662 Go cutover loaded the BLOCK/SPLICE lists ONCE at startup, so an
// autolearn promotion (or a manual edit) of learned-trackers.txt never took
// effect until a worker restart — the very thing that made new adwares slip
// through forever. These tests prove the mtime-based live-reload: after the
// throttle window, a host appended to learned-trackers.txt flips Decide from
// "mitm" to "block" with NO restart. Concurrency is exercised under -race.
package main

import (
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// writeFile is a tiny helper that (re)writes a backing list file with content.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// bumpMtime forces the file's mtime forward so the reload's stat sees a change
// even on coarse-granularity filesystems or sub-second test runs.
func bumpMtime(t *testing.T, path string, d time.Duration) {
	t.Helper()
	ft := time.Now().Add(d)
	if err := os.Chtimes(path, ft, ft); err != nil {
		t.Fatalf("chtimes %s: %v", path, err)
	}
}

// TestMaybeReloadPicksUpAppendedLearnedTracker is the linchpin test: a host that
// initially Decides "mitm" must flip to "block" once it is appended to
// learned-trackers.txt and the throttle window elapses — without reloading the
// Policy from scratch.
func TestMaybeReloadPicksUpAppendedLearnedTracker(t *testing.T) {
	dir := t.TempDir()
	learned := filepath.Join(dir, "learned-trackers.txt")
	allow := filepath.Join(dir, "ad-allowlist.txt")
	writeFile(t, learned, "")
	writeFile(t, allow, "")

	pol, err := LoadPolicy(PolicyOpts{
		LearnedPath: learned,
		AllowPath:   allow,
		// keep the splice/never paths in the temp dir so missing-file behaviour
		// (empty set) is deterministic.
		SpliceSeedPath:   filepath.Join(dir, "seed"),
		SpliceLearnPath:  filepath.Join(dir, "slearn"),
		PureTrackersPath: filepath.Join(dir, "pure"),
		SelfDomains:      []string{"secubox.in"},
	})
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	// Make the reload eager for the test (no 15s wait): zero throttle.
	pol.reloadThrottle = 0

	const host = "acotedemoi.com"
	if got := pol.Decide(host, host); got != "mitm" {
		t.Fatalf("before promotion: Decide(%q) = %q, want mitm", host, got)
	}

	// Promote: append the host and bump mtime forward.
	writeFile(t, learned, host+"\n")
	bumpMtime(t, learned, 2*time.Second)

	if got := pol.Decide(host, host); got != "block" {
		t.Fatalf("after promotion: Decide(%q) = %q, want block", host, got)
	}
}

// TestMaybeReloadThrottled proves the throttle: with a non-zero throttle window,
// a change made just after a reload is NOT observed until the window elapses,
// keeping the hot path cheap (one stat per ~window, not per request).
func TestMaybeReloadThrottled(t *testing.T) {
	dir := t.TempDir()
	learned := filepath.Join(dir, "learned-trackers.txt")
	writeFile(t, learned, "")

	pol, err := LoadPolicy(PolicyOpts{LearnedPath: learned, AllowPath: filepath.Join(dir, "allow")})
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	pol.reloadThrottle = time.Hour // effectively "never re-stat during the test"

	// Prime the throttle clock with one Decide (does the initial stat).
	_ = pol.Decide("x.example", "x.example")

	const host = "tracker.example"
	writeFile(t, learned, host+"\n")
	bumpMtime(t, learned, 2*time.Second)

	if got := pol.Decide(host, host); got != "mitm" {
		t.Fatalf("throttled: Decide(%q) = %q, want mitm (change not yet observed)", host, got)
	}
}

// TestMaybeReloadAllowlist proves the allowlist file is live-reloaded too: a
// host the ad-host regex would block ("doubleclick.net") flips block→allow once
// appended to the allowlist and the window elapses.
func TestMaybeReloadAllowlist(t *testing.T) {
	dir := t.TempDir()
	learned := filepath.Join(dir, "learned-trackers.txt")
	allow := filepath.Join(dir, "ad-allowlist.txt")
	writeFile(t, learned, "")
	writeFile(t, allow, "")

	pol, err := LoadPolicy(PolicyOpts{LearnedPath: learned, AllowPath: allow})
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	pol.reloadThrottle = 0

	const host = "doubleclick.net"
	if got := pol.Decide(host, host); got != "block" {
		t.Fatalf("before allow: Decide(%q) = %q, want block", host, got)
	}
	writeFile(t, allow, host+"\n")
	bumpMtime(t, allow, 2*time.Second)
	if got := pol.Decide(host, host); got != "allow" {
		t.Fatalf("after allow: Decide(%q) = %q, want allow", host, got)
	}
}

// TestMaybeReloadConcurrent runs Decide from many goroutines while the backing
// learned file is rewritten concurrently. Under `go test -race` this proves the
// RWMutex-guarded swap is data-race-free.
func TestMaybeReloadConcurrent(t *testing.T) {
	dir := t.TempDir()
	learned := filepath.Join(dir, "learned-trackers.txt")
	writeFile(t, learned, "seed.example\n")

	pol, err := LoadPolicy(PolicyOpts{LearnedPath: learned, AllowPath: filepath.Join(dir, "allow")})
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	pol.reloadThrottle = 0 // force a stat on every Decide → maximal contention

	var wg sync.WaitGroup
	var blocks int64
	stop := make(chan struct{})

	// Writer: keep appending hosts + bumping mtime.
	wg.Add(1)
	go func() {
		defer wg.Done()
		i := 0
		for {
			select {
			case <-stop:
				return
			default:
			}
			writeFile(t, learned, "seed.example\nh"+itoa(i)+".example\n")
			bumpMtime(t, learned, time.Duration(i+1)*time.Second)
			i++
		}
	}()

	// Readers: hammer Decide on the seed (stable → always block) + a live host.
	for r := 0; r < 8; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 2000; j++ {
				if pol.Decide("seed.example", "seed.example") == "block" {
					atomic.AddInt64(&blocks, 1)
				}
				pol.Decide("h0.example", "h0.example")
			}
		}()
	}
	time.Sleep(50 * time.Millisecond)
	close(stop)
	wg.Wait()
	if blocks == 0 {
		t.Fatal("expected the stable seed host to block at least once")
	}
}
