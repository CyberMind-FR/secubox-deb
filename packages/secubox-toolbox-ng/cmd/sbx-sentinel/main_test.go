// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"context"
	"encoding/json"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/sentinel"
)

// stubAnalyzer returns a fixed Verdict (a copy) for every message it sees,
// and counts how many times Analyze was called. Safe for concurrent use.
// If panicOn is set and returns true for a message, Analyze panics instead
// of returning — used to exercise the daemon's per-analyzer recover().
type stubAnalyzer struct {
	mu      sync.Mutex
	calls   int
	verdict sentinel.Verdict
	panicOn func(sentinel.MirrorMsg) bool
}

func (s *stubAnalyzer) Analyze(msg sentinel.MirrorMsg) []*sentinel.Verdict {
	s.mu.Lock()
	s.calls++
	s.mu.Unlock()
	if s.panicOn != nil && s.panicOn(msg) {
		panic("stubAnalyzer: forced panic for test")
	}
	v := s.verdict
	v.MacHash = msg.Meta.MacHash
	v.TS = time.Now().Unix()
	return []*sentinel.Verdict{&v}
}

func (s *stubAnalyzer) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// dialWithRetry dials sock, retrying briefly since run's listener is stood
// up asynchronously (run() itself blocks serving connections).
func dialWithRetry(t *testing.T, sock string) net.Conn {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := net.Dial("unix", sock)
		if err == nil {
			return conn
		}
		lastErr = err
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("dial %q: timed out, last error: %v", sock, lastErr)
	return nil
}

// waitForRecent polls store.Recent(limit) until pred matches at least one
// verdict, or fails the test after a timeout.
func waitForRecent(t *testing.T, store *sentinel.Store, pred func(sentinel.Verdict) bool) sentinel.Verdict {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		recent, err := store.Recent(50)
		if err != nil {
			t.Fatalf("Recent: %v", err)
		}
		for _, v := range recent {
			if pred(v) {
				return v
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("timed out waiting for expected verdict to land in store")
	return sentinel.Verdict{}
}

func newTestConfig(t *testing.T, analyzers ...Analyzer) Config {
	t.Helper()
	dir := t.TempDir()
	return Config{
		SocketPath:    filepath.Join(dir, "sentinel-mirror.sock"),
		DBPath:        filepath.Join(dir, "verdicts.db"),
		TTL:           time.Hour,
		PruneInterval: 50 * time.Millisecond,
		Analyzers:     analyzers,
	}
}

// startDaemon starts run(ctx, cfg) in the background (wiring cfg.onStoreOpen
// to capture the daemon's own live *sentinel.Store — bbolt takes an
// exclusive file lock, so tests must reuse this handle rather than opening
// a second one on the same DBPath) and returns the store plus cancel/wait
// funcs. It fails the test if the store isn't handed back promptly.
func startDaemon(t *testing.T, cfg Config) (store *sentinel.Store, cancel func(), wait func() error) {
	t.Helper()

	storeCh := make(chan *sentinel.Store, 1)
	cfg.onStoreOpen = func(s *sentinel.Store) { storeCh <- s }

	ctx, cancelFn := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- run(ctx, cfg)
	}()

	select {
	case store = <-storeCh:
	case err := <-errCh:
		t.Fatalf("run exited before opening store: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for daemon to open its store")
	}

	wait = func() error {
		select {
		case err := <-errCh:
			return err
		case <-time.After(5 * time.Second):
			t.Fatal("run() did not return after cancel — possible goroutine leak/deadlock")
			return nil
		}
	}
	return store, cancelFn, wait
}

func TestRunRecordsVerdictFromStubAnalyzer(t *testing.T) {
	stub := &stubAnalyzer{verdict: sentinel.Verdict{
		Class:      sentinel.ClassBotnetC2,
		Severity:   95,
		Confidence: 95,
		Action:     sentinel.ActionBlock,
	}}
	cfg := newTestConfig(t, stub)

	store, cancel, wait := startDaemon(t, cfg)
	defer func() {
		cancel()
		if err := wait(); err != nil {
			t.Errorf("run returned error on shutdown: %v", err)
		}
	}()

	conn := dialWithRetry(t, cfg.SocketPath)
	defer conn.Close()

	msg := sentinel.MirrorMsg{
		Meta: sentinel.FlowMeta{Host: "evil.example", MacHash: "mac-under-test"},
		Body: []byte("payload"),
		TS:   time.Now().Unix(),
	}
	if err := json.NewEncoder(conn).Encode(msg); err != nil {
		t.Fatalf("encode: %v", err)
	}

	got := waitForRecent(t, store, func(v sentinel.Verdict) bool {
		return v.MacHash == "mac-under-test"
	})
	if got.Class != sentinel.ClassBotnetC2 {
		t.Fatalf("unexpected class: %v", got.Class)
	}
	if got.Action != sentinel.ActionBlock {
		t.Fatalf("expected high-confidence block to survive FinalizeAction, got %v", got.Action)
	}
	if stub.callCount() != 1 {
		t.Fatalf("expected analyzer called once, got %d", stub.callCount())
	}
}

// TestRunFinalizeActionDowngradesHeuristic asserts the daemon calls
// FinalizeAction on every analyzer-returned verdict: a heuristic class
// (ClassZeroClick) that an analyzer mis-declares as ActionBlock must land
// in the store downgraded to ActionReport.
func TestRunFinalizeActionDowngradesHeuristic(t *testing.T) {
	stub := &stubAnalyzer{verdict: sentinel.Verdict{
		Class:      sentinel.ClassZeroClick,
		Severity:   99,
		Confidence: 99,
		Action:     sentinel.ActionBlock, // mis-declared — must be downgraded
	}}
	cfg := newTestConfig(t, stub)

	store, cancel, wait := startDaemon(t, cfg)
	defer func() {
		cancel()
		if err := wait(); err != nil {
			t.Errorf("run returned error on shutdown: %v", err)
		}
	}()

	conn := dialWithRetry(t, cfg.SocketPath)
	defer conn.Close()

	msg := sentinel.MirrorMsg{Meta: sentinel.FlowMeta{MacHash: "heuristic-mac"}, TS: time.Now().Unix()}
	if err := json.NewEncoder(conn).Encode(msg); err != nil {
		t.Fatalf("encode: %v", err)
	}

	got := waitForRecent(t, store, func(v sentinel.Verdict) bool {
		return v.MacHash == "heuristic-mac"
	})
	if got.Action != sentinel.ActionReport {
		t.Fatalf("expected heuristic class downgraded to ActionReport, got %v", got.Action)
	}
}

// TestRunSkipsMalformedLine sends a malformed line followed by a good line
// on the same connection and asserts the daemon neither crashes nor drops
// the connection: the following good message still lands in the store.
func TestRunSkipsMalformedLine(t *testing.T) {
	stub := &stubAnalyzer{verdict: sentinel.Verdict{Class: sentinel.ClassMalware, Severity: 90, Confidence: 90, Action: sentinel.ActionBlock}}
	cfg := newTestConfig(t, stub)

	store, cancel, wait := startDaemon(t, cfg)
	defer func() {
		cancel()
		if err := wait(); err != nil {
			t.Errorf("run returned error on shutdown: %v", err)
		}
	}()

	conn := dialWithRetry(t, cfg.SocketPath)
	defer conn.Close()

	if _, err := conn.Write([]byte("{not valid json at all\n")); err != nil {
		t.Fatalf("write malformed line: %v", err)
	}

	good := sentinel.MirrorMsg{Meta: sentinel.FlowMeta{MacHash: "after-malformed"}, TS: time.Now().Unix()}
	if err := json.NewEncoder(conn).Encode(good); err != nil {
		t.Fatalf("encode good line: %v", err)
	}

	waitForRecent(t, store, func(v sentinel.Verdict) bool {
		return v.MacHash == "after-malformed"
	})
}

// TestRunAnalyzerPanicRecovered asserts a panicking Analyzer never crashes
// the daemon: the panicking message yields no verdict, but a subsequent
// message on the same connection is still processed normally.
func TestRunAnalyzerPanicRecovered(t *testing.T) {
	panicky := &stubAnalyzer{
		verdict: sentinel.Verdict{Class: sentinel.ClassMalware, Severity: 90, Confidence: 90, Action: sentinel.ActionBlock},
		panicOn: func(msg sentinel.MirrorMsg) bool { return msg.Meta.MacHash == "boom" },
	}
	cfg := newTestConfig(t, panicky)

	store, cancel, wait := startDaemon(t, cfg)
	defer func() {
		cancel()
		if err := wait(); err != nil {
			t.Errorf("run returned error on shutdown: %v", err)
		}
	}()

	conn := dialWithRetry(t, cfg.SocketPath)
	defer conn.Close()
	enc := json.NewEncoder(conn)

	if err := enc.Encode(sentinel.MirrorMsg{Meta: sentinel.FlowMeta{MacHash: "boom"}, TS: time.Now().Unix()}); err != nil {
		t.Fatalf("encode: %v", err)
	}
	if err := enc.Encode(sentinel.MirrorMsg{Meta: sentinel.FlowMeta{MacHash: "after-boom"}, TS: time.Now().Unix()}); err != nil {
		t.Fatalf("encode: %v", err)
	}

	waitForRecent(t, store, func(v sentinel.Verdict) bool {
		return v.MacHash == "after-boom"
	})

	recent, err := store.Recent(50)
	if err != nil {
		t.Fatalf("Recent: %v", err)
	}
	for _, v := range recent {
		if v.MacHash == "boom" {
			t.Fatalf("expected the panicking message to yield no verdict, found one: %+v", v)
		}
	}
}

// TestRunPrunesExpiredVerdicts asserts the periodic Prune ticker actually
// removes verdicts once they age past cfg.TTL.
func TestRunPrunesExpiredVerdicts(t *testing.T) {
	stub := &stubAnalyzer{verdict: sentinel.Verdict{Class: sentinel.ClassMalware, Severity: 90, Confidence: 90, Action: sentinel.ActionBlock}}
	cfg := newTestConfig(t, stub)
	cfg.TTL = 10 * time.Millisecond
	cfg.PruneInterval = 20 * time.Millisecond

	store, cancel, wait := startDaemon(t, cfg)
	defer func() {
		cancel()
		if err := wait(); err != nil {
			t.Errorf("run returned error on shutdown: %v", err)
		}
	}()

	conn := dialWithRetry(t, cfg.SocketPath)
	defer conn.Close()
	if err := json.NewEncoder(conn).Encode(sentinel.MirrorMsg{Meta: sentinel.FlowMeta{MacHash: "will-expire"}, TS: time.Now().Unix()}); err != nil {
		t.Fatalf("encode: %v", err)
	}

	waitForRecent(t, store, func(v sentinel.Verdict) bool { return v.MacHash == "will-expire" })

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		recent, err := store.Recent(50)
		if err != nil {
			t.Fatalf("Recent: %v", err)
		}
		found := false
		for _, v := range recent {
			if v.MacHash == "will-expire" {
				found = true
			}
		}
		if !found {
			return // pruned
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("verdict was never pruned after TTL elapsed")
}

// TestRunGracefulShutdown asserts cancelling the context makes run return
// promptly (no goroutine leak / hang), and that the socket is no longer
// accepting connections afterward.
func TestRunGracefulShutdown(t *testing.T) {
	cfg := newTestConfig(t)

	_, cancel, wait := startDaemon(t, cfg)

	// Make sure the daemon is actually up before tearing it down.
	conn := dialWithRetry(t, cfg.SocketPath)
	conn.Close()

	cancel()
	if err := wait(); err != nil {
		t.Fatalf("run returned error on shutdown: %v", err)
	}

	// Any dial error (connection-refused, no-such-file, ...) confirms the
	// daemon is no longer serving; we don't care which.
	if _, err := net.Dial("unix", cfg.SocketPath); err == nil {
		t.Fatal("expected socket to be unreachable after shutdown")
	}
}
