// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package sentinel

import (
	"bufio"
	"encoding/json"
	"net"
	"path/filepath"
	"testing"
	"time"
)

// startMirrorListener starts a unix-socket listener that decodes
// newline-delimited JSON MirrorMsg values onto the returned channel. It
// accepts a single connection (sufficient for these tests, which use one
// Mirror per listener) and closes it/the listener when t cleans up.
func startMirrorListener(t *testing.T, sock string) <-chan MirrorMsg {
	t.Helper()
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	out := make(chan MirrorMsg, 256)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		sc := bufio.NewScanner(conn)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for sc.Scan() {
			var msg MirrorMsg
			if err := json.Unmarshal(sc.Bytes(), &msg); err != nil {
				continue
			}
			out <- msg
		}
	}()
	return out
}

func TestMirrorEmitDeliversMessages(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "sentinel.sock")
	received := startMirrorListener(t, sock)

	m := NewMirror(sock, 8, 1024)
	defer m.Close()

	for i := 0; i < 3; i++ {
		m.Emit(MirrorMsg{
			Meta: FlowMeta{Host: "evil.example", MacHash: "deadbeef"},
			Body: []byte("payload"),
			TS:   time.Now().Unix(),
		})
	}

	for i := 0; i < 3; i++ {
		select {
		case msg := <-received:
			if msg.Meta.Host != "evil.example" {
				t.Fatalf("unexpected host: %q", msg.Meta.Host)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for message %d", i)
		}
	}

	if d := m.Dropped(); d != 0 {
		t.Fatalf("expected 0 dropped, got %d", d)
	}
}

func TestMirrorTruncatesBody(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "sentinel.sock")
	received := startMirrorListener(t, sock)

	const cap = 16
	m := NewMirror(sock, 8, cap)
	defer m.Close()

	big := make([]byte, 4096)
	for i := range big {
		big[i] = 'a'
	}
	m.Emit(MirrorMsg{Meta: FlowMeta{Host: "big.example"}, Body: big, TS: time.Now().Unix()})

	select {
	case msg := <-received:
		if len(msg.Body) != cap {
			t.Fatalf("expected body truncated to %d, got %d", cap, len(msg.Body))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for truncated message")
	}
}

// TestMirrorEmitNeverBlocksOnOverflow uses a queue of 1 with no reader ever
// draining (no listener at all — the writer goroutine will fail to dial and
// just keep retrying in the background), and asserts that Emit still
// returns immediately and Dropped() eventually goes positive.
func TestMirrorEmitNeverBlocksOnOverflow(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "nonexistent.sock") // nothing listens here

	m := NewMirror(sock, 1, 64)
	defer m.Close()

	done := make(chan struct{})
	go func() {
		for i := 0; i < 10000; i++ {
			m.Emit(MirrorMsg{Meta: FlowMeta{Host: "x"}, Body: []byte("y"), TS: 1})
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Emit blocked — overflow must be non-blocking")
	}

	if m.Dropped() == 0 {
		t.Fatal("expected Dropped() > 0 after overflowing an undrained queue of size 1")
	}
}

// TestMirrorEmitCopiesBodyNoAliasing guards against a buffer-aliasing bug:
// Emit must copy msg.Body into a fresh slice before queueing it, because
// sbxmitm's hot path may reuse/pool the backing array the instant Emit
// returns. If Emit queued msg.Body as-is (no copy), mutating the caller's
// buffer right after Emit would corrupt the message the writer goroutine
// later encodes — a genuine data race on the underlying array.
func TestMirrorEmitCopiesBodyNoAliasing(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "sentinel.sock")
	received := startMirrorListener(t, sock)

	m := NewMirror(sock, 8, 1024)
	defer m.Close()

	const want = "SENSITIVE-PAYLOAD"
	orig := []byte(want)
	m.Emit(MirrorMsg{Meta: FlowMeta{Host: "alias.example"}, Body: orig, TS: time.Now().Unix()})

	// Mutate the caller's buffer immediately — as sbxmitm's hot path would
	// do by reusing a pooled read buffer right after Emit returns. If Emit
	// queued the slice as-is (aliasing), the listener will observe this
	// mutated content instead of the original payload.
	for i := range orig {
		orig[i] = 'X'
	}

	select {
	case msg := <-received:
		if got := string(msg.Body); got != want {
			t.Fatalf("Emit aliased caller buffer: got %q, want %q", got, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for message")
	}
}
