// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// Unit tests for the sidecar emit helper (#662 Phase 4).
package main

import (
	"bufio"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestEmitDelivers: emitSync to a live unix socket delivers the POST request
// line, route and JSON body.
func TestEmitDelivers(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "emit.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	got := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		var sb strings.Builder
		r := bufio.NewReader(c)
		buf := make([]byte, 4096)
		for {
			n, err := r.Read(buf)
			sb.Write(buf[:n])
			if err != nil || strings.Contains(sb.String(), `"k":"v"`) {
				break
			}
		}
		// Reply so emitSync's drain completes cleanly.
		c.Write([]byte("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
		got <- sb.String()
	}()

	if err := emitSync(sock, "/classify", []byte(`{"k":"v"}`)); err != nil {
		t.Fatalf("emitSync: %v", err)
	}

	select {
	case raw := <-got:
		if !strings.HasPrefix(raw, "POST /classify HTTP/1.1") {
			t.Errorf("missing/wrong request line in:\n%s", raw)
		}
		if !strings.Contains(raw, `{"k":"v"}`) {
			t.Errorf("body not delivered in:\n%s", raw)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server never received the emit")
	}
}

// TestEmitDeadSocketNoPanicNoBlock: emit() (the goroutine form) to a
// nonexistent socket must return immediately and never panic, and emitSync
// must just return an error without blocking past the timeout.
func TestEmitDeadSocketNoPanicNoBlock(t *testing.T) {
	dead := filepath.Join(t.TempDir(), "nope.sock")

	// emit (async) returns instantly even though the socket is dead.
	done := make(chan struct{})
	go func() {
		defer close(done)
		emit(dead, "/inject", []byte(`{"x":1}`)) // must not panic/block
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("emit() blocked on a dead socket")
	}

	// emitSync surfaces the dial error (which emit swallows) without blocking.
	start := time.Now()
	if err := emitSync(dead, "/inject", []byte(`{}`)); err == nil {
		t.Error("emitSync to dead socket: expected error, got nil")
	}
	if elapsed := time.Since(start); elapsed > emitTimeout+time.Second {
		t.Errorf("emitSync blocked %v on dead socket", elapsed)
	}
}

// TestEmitEmptyRouteDefaults: an empty route becomes "/".
func TestEmitEmptyRouteDefaults(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "root.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 256)
		n, _ := c.Read(buf)
		c.Write([]byte("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
		got <- string(buf[:n])
	}()
	if err := emitSync(sock, "", nil); err != nil {
		t.Fatalf("emitSync: %v", err)
	}
	select {
	case raw := <-got:
		if !strings.HasPrefix(raw, "POST / HTTP/1.1") {
			t.Errorf("empty route not defaulted to /, got:\n%s", raw)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no request received")
	}
}
