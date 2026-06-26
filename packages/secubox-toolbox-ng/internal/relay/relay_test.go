// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: internal/relay — unit tests
package relay_test

import (
	"bufio"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/relay"
)

// spinEchoServer starts a unix-socket server in a goroutine that accepts one
// connection, reads the raw request, and records the request-line + body into
// the returned channel. The listener is returned so the test can close it.
func spinEchoServer(t *testing.T, sockPath string) (net.Listener, <-chan [2]string) {
	t.Helper()
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ch := make(chan [2]string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		r := bufio.NewReader(conn)

		// Read request-line.
		reqLine, _ := r.ReadString('\n')
		reqLine = strings.TrimSpace(reqLine)

		// Drain headers, find Content-Length.
		contentLength := 0
		for {
			line, err := r.ReadString('\n')
			if err != nil || strings.TrimSpace(line) == "" {
				break
			}
			trimmed := strings.TrimSpace(line)
			var clVal int
			if n, _ := parseContentLength(trimmed, &clVal); n {
				contentLength = clVal
			}
		}

		// Read body.
		var body string
		if contentLength > 0 {
			buf := make([]byte, contentLength)
			io.ReadFull(r, buf) //nolint:errcheck
			body = string(buf)
		}

		// Reply so the sender sees a clean close.
		conn.Write([]byte("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")) //nolint:errcheck
		ch <- [2]string{reqLine, body}
	}()
	return ln, ch
}

// parseContentLength parses "Content-Length: N" from a trimmed header line.
func parseContentLength(line string, out *int) (bool, error) {
	const prefix = "Content-Length: "
	if !strings.HasPrefix(line, prefix) {
		return false, nil
	}
	var n int
	_, err := parseIntStr(strings.TrimPrefix(line, prefix), &n)
	if err != nil {
		return false, err
	}
	*out = n
	return true, nil
}

func parseIntStr(s string, out *int) (int, error) {
	var n int
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	*out = n
	return n, nil
}

// TestEmitSync spins a unix-socket server, calls EmitSync, and asserts that
// the server observed the correct request-line and exact body payload.
func TestEmitSync(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "t.sock")
	ln, ch := spinEchoServer(t, sock)
	defer ln.Close()

	payload := []byte(`{"test":true}`)
	if err := relay.EmitSync(sock, "/ingest", payload); err != nil {
		t.Fatalf("EmitSync error: %v", err)
	}

	got := <-ch
	reqLine, body := got[0], got[1]

	if reqLine != "POST /ingest HTTP/1.1" {
		t.Errorf("request-line = %q, want %q", reqLine, "POST /ingest HTTP/1.1")
	}
	if body != string(payload) {
		t.Errorf("body = %q, want %q", body, payload)
	}
}

// TestEmitSyncDeadSocket verifies that EmitSync returns an error when the
// socket does not exist (dead/missing peer).
func TestEmitSyncDeadSocket(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "nonexistent.sock")
	err := relay.EmitSync(sock, "/ingest", []byte(`{}`))
	if err == nil {
		t.Error("expected error for missing socket, got nil")
	}
}

// TestEmit verifies that Emit (fire-and-forget) delivers the payload
// asynchronously without blocking the caller.
func TestEmit(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "emit.sock")
	ln, ch := spinEchoServer(t, sock)
	defer ln.Close()

	payload := []byte(`{"async":true}`)
	relay.Emit(sock, "/fire", payload) // must return immediately

	got := <-ch
	reqLine := got[0]
	if reqLine != "POST /fire HTTP/1.1" {
		t.Errorf("request-line = %q, want %q", reqLine, "POST /fire HTTP/1.1")
	}
}
