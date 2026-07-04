// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// #796 — sbxwaf must forward WebSocket upgrades (it used to force Connection:
// close on every upstream request, clobbering Connection: Upgrade and breaking
// httputil.ReverseProxy's WS tunnel → wss:// vhosts got a 404/1006).
package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// hijackableRW is a ResponseWriter that records whether Hijack was called on it.
type hijackableRW struct {
	http.ResponseWriter
	hijacked bool
}

func (h *hijackableRW) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h.hijacked = true
	return nil, nil, nil
}

// TestResponseWrappersForwardHijack guards #796: every ResponseWriter wrapper in
// the sbxwaf handler chain (visit-stats + media-cache) must forward Hijack, or
// httputil.ReverseProxy can't tunnel WebSocket upgrades ("can't switch protocols
// using non-Hijacker ResponseWriter type …").
func TestResponseWrappersForwardHijack(t *testing.T) {
	base := &hijackableRW{ResponseWriter: httptest.NewRecorder()}

	sr := &statusRecorder{ResponseWriter: base}
	if _, ok := interface{}(sr).(http.Hijacker); !ok {
		t.Fatal("statusRecorder does not implement http.Hijacker")
	}
	sr.Hijack()
	if !base.hijacked {
		t.Fatal("statusRecorder.Hijack did not forward to the underlying writer")
	}

	base.hijacked = false
	cw := &cachingResponseWriter{ResponseWriter: base}
	if _, ok := interface{}(cw).(http.Hijacker); !ok {
		t.Fatal("cachingResponseWriter does not implement http.Hijacker")
	}
	cw.Hijack()
	if !base.hijacked {
		t.Fatal("cachingResponseWriter.Hijack did not forward to the underlying writer")
	}
}

func TestIsWebSocketUpgrade(t *testing.T) {
	cases := []struct {
		conn, upg string
		want      bool
	}{
		{"Upgrade", "websocket", true},
		{"upgrade", "WebSocket", true},             // case-insensitive
		{"keep-alive, Upgrade", "websocket", true}, // Upgrade token in a list
		{"keep-alive", "websocket", false},         // no Upgrade token in Connection
		{"Upgrade", "", false},                     // no Upgrade header
		{"close", "websocket", false},              // close, not upgrade
		{"", "", false},                            // plain request
	}
	for _, c := range cases {
		h := http.Header{}
		if c.conn != "" {
			h.Set("Connection", c.conn)
		}
		if c.upg != "" {
			h.Set("Upgrade", c.upg)
		}
		if got := isWebSocketUpgrade(h); got != c.want {
			t.Errorf("isWebSocketUpgrade(Connection=%q Upgrade=%q) = %v, want %v",
				c.conn, c.upg, got, c.want)
		}
	}
}

// wsBackend upgrades a WebSocket handshake (records the Connection header it
// received on connCh) and echoes back "hello". Non-WS requests get 200 with the
// Connection header sent to connCh too.
func wsBackend(connCh chan<- string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		select {
		case connCh <- r.Header.Get("Connection"):
		default:
		}
		if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			w.WriteHeader(http.StatusOK)
			io.WriteString(w, "plain-ok")
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "backend: no hijack", http.StatusInternalServerError)
			return
		}
		conn, brw, err := hj.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		io.WriteString(brw, "HTTP/1.1 101 Switching Protocols\r\n"+
			"Upgrade: websocket\r\nConnection: Upgrade\r\n\r\nhello")
		brw.Flush()
	}
}

func splitHostPortInt(t *testing.T, url string) (string, int) {
	t.Helper()
	addr := strings.TrimPrefix(url, "http://")
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", addr, err)
	}
	var port int
	for _, b := range []byte(portStr) {
		port = port*10 + int(b-'0')
	}
	return host, port
}

// TestHandlerPreservesWebSocketUpgrade drives a real WS handshake through the
// sbxwaf handler (rules loaded → the Connection-rewrite path is active) and
// asserts it reaches the backend as an upgrade (101), not a clobbered plain GET.
func TestHandlerPreservesWebSocketUpgrade(t *testing.T) {
	connCh := make(chan string, 1)
	backend := httptest.NewServer(wsBackend(connCh))
	defer backend.Close()
	bHost, bPort := splitHostPortInt(t, backend.URL)

	srv := &Server{
		rules:  LoadRules("/tmp/nonexistent-waf-rules-796.json"), // non-nil, matches nothing → clobber path active
		visits: NewVisitStats(t.TempDir() + "/visits.json"),      // non-nil → statusRecorder wraps w (board path; must still Hijack)
		routeLookup: func(host string) (string, int, bool) {
			return bHost, bPort, true
		},
	}
	front := httptest.NewServer(srv.handler())
	defer front.Close()

	c, err := net.Dial("tcp", strings.TrimPrefix(front.URL, "http://"))
	if err != nil {
		t.Fatalf("dial front: %v", err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))

	fmt.Fprintf(c, "GET /api HTTP/1.1\r\nHost: zigbee.example.com\r\n"+
		"Upgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")

	br := bufio.NewReader(c)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read status line: %v", err)
	}
	if !strings.Contains(status, "101") {
		t.Fatalf("WebSocket upgrade not tunnelled: status = %q (want 101 Switching Protocols)", strings.TrimSpace(status))
	}

	// The backend must have seen the upgrade, NOT a clobbered Connection: close.
	select {
	case got := <-connCh:
		if strings.EqualFold(strings.TrimSpace(got), "close") {
			t.Fatalf("backend received Connection: close on a WebSocket upgrade (clobbered)")
		}
		if !strings.Contains(strings.ToLower(got), "upgrade") {
			t.Fatalf("backend Connection header lost the upgrade token: %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("backend never received the request")
	}
}

// TestHandlerProxiesNonWebSocket is the regression guard: the WS carve-out must
// not break ordinary (non-WS) requests — they still proxy normally. (The #496
// Connection: close set on the upstream request is a hop-by-hop header that
// ReverseProxy consumes to disable keep-alive; it is not forwarded to the
// backend, so we assert the response, not the backend's Connection header.)
func TestHandlerProxiesNonWebSocket(t *testing.T) {
	connCh := make(chan string, 1)
	backend := httptest.NewServer(wsBackend(connCh))
	defer backend.Close()
	bHost, bPort := splitHostPortInt(t, backend.URL)

	srv := &Server{
		rules: LoadRules("/tmp/nonexistent-waf-rules-796.json"),
		routeLookup: func(host string) (string, int, bool) {
			return bHost, bPort, true
		},
	}
	front := httptest.NewServer(srv.handler())
	defer front.Close()

	resp, err := http.Get(front.URL + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("non-WS request: status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "plain-ok") {
		t.Fatalf("non-WS request: body = %q, want plain-ok", string(body))
	}
}
