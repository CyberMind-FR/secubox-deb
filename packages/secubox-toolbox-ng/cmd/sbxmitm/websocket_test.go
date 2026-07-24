// SPDX-License-Identifier: LicenseRef-CMSD-1.0
package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestIsWebSocketUpgrade(t *testing.T) {
	mk := func(conn, upg string) *http.Request {
		r, _ := http.NewRequest("GET", "https://x/socket.io/", nil)
		if conn != "" {
			r.Header.Set("Connection", conn)
		}
		if upg != "" {
			r.Header.Set("Upgrade", upg)
		}
		return r
	}
	cases := []struct {
		conn, upg string
		want      bool
	}{
		{"Upgrade", "websocket", true},
		{"keep-alive, Upgrade", "websocket", true}, // comma list
		{"upgrade", "WebSocket", true},             // case-insensitive
		{"Upgrade", "", false},                     // no Upgrade header
		{"", "websocket", false},                   // no Connection token
		{"keep-alive", "websocket", false},         // Connection lacks upgrade
		{"Upgrade", "h2c", false},                  // not websocket
	}
	for _, c := range cases {
		if got := isWebSocketUpgrade(mk(c.conn, c.upg)); got != c.want {
			t.Errorf("isWebSocketUpgrade(conn=%q upg=%q)=%v want %v", c.conn, c.upg, got, c.want)
		}
	}
}

// A minimal RFC6455-ish upstream: it completes the 101 handshake by hand (echo
// of the frames is NOT needed — the test asserts the 101 crosses the proxy and
// that raw bytes flow both ways). We avoid pulling a websocket library: after
// 101 the server just echoes whatever bytes it receives.
func rawWSHandler(w http.ResponseWriter, r *http.Request) {
	if !isWebSocketUpgrade(r) {
		http.Error(w, "not ws", 400)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "no hijack", 500)
		return
	}
	conn, _, err := hj.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	_, _ = conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n"))
	// Echo loop: prove the post-handshake pipe carries bytes both ways.
	buf := make([]byte, 256)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := conn.Read(buf)
		if n > 0 {
			_, _ = conn.Write(buf[:n])
		}
		if err != nil {
			return
		}
	}
}

func TestProxyWebSocket_RelaysUpgradeAndPipes(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(rawWSHandler))
	defer srv.Close()

	// Trust the test server's cert so dialUChromeALPN's manual verification
	// passes (it verifies against system roots by default; here we inject the
	// httptest CA via a rootCAs pool through a dedicated dial).
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())

	// srv.Listener.Addr() is host:port; SNI must match the cert (example.com is
	// httptest's default SAN). Dial the real addr, verify against "example.com".
	addr := srv.Listener.Addr().String()

	// Build the client side of the MITM boundary with an in-memory pipe: one end
	// stands in for the TLS-terminated client conn, the other is the "browser".
	cliProxy, cliBrowser := net.Pipe()
	defer cliProxy.Close()
	defer cliBrowser.Close()

	// The proxy reads the upgrade request from cliProxy via a bufio reader
	// (mirrors mitmPipeline's `br`).
	br := bufio.NewReader(cliProxy)

	// Kick the proxy: it dials upstream (h1.1 forced), relays 101, then pipes.
	px := &Proxy{}
	go func() {
		// Wait for the request to arrive on br before dialing (ReadRequest).
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		req.URL.Scheme = "https"
		req.URL.Host = "example.com"
		// Force the dial to the httptest addr but verify SNI=example.com.
		px.proxyWebSocketWithDial(cliProxy, br, req, addr, "example.com", pool)
	}()

	// Browser writes the upgrade request, then a payload, expects the echo.
	up := "GET /socket.io/ HTTP/1.1\r\nHost: example.com\r\n" +
		"Connection: Upgrade\r\nUpgrade: websocket\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
	if _, err := cliBrowser.Write([]byte(up)); err != nil {
		t.Fatalf("write upgrade: %v", err)
	}
	rd := bufio.NewReader(cliBrowser)
	status, err := rd.ReadString('\n')
	if err != nil {
		t.Fatalf("read status: %v", err)
	}
	if !strings.Contains(status, "101") {
		t.Fatalf("expected 101 relayed, got %q", status)
	}
	// Drain the rest of the 101 headers up to the blank line.
	for {
		line, err := rd.ReadString('\n')
		if err != nil {
			t.Fatalf("read headers: %v", err)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	// Post-handshake: send a payload, expect it echoed back through both pipes.
	payload := []byte("hello-frame")
	if _, err := cliBrowser.Write(payload); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	got := make([]byte, len(payload))
	_ = cliBrowser.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := readFull(rd, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("echo mismatch: got %q want %q", got, payload)
	}
}

func readFull(r *bufio.Reader, buf []byte) (int, error) {
	n := 0
	for n < len(buf) {
		m, err := r.Read(buf[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

// proxyWebSocketWithDial is a test seam: same body as proxyWebSocket but with an
// injectable dial target + rootCAs so the httptest self-signed cert is trusted.
func (px *Proxy) proxyWebSocketWithDial(clientConn net.Conn, clientBr *bufio.Reader, req *http.Request, target, sni string, roots *x509.CertPool) {
	up, _, err := dialUChromeALPN(newTestCtx(), target, sni, roots, []string{"http/1.1"})
	if err != nil {
		writeRaw(clientConn, 502, "Bad Gateway", nil, nil)
		return
	}
	defer up.Close()
	req.RequestURI = ""
	if err := req.Write(up); err != nil {
		writeRaw(clientConn, 502, "Bad Gateway", nil, nil)
		return
	}
	upBr := bufio.NewReader(up)
	resp, err := http.ReadResponse(upBr, req)
	if err != nil {
		writeRaw(clientConn, 502, "Bad Gateway", nil, nil)
		return
	}
	if err := resp.Write(clientConn); err != nil {
		resp.Body.Close()
		return
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		resp.Body.Close()
		return
	}
	resp.Body.Close()
	_ = clientConn.SetDeadline(time.Time{})
	_ = up.SetDeadline(time.Time{})
	done := make(chan struct{}, 2)
	go func() { _, _ = ioCopy(up, clientBr); done <- struct{}{} }()
	go func() { _, _ = ioCopy(clientConn, upBr); done <- struct{}{} }()
	<-done
	_ = up.Close()
	_ = clientConn.Close()
	<-done
}

// small indirections so the test file needs no extra imports beyond what it has.
func ioCopy(dst interface{ Write([]byte) (int, error) }, src *bufio.Reader) (int64, error) {
	var total int64
	buf := make([]byte, 4096)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return total, werr
			}
			total += int64(n)
		}
		if err != nil {
			return total, err
		}
	}
}

func newTestCtx() interface {
	Deadline() (time.Time, bool)
	Done() <-chan struct{}
	Err() error
	Value(any) any
} {
	return testCtx{}
}

type testCtx struct{}

func (testCtx) Deadline() (time.Time, bool) { return time.Now().Add(5 * time.Second), true }
func (testCtx) Done() <-chan struct{}       { return nil }
func (testCtx) Err() error                  { return nil }
func (testCtx) Value(any) any               { return nil }

var _ = tls.Config{}
