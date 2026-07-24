// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: sbxmitm — WebSocket upgrade proxying for MITM'd flows.
//
// The MITM pipeline serves a decrypted flow with a manual request/response
// handler (up.Do → resp → write back): an http.Client CANNOT carry a
// "101 Switching Protocols", so any wss:// on a MITM'd host used to hang/fail
// (Socket.IO, zigbee2mqtt, any real-time app behind wg-toolbox). This handles
// the upgrade the way httputil.ReverseProxy does: forward the upgrade request
// to upstream over an http/1.1 connection, relay the 101, then pipe raw bytes
// bidirectionally until either side closes. A spliced host never reaches here —
// its passthrough io.Copy already carried the WebSocket natively.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// isWebSocketUpgrade reports whether req is an HTTP/1.1 WebSocket upgrade:
// `Connection` contains the `upgrade` token (comma list, case-insensitive) AND
// `Upgrade` is `websocket`. Both are required — a stray Upgrade header without
// the Connection token is not a real upgrade.
func isWebSocketUpgrade(req *http.Request) bool {
	if !strings.EqualFold(req.Header.Get("Upgrade"), "websocket") {
		return false
	}
	for _, tok := range strings.Split(req.Header.Get("Connection"), ",") {
		if strings.EqualFold(strings.TrimSpace(tok), "upgrade") {
			return true
		}
	}
	return false
}

// proxyWebSocket carries a WebSocket upgrade across the MITM boundary. It dials
// upstream forcing http/1.1 (a 101 cannot ride h2), writes the upgrade request
// verbatim, and relays the upstream response back over clientConn. On a 101 it
// then pipes raw bytes both ways until either peer closes; on any other status
// it relays the response and returns (no pipe). clientBr is the buffered reader
// already draining clientConn (it may hold client bytes read past the request
// line) — the client→upstream copy MUST read from it, not clientConn, or those
// buffered frames are lost.
func (px *Proxy) proxyWebSocket(clientConn net.Conn, clientBr *bufio.Reader, req *http.Request, target, sni string) {
	ctx, cancel := context.WithTimeout(context.Background(),
		upstreamDialTimeout+upstreamHandshakeTimeout)
	defer cancel()

	up, _, err := dialUChromeALPN(ctx, target, sni, nil, []string{"http/1.1"})
	if err != nil {
		writeRaw(clientConn, 502, "Bad Gateway", nil, nil)
		return
	}
	defer up.Close()

	// Forward the upgrade request verbatim (RequestURI must be empty for Write;
	// Sec-WebSocket-Key/Version and the client headers ride along unchanged so
	// the handshake stays valid).
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
	// Relay the upstream response (status + headers) to the client verbatim.
	if err := resp.Write(clientConn); err != nil {
		resp.Body.Close()
		return
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		// Upstream declined the upgrade — the full response is already relayed.
		resp.Body.Close()
		return
	}
	resp.Body.Close() // 101 has no body; frees the (empty) body reader.

	// 101 Switching Protocols — from here both connections carry opaque WebSocket
	// frames. Pipe until either side closes, then unblock the other by closing.
	// Read via the buffered readers so any frames already buffered past the
	// handshake (upBr after the 101 headers, clientBr after the request) are not
	// dropped. Deadlines are cleared so a long-lived idle socket is not killed.
	_ = clientConn.SetDeadline(time.Time{})
	_ = up.SetDeadline(time.Time{})

	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, clientBr); done <- struct{}{} }()
	go func() { _, _ = io.Copy(clientConn, upBr); done <- struct{}{} }()
	<-done
	// One direction ended (peer closed / errored). Close both so the surviving
	// io.Copy returns and its goroutine exits — no lingering pipe goroutine.
	_ = up.Close()
	_ = clientConn.Close()
	<-done
}

// wsDialTarget mirrors the transport's target/SNI resolution (uchrome.go
// RoundTrip) for the WebSocket path: transparent (dialHost != "") pins the
// captured original-dst with SNI=host; CONNECT (dialHost == "") dials the
// request's own host:port with SNI from the URL.
func wsDialTarget(req *http.Request, dialHost, host string) (target, sni string) {
	if dialHost != "" {
		return dialHost, host
	}
	return canonicalAddr(req.URL), req.URL.Hostname()
}

// interface assertion: tls.Conn satisfies net.Conn (the client side is a
// *tls.Conn from the MITM handshake). Kept as documentation of the contract.
var _ net.Conn = (*tls.Conn)(nil)
