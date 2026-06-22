// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
)

func newReader(c net.Conn) *bufio.Reader { return bufio.NewReader(c) }

// writeResponse serializes an http.Response (status + headers + body) onto a
// (TLS) conn, preserving MULTI-VALUED headers (notably Set-Cookie, which the
// poison path rewrites per-cookie). Hop-by-hop framing headers are dropped and
// replaced with an explicit Content-Length + Connection: close, because we send
// the fully-buffered body.
func writeResponse(c io.Writer, resp *http.Response, body []byte) {
	status := resp.Status
	if status == "" {
		status = fmt.Sprintf("%d", resp.StatusCode)
	}
	fmt.Fprintf(c, "HTTP/1.1 %s\r\n", status)
	for k, vals := range resp.Header {
		switch http.CanonicalHeaderKey(k) {
		case "Content-Length", "Transfer-Encoding", "Connection":
			continue // we set framing ourselves
		}
		for _, v := range vals {
			fmt.Fprintf(c, "%s: %s\r\n", k, v)
		}
	}
	fmt.Fprintf(c, "Content-Length: %d\r\n", len(body))
	fmt.Fprintf(c, "Connection: close\r\n")
	io.WriteString(c, "\r\n")
	if len(body) > 0 {
		c.Write(body)
	}
}

// streamResponse serializes an http.Response by writing its status + headers and
// then STREAMING resp.Body to the conn (io.Copy) — it never buffers the whole
// body in memory. Used for every response we do NOT rewrite (anything but
// 2xx text/html): buffering+capping those was silently truncating large bodies
// (#697 — Gmail messages/attachments/images over the tunnel just stopped
// rendering). The upstream Content-Length is preserved when present (the bytes
// are unchanged); otherwise Connection: close delimits the body. `prefix` holds
// any bytes already consumed from resp.Body by a caller peek (streamed first).
func streamResponse(c io.Writer, resp *http.Response, prefix []byte) {
	status := resp.Status
	if status == "" {
		status = fmt.Sprintf("%d", resp.StatusCode)
	}
	fmt.Fprintf(c, "HTTP/1.1 %s\r\n", status)
	for k, vals := range resp.Header {
		switch http.CanonicalHeaderKey(k) {
		case "Transfer-Encoding", "Connection":
			continue // body is de-chunked by ReadResponse; we close the conn ourselves
		}
		for _, v := range vals {
			fmt.Fprintf(c, "%s: %s\r\n", k, v)
		}
	}
	fmt.Fprintf(c, "Connection: close\r\n")
	io.WriteString(c, "\r\n")
	if len(prefix) > 0 {
		c.Write(prefix)
	}
	io.Copy(c, resp.Body)
}

// writeRaw writes a minimal HTTP/1.1 response onto a (TLS) conn.
func writeRaw(c io.Writer, code int, status string, headers map[string]string, body []byte) {
	if status == "" {
		status = "OK"
	}
	fmt.Fprintf(c, "HTTP/1.1 %d %s\r\n", code, status)
	fmt.Fprintf(c, "Content-Length: %d\r\n", len(body))
	fmt.Fprintf(c, "Connection: close\r\n")
	for k, v := range headers {
		if v != "" {
			fmt.Fprintf(c, "%s: %s\r\n", k, v)
		}
	}
	io.WriteString(c, "\r\n")
	if len(body) > 0 {
		c.Write(body)
	}
}
