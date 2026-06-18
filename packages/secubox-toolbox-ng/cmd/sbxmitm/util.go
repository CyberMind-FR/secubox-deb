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
