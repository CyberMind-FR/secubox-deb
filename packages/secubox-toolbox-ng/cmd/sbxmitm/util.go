// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
)

func newReader(c net.Conn) *bufio.Reader { return bufio.NewReader(c) }

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
