// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: h2-over-uTLS dispatch test (#662)
//
// Proves the negotiated-protocol dispatch: when the origin ALPN-negotiates h2,
// the transport speaks HTTP/2 over the established uTLS conn (via x/net/http2),
// not HTTP/1.1. The h1 path is covered in uchrome_test.go.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"testing"

	"golang.org/x/net/http2"
)

func TestUChromeNegotiatesH2(t *testing.T) {
	cert, leaf := genLeafCert(t, "h2.test")
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2"}, // origin offers ONLY h2
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	h2s := &http2.Server{}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			tc := c.(*tls.Conn)
			if err := tc.Handshake(); err != nil {
				c.Close()
				continue
			}
			go h2s.ServeConn(tc, &http2.ServeConnOpts{
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					io.WriteString(w, "h2-body")
				}),
			})
		}
	}()

	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	tr := newUchromeTransport(ln.Addr().String(), "h2.test")
	tr.rootCAs = pool

	req, _ := http.NewRequest("GET", "https://h2.test/", nil)
	req.RequestURI = ""
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("h2 round-trip must succeed: %v", err)
	}
	defer resp.Body.Close()
	if resp.ProtoMajor != 2 {
		t.Fatalf("expected the transport to speak HTTP/2, got %s", resp.Proto)
	}
	b, _ := io.ReadAll(resp.Body)
	if string(b) != "h2-body" {
		t.Fatalf("h2 body mismatch: got %q", b)
	}
}
