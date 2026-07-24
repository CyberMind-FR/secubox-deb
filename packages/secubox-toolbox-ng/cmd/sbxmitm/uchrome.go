// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: uTLS Chrome upstream transport (#662)
//
// The live R3 engine MITM-terminates the client, then makes its OWN upstream TLS
// connection to the real origin. With the stdlib crypto/tls that upstream
// handshake carries a Go ClientHello whose JA3/JA4 fingerprint is trivially
// distinguishable from a browser — DataDome / anti-bot vendors block it outright,
// breaking every site behind them for R3 users.
//
// This transport replaces the upstream crypto/tls handshake with uTLS
// (github.com/refraction-networking/utls) presenting a recent Chrome
// ClientHello (HelloChrome_Auto), WITHOUT resorting to TLS splice (so the body
// is still fully inspectable: ad-block / banner / anti-track all keep working).
//
// SECURITY BOUNDARY — UNCHANGED:
//   - The upstream cert chain is STILL verified against the system roots + the
//     SNI/Host ServerName. We set cfg.InsecureSkipVerify=true ONLY because uTLS's
//     ClientHello presets force their own verification off; we IMMEDIATELY do the
//     full chain + hostname verification ourselves after the handshake and FAIL
//     the connection on any verify error. There is NO net weakening: a bad or
//     mismatched cert is rejected exactly as crypto/tls would reject it.
//
// DIAL PINNING — UNCHANGED:
//   - TRANSPARENT: the TCP dial is pinned to the captured original-dst (ip:port);
//     we do NOT resolve/redirect to the SNI host. TLS ServerName + verification
//     still use the SNI host (validated by hostname, not the bare IP).
//   - CONNECT: the TCP dial is the request host:port.
//
// ALPN: we offer what Chrome offers (h2, http/1.1). After the handshake we speak
// the NEGOTIATED protocol: h2 → golang.org/x/net/http2 over the established uTLS
// conn; otherwise HTTP/1.1 via the stdlib. This keeps the wire fingerprint
// Chrome-shaped AND the protocol correct.
//
// Pure-Go, cgo-free: utls + x/net/http2 are all CGO_ENABLED=0 clean.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

// chromeHello is the uTLS ClientHelloID presented on every upstream handshake.
// HelloChrome_Auto tracks uTLS's most recent stable Chrome preset, so the
// JA3/JA4 we emit matches a current Chrome without us pinning a version that
// rots. Documented here so the choice is greppable.
var chromeHello = utls.HelloChrome_Auto

// upstreamDialTimeout / upstreamHandshakeTimeout bound the upstream TCP + TLS
// setup so a black-holed origin can't pin a worker goroutine.
const (
	upstreamDialTimeout      = 10 * time.Second
	upstreamHandshakeTimeout = 10 * time.Second
	// upstreamResponseTimeout bounds write-request + read-response-HEADERS on the
	// HTTP/1.1 path (mirrors stdlib http.Transport.ResponseHeaderTimeout): without
	// it, an origin that completes TLS then never replies pins a worker goroutine
	// forever. Cleared before body streaming so large/slow downloads aren't cut.
	upstreamResponseTimeout = 30 * time.Second
)

// uchromeTransport is an http.RoundTripper that, for every request, opens a
// fresh uTLS Chrome-fingerprinted connection to the target, verifies the cert
// chain against the system roots + ServerName, then speaks the ALPN-negotiated
// protocol (h2 or http/1.1) over it.
//
// dialAddr pins the TCP destination:
//   - "" → CONNECT semantics: dial req.URL.Host (the request's own host:port).
//   - non-"" → transparent: dial this captured original-dst ip:port for EVERY
//     request regardless of req.URL.Host.
//
// sni is the ServerName used for the ClientHello SNI extension AND certificate
// hostname verification. For CONNECT it is the request host; for transparent it
// is the SNI captured off the original ClientHello.
//
// rootCAs overrides the verification roots when non-nil (tests inject a test
// CA). nil → the system roots (production).
//
// Connections are NOT pooled: a MITM worker handles one client request/response
// then tears the upstream down (the existing stdlib path did the same via a
// per-request http.Client with Connection: close). This keeps fd usage bounded
// and avoids cross-origin conn reuse hazards. Each RoundTrip closes its conn
// when the response body is fully consumed.
type uchromeTransport struct {
	dialAddr string
	sni      string
	rootCAs  *x509.CertPool // nil → system roots
}

// newUchromeTransport builds a uchromeTransport. dialAddr "" selects CONNECT
// (dial req.URL.Host); non-"" pins the transparent original-dst. sni is the
// ServerName for SNI + verification.
func newUchromeTransport(dialAddr, sni string) *uchromeTransport {
	return &uchromeTransport{dialAddr: dialAddr, sni: sni}
}

// dialUChrome opens a TCP connection to target, wraps it in a uTLS Chrome
// ClientHello with ServerName=sni, completes the handshake, then performs FULL
// certificate verification (chain to rootCAs/system roots + hostname=sni). On
// any error the connection is closed and the error returned — a bad/mismatched
// cert is REJECTED, never used. Returns the live uTLS conn and the negotiated
// ALPN protocol ("h2", "http/1.1", or "").
func dialUChrome(ctx context.Context, target, sni string, rootCAs *x509.CertPool) (*utls.UConn, string, error) {
	// Default ALPN mirrors what Chrome offers (h2 preferred, http/1.1 fallback).
	return dialUChromeALPN(ctx, target, sni, rootCAs, []string{"h2", "http/1.1"})
}

// dialUChromeALPN is dialUChrome with an explicit ALPN offer. A WebSocket
// upgrade is HTTP/1.1 semantics (Connection: Upgrade), so the WS path forces
// []string{"http/1.1"} — negotiating h2 upstream would make the 101 handshake
// impossible. Every other property (Chrome ClientHello, manual verification,
// timeouts) is identical.
func dialUChromeALPN(ctx context.Context, target, sni string, rootCAs *x509.CertPool, alpn []string) (*utls.UConn, string, error) {
	d := &net.Dialer{Timeout: upstreamDialTimeout}
	raw, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		return nil, "", fmt.Errorf("dial %s: %w", target, err)
	}

	// InsecureSkipVerify is set ONLY to take uTLS's automatic verification out of
	// the path; we run the exact stdlib verification ourselves below and reject
	// on failure, so the trust boundary is identical to crypto/tls. NextProtos
	// mirrors what Chrome offers so the negotiated protocol (and the offered ALPN
	// list in the fingerprint) is browser-shaped.
	cfg := &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, // we verify manually below — NOT a weakening
		NextProtos:         alpn,
		RootCAs:            rootCAs, // nil → uTLS uses system roots in our manual check
	}
	uconn := utls.UClient(raw, cfg, chromeHello)

	// Bound the handshake; UClient has no built-in deadline.
	if dl, ok := ctx.Deadline(); ok {
		_ = uconn.SetDeadline(dl)
	} else {
		_ = uconn.SetDeadline(time.Now().Add(upstreamHandshakeTimeout))
	}
	if err := uconn.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, "", fmt.Errorf("utls handshake %s (sni=%s): %w", target, sni, err)
	}
	// Clear the handshake deadline; per-request I/O timeouts are handled by the
	// caller's context / http client.
	_ = uconn.SetDeadline(time.Time{})

	// ── manual chain + hostname verification (the preserved security boundary) ──
	if err := verifyUConn(uconn, sni, rootCAs); err != nil {
		uconn.Close()
		return nil, "", err
	}

	return uconn, uconn.ConnectionState().NegotiatedProtocol, nil
}

// verifyUConn performs the full certificate verification crypto/tls would have
// done with InsecureSkipVerify=false: build the chain from the presented certs
// up to roots, checking validity + the ServerName against the leaf's SANs. roots
// nil → the host's system roots. Any failure → error (caller closes the conn).
func verifyUConn(uconn *utls.UConn, serverName string, roots *x509.CertPool) error {
	cs := uconn.ConnectionState()
	if len(cs.PeerCertificates) == 0 {
		return fmt.Errorf("utls verify: no peer certificates from %q", serverName)
	}
	opts := x509.VerifyOptions{
		Roots:         roots, // nil → system roots
		DNSName:       serverName,
		Intermediates: x509.NewCertPool(),
	}
	for _, c := range cs.PeerCertificates[1:] {
		opts.Intermediates.AddCert(c)
	}
	if _, err := cs.PeerCertificates[0].Verify(opts); err != nil {
		return fmt.Errorf("utls verify %q: %w", serverName, err)
	}
	return nil
}

// RoundTrip implements http.RoundTripper. It dials a fresh Chrome-fingerprinted,
// verified upstream conn, then dispatches on the negotiated ALPN protocol.
func (t *uchromeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	target := t.dialAddr
	if target == "" {
		// CONNECT semantics: dial the request's own host:port.
		target = canonicalAddr(req.URL)
	}
	sni := t.sni
	if sni == "" {
		sni = req.URL.Hostname()
	}

	ctx := req.Context()
	uconn, proto, err := dialUChrome(ctx, target, sni, t.rootCAs)
	if err != nil {
		return nil, err
	}

	if proto == "h2" {
		return t.roundTripH2(uconn, req)
	}
	return roundTripH1(uconn, req)
}

// roundTripH2 speaks HTTP/2 over the already-established, verified uTLS conn by
// handing it to an http2.Transport as a pre-dialed connection. The conn is owned
// by the http2 transport thereafter (it closes it when done). A fresh
// single-use http2.Transport per request keeps fingerprint + fd lifetime simple
// and avoids cross-request conn reuse.
func (t *uchromeTransport) roundTripH2(uconn *utls.UConn, req *http.Request) (*http.Response, error) {
	tr := &http2.Transport{
		// We hand it the already-handshaked conn; it must not re-dial or
		// re-handshake. AllowHTTP stays false: this IS a TLS conn.
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			return uconn, nil
		},
		DisableCompression: true, // we relay Accept-Encoding verbatim; let the origin compress
	}
	resp, err := tr.RoundTrip(req)
	if err != nil {
		uconn.Close()
		return nil, err
	}
	// Closing the response body closes the underlying conn (http2 owns it). Wrap
	// the body so the transport is torn down with it (no fd leak, no pooling).
	resp.Body = &h2BodyCloser{ReadCloser: resp.Body, tr: tr}
	return resp, nil
}

// h2BodyCloser closes the single-use http2.Transport (and thus the uTLS conn)
// when the response body is closed, so a per-request transport never leaks.
type h2BodyCloser struct {
	io.ReadCloser
	tr   *http2.Transport
	once sync.Once
}

func (b *h2BodyCloser) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(b.tr.CloseIdleConnections)
	return err
}

// roundTripH1 speaks HTTP/1.1 over the established uTLS conn by writing the
// request and reading the response with the stdlib. The response body is wrapped
// so that closing it closes the conn — single-use, no pooling, no fd leak.
func roundTripH1(uconn *utls.UConn, req *http.Request) (*http.Response, error) {
	// Bound write-request + read-response-HEADERS: an origin that completes the
	// TLS handshake then stalls would otherwise pin this goroutine forever
	// (the http.Client.Timeout in the caller does NOT reach a custom
	// RoundTripper's raw conn I/O). Honour the request context deadline if it is
	// sooner; clear the deadline before returning so body STREAMING isn't capped.
	deadline := time.Now().Add(upstreamResponseTimeout)
	if d, ok := req.Context().Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = uconn.SetDeadline(deadline)
	// Write the request over the conn. req.Write emits a valid origin-form
	// HTTP/1.1 request (RequestURI was cleared by the caller).
	if err := req.Write(uconn); err != nil {
		uconn.Close()
		return nil, fmt.Errorf("utls h1 write: %w", err)
	}
	resp, err := http.ReadResponse(newReader(uconn), req)
	if err != nil {
		uconn.Close()
		return nil, fmt.Errorf("utls h1 read: %w", err)
	}
	_ = uconn.SetDeadline(time.Time{}) // headers in: don't cap body streaming
	resp.Body = &h1BodyCloser{ReadCloser: resp.Body, conn: uconn}
	return resp, nil
}

// h1BodyCloser closes the underlying uTLS conn when the response body is closed.
type h1BodyCloser struct {
	io.ReadCloser
	conn net.Conn
	once sync.Once
}

func (b *h1BodyCloser) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(func() { b.conn.Close() })
	return err
}

// canonicalAddr returns the host:port to dial for a URL, defaulting the port to
// 443 (the only scheme this MITM upstream ever speaks is https).
func canonicalAddr(u *url.URL) string {
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "443"
	}
	return net.JoinHostPort(host, port)
}
