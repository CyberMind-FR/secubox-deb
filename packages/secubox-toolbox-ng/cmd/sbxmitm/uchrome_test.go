// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: uTLS Chrome upstream transport tests (#662)
//
// Proves the upstream transport (1) presents a Chrome ClientHello, (2) completes
// an HTTP round-trip when the origin cert is TRUSTED, and (3) REJECTS — errors,
// no plaintext — when the cert is untrusted or the ServerName mismatches, so the
// certificate-verification security boundary is demonstrably still ON.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

// genLeafCert returns a self-signed leaf cert+key valid for the given DNS names,
// plus the cert as an *x509.Certificate (to seed a RootCAs pool — self-signed,
// so it is its own root). nextProtos sets the server ALPN offer.
func genLeafCert(t *testing.T, names ...string) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: names[0]},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true, // self-signed root for the test pool
		DNSNames:              names,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, leaf
}

// startTLSServer spins a localhost TLS server presenting cert and serving a
// fixed body on every request. It returns the listener address and a cleanup.
// nextProtos controls the server's ALPN (e.g. {"http/1.1"} or {"h2","http/1.1"}).
func startTLSServer(t *testing.T, cert tls.Certificate, body string, nextProtos []string) (addr string, cleanup func()) {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   nextProtos,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, body)
		}),
	}
	go srv.Serve(ln)
	return ln.Addr().String(), func() { srv.Close() }
}

// TestUChromeTrustedCertRoundTrips: a server whose self-signed cert is in the
// transport's RootCAs pool, with the SNI matching a SAN, completes a full HTTP
// round-trip — proving verification PASSES on a trusted, matching cert.
func TestUChromeTrustedCertRoundTrips(t *testing.T) {
	cert, leaf := genLeafCert(t, "origin.test")
	addr, cleanup := startTLSServer(t, cert, "hello-from-origin", []string{"http/1.1"})
	defer cleanup()

	pool := x509.NewCertPool()
	pool.AddCert(leaf)

	tr := newUchromeTransport(addr, "origin.test")
	tr.rootCAs = pool

	req, _ := http.NewRequest("GET", "https://origin.test/", nil)
	req.RequestURI = ""
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("trusted-cert round-trip must succeed: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if string(b) != "hello-from-origin" {
		t.Fatalf("body mismatch: got %q", b)
	}
}

// TestUChromeUntrustedCertRejected: the server cert is NOT in the transport's
// RootCAs pool → verification MUST fail; no response, no plaintext leaks.
func TestUChromeUntrustedCertRejected(t *testing.T) {
	cert, _ := genLeafCert(t, "origin.test")
	addr, cleanup := startTLSServer(t, cert, "SECRET-SHOULD-NOT-LEAK", []string{"http/1.1"})
	defer cleanup()

	// Empty pool: the self-signed origin cert chains to nothing trusted.
	tr := newUchromeTransport(addr, "origin.test")
	tr.rootCAs = x509.NewCertPool()

	req, _ := http.NewRequest("GET", "https://origin.test/", nil)
	req.RequestURI = ""
	resp, err := tr.RoundTrip(req)
	if err == nil {
		if resp != nil {
			resp.Body.Close()
		}
		t.Fatal("untrusted cert MUST be rejected (verification is the security boundary)")
	}
	if !strings.Contains(err.Error(), "verify") {
		t.Logf("rejected (not a verify-tagged error, still rejected): %v", err)
	}
}

// TestUChromeHostnameMismatchRejected: the cert is trusted (in the pool) but its
// SAN does NOT cover the SNI we verify against → hostname verification MUST fail.
func TestUChromeHostnameMismatchRejected(t *testing.T) {
	cert, leaf := genLeafCert(t, "origin.test") // SAN = origin.test only
	addr, cleanup := startTLSServer(t, cert, "SECRET", []string{"http/1.1"})
	defer cleanup()

	pool := x509.NewCertPool()
	pool.AddCert(leaf)

	// Verify against a DIFFERENT name the cert does not cover.
	tr := newUchromeTransport(addr, "evil.test")
	tr.rootCAs = pool

	req, _ := http.NewRequest("GET", "https://evil.test/", nil)
	req.RequestURI = ""
	resp, err := tr.RoundTrip(req)
	if err == nil {
		if resp != nil {
			resp.Body.Close()
		}
		t.Fatal("ServerName mismatch MUST be rejected")
	}
}

// TestUChromeHelloIsChrome asserts the transport uses a Chrome ClientHelloID
// (the JA3/JA4 win). We assert the package-level chromeHello is one of uTLS's
// Chrome presets — at minimum that HelloChrome is the client family used.
func TestUChromeHelloIsChrome(t *testing.T) {
	if !strings.HasPrefix(chromeHello.Client, "Chrome") {
		t.Fatalf("upstream ClientHelloID must be a Chrome preset, got Client=%q", chromeHello.Client)
	}
	// HelloChrome_Auto is the intended preset (tracks latest stable Chrome).
	if chromeHello != utls.HelloChrome_Auto {
		t.Logf("note: chromeHello is %v (not HelloChrome_Auto)", chromeHello)
	}
}

// TestDialUChromeContextCancelled: a cancelled context fails the dial cleanly
// (no hang, no fd leak panic), exercising the timeout/cancel path.
func TestDialUChromeContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// 203.0.113.0/24 (TEST-NET-3) is non-routable; the cancelled ctx short-circuits.
	_, _, err := dialUChrome(ctx, net.JoinHostPort("203.0.113.1", "443"), "x.test", x509.NewCertPool())
	if err == nil {
		t.Fatal("cancelled context must fail the dial")
	}
}
