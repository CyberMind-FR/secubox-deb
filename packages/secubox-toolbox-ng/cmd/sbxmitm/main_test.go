// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// genTestCA writes a self-signed CA (cert+key PEM) to dir, mirroring ca-wg.
func genTestCA(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "SecuBox Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	certPath = filepath.Join(dir, "ca.pem")
	keyPath = filepath.Join(dir, "key.pem")
	cf, _ := os.Create(certPath)
	pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	cf.Close()
	kder, _ := x509.MarshalPKCS8PrivateKey(key)
	kf, _ := os.Create(keyPath)
	pem.Encode(kf, &pem.Block{Type: "PRIVATE KEY", Bytes: kder})
	kf.Close()
	return certPath, keyPath
}

func TestForgeChainsToCA(t *testing.T) {
	cp, kp := genTestCA(t, t.TempDir())
	ca, err := loadCA(cp, kp)
	if err != nil {
		t.Fatalf("loadCA: %v", err)
	}
	leaf, err := ca.forge("ads.example.com")
	if err != nil {
		t.Fatalf("forge: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	if _, err := leaf.Leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "ads.example.com"}); err != nil {
		t.Fatalf("forged leaf does not chain to CA / wrong SAN: %v", err)
	}
	leaf2, _ := ca.forge("ads.example.com")
	if leaf2 != leaf {
		t.Fatal("forge not cached")
	}
}

// NOTE (#662 Phase 3): the old TestActionDecision drove the removed hardcoded
// Policy{AdHosts, SpliceHosts} fields. The decision surface now loads from
// disk (LoadPolicy) and mirrors the Python addons; coverage moved to
// TestParityDecide / TestPolicyActionVerbs in policy_test.go.

func TestInjectMarker(t *testing.T) {
	p := &Policy{Inject: []byte("<!--SBX-->")}
	out := string(p.injectMarker([]byte("<html><head></head><body>hi</body></html>")))
	if !contains(out, "<!--SBX--></head>") {
		t.Fatalf("marker not injected before </head>: %s", out)
	}
	if string(p.injectMarker([]byte(out))) != out {
		t.Fatal("inject not idempotent")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// TestClientHelloCaptureAndForge: a real localhost TLS handshake proves the Go
// core forges a per-SNI cert from the CA that the client trusts AND that the
// ClientHello (JA4 material) is captured.
func TestClientHelloCaptureAndForge(t *testing.T) {
	cp, kp := genTestCA(t, t.TempDir())
	ca, err := loadCA(cp, kp)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var captured string
	px := &Proxy{ca: ca, jaSink: func(s string) { mu.Lock(); captured = s; mu.Unlock() }}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		s := tls.Server(c, px.serverTLSConfig())
		s.Handshake()
		s.Close()
	}()

	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{ServerName: "example.com", RootCAs: pool})
	if err != nil {
		t.Fatalf("client handshake against forged cert failed (CA not trusted / forge broken): %v", err)
	}
	conn.Close()

	mu.Lock()
	defer mu.Unlock()
	if captured == "" {
		t.Fatal("ClientHello not captured")
	}
	if !contains(captured, "sni=example.com") {
		t.Fatalf("JA4 capture missing SNI: %q", captured)
	}
	t.Logf("captured JA4-ish: %s", captured)
}
