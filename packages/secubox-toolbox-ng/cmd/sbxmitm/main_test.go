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

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/forge"
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
	ca, err := forge.LoadCA(cp, kp)
	if err != nil {
		t.Fatalf("loadCA: %v", err)
	}
	leaf, err := ca.Forge("ads.example.com")
	if err != nil {
		t.Fatalf("forge: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	if _, err := leaf.Leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "ads.example.com"}); err != nil {
		t.Fatalf("forged leaf does not chain to CA / wrong SAN: %v", err)
	}
	leaf2, _ := ca.Forge("ads.example.com")
	if leaf2 != leaf {
		t.Fatal("forge not cached")
	}
}

// TestLoadCACombinedPEM proves loadCA pulls the right blocks out of a COMBINED
// cert+key bundle — the real shape of mitmproxy's confdir `mitmproxy-ca.pem`,
// which the live R3 CA uses and the worker unit points --ca-key at. mitmproxy
// writes the PRIVATE KEY block first, then the CERTIFICATE; loadCA must scan by
// type, not position.
func TestLoadCACombinedPEM(t *testing.T) {
	dir := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(7),
		Subject:               pkix.Name{CommonName: "Gondwana ToolBoX R3 CA (test)"},
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
	kder, _ := x509.MarshalPKCS8PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	// mitmproxy-ca.pem layout: key THEN cert in one file.
	combined := filepath.Join(dir, "mitmproxy-ca.pem")
	if err := os.WriteFile(combined, append(append([]byte{}, keyPEM...), certPEM...), 0o600); err != nil {
		t.Fatal(err)
	}
	// mitmproxy-ca-cert.pem: cert only.
	certOnly := filepath.Join(dir, "mitmproxy-ca-cert.pem")
	if err := os.WriteFile(certOnly, certPEM, 0o644); err != nil {
		t.Fatal(err)
	}

	// The unit's exact arg shape: --ca-cert <cert-only> --ca-key <combined>.
	ca, err := forge.LoadCA(certOnly, combined)
	if err != nil {
		t.Fatalf("forge.LoadCA(cert-only, combined): %v", err)
	}
	leaf, err := ca.Forge("ads.example.com")
	if err != nil {
		t.Fatalf("forge: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	if _, err := leaf.Leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "ads.example.com"}); err != nil {
		t.Fatalf("forged leaf does not chain to combined-PEM CA: %v", err)
	}
	// Belt-and-braces: the combined file works as BOTH cert and key source.
	if _, err := forge.LoadCA(combined, combined); err != nil {
		t.Fatalf("forge.LoadCA(combined, combined): %v", err)
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
	ca, err := forge.LoadCA(cp, kp)
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
	pool.AddCert(ca.Cert)
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

func TestJA4StackIsSNIIndependent(t *testing.T) {
	h1 := &tls.ClientHelloInfo{SupportedVersions: []uint16{0x0304}, CipherSuites: []uint16{1, 2, 3}, SupportedProtos: []string{"h2"}, ServerName: "a.example"}
	h2 := &tls.ClientHelloInfo{SupportedVersions: []uint16{0x0304}, CipherSuites: []uint16{1, 2, 3}, SupportedProtos: []string{"h2"}, ServerName: "b.example"}
	if ja4stack(h1) != ja4stack(h2) {
		t.Errorf("ja4stack must be SNI-independent: %q vs %q", ja4stack(h1), ja4stack(h2))
	}
	if ja4stack(h1) == ja4ish(h1) {
		t.Error("ja4stack must differ from ja4ish (which embeds SNI)")
	}
	if ja4stack(nil) != "" {
		t.Error("ja4stack(nil) must be empty")
	}
}
