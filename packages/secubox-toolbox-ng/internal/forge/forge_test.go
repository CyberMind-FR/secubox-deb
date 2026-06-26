// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: forge package tests
package forge

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeTestCA mints a self-signed CA and writes cert+key PEMs to dir.
// Returns (certPath, keyPath).
func writeTestCA(t *testing.T, dir string) (certPath, keyPath string) {
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

func TestForgeChainsAndCaches(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeTestCA(t, dir) // helper mints a CA, writes PEMs
	ca, err := LoadCA(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}
	c1, err := ca.Forge("example.com")
	if err != nil {
		t.Fatalf("Forge: %v", err)
	}
	if c1.Leaf.DNSNames[0] != "example.com" {
		t.Fatalf("CN/SAN wrong: %v", c1.Leaf.DNSNames)
	}
	c2, _ := ca.Forge("example.com")
	if c1 != c2 {
		t.Fatalf("Forge not cached")
	}
}

// TestForgeChainsToCA verifies the leaf cert chains to the CA.
func TestForgeChainsToCA(t *testing.T) {
	cp, kp := writeTestCA(t, t.TempDir())
	ca, err := LoadCA(cp, kp)
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}
	leaf, err := ca.Forge("ads.example.com")
	if err != nil {
		t.Fatalf("Forge: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	if _, err := leaf.Leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "ads.example.com"}); err != nil {
		t.Fatalf("forged leaf does not chain to CA / wrong SAN: %v", err)
	}
}

// TestLoadCACombinedPEM proves LoadCA pulls the right blocks out of a COMBINED
// cert+key bundle — the real shape of mitmproxy's confdir `mitmproxy-ca.pem`.
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
	ca, err := LoadCA(certOnly, combined)
	if err != nil {
		t.Fatalf("LoadCA(cert-only, combined): %v", err)
	}
	leaf, err := ca.Forge("ads.example.com")
	if err != nil {
		t.Fatalf("Forge: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	if _, err := leaf.Leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "ads.example.com"}); err != nil {
		t.Fatalf("forged leaf does not chain to combined-PEM CA: %v", err)
	}
	// Belt-and-braces: the combined file works as BOTH cert and key source.
	if _, err := LoadCA(combined, combined); err != nil {
		t.Fatalf("LoadCA(combined, combined): %v", err)
	}
}
