// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// #662 Phase 2b — controlled multi-core throughput bench. Drives full client↔
// proxy TLS handshakes (forge + ClientHello capture) in parallel. Run with
// `-cpu=1,2,4,8` to SHOW the scaling Python mitmproxy's GIL cannot do:
//   go test -run x -bench BenchmarkHandshake -benchmem -cpu=1,2,4,8 ./cmd/sbxmitm
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
	"testing"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/forge"
)

func benchCA(b *testing.B) (string, string) {
	b.Helper()
	dir := b.TempDir()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Bench CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	cp := filepath.Join(dir, "ca.pem")
	kp := filepath.Join(dir, "key.pem")
	cf, _ := os.Create(cp)
	pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	cf.Close()
	kder, _ := x509.MarshalPKCS8PrivateKey(key)
	kf, _ := os.Create(kp)
	pem.Encode(kf, &pem.Block{Type: "PRIVATE KEY", Bytes: kder})
	kf.Close()
	return cp, kp
}

// BenchmarkHandshake: steady-state forged-cert TLS handshakes/sec under parallel
// load (warm forge cache). req/s should rise ~linearly with -cpu (no GIL).
func BenchmarkHandshake(b *testing.B) {
	cp, kp := benchCA(b)
	ca, err := forge.LoadCA(cp, kp)
	if err != nil {
		b.Fatal(err)
	}
	px := &Proxy{ca: ca}
	if _, err := ca.Forge("example.com"); err != nil { // warm cache
		b.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer ln.Close()
	cfg := px.serverTLSConfig()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				s := tls.Server(c, cfg)
				s.Handshake()
				s.Close()
			}()
		}
	}()
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	addr := ln.Addr().String()
	ccfg := &tls.Config{ServerName: "example.com", RootCAs: pool, MinVersion: tls.VersionTLS12}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			conn, err := tls.Dial("tcp", addr, ccfg)
			if err != nil {
				b.Error(err)
				return
			}
			conn.Close()
		}
	})
}
