// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: forge — CA + per-host leaf cert forging
//
// Extracted from cmd/sbxmitm so that a future cmd/sbxwaf can reuse the same
// primitives. Behaviour is identical to the original: forge a per-host TLS
// leaf cert signed by the CA, cached by lowercased hostname.
package forge

import (
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"strings"
	"sync"
	"time"
)

// CA holds the loaded forging CA (reused from ca-wg) + a per-host leaf cache.
type CA struct {
	// Cert is the CA certificate (exported so callers can build a trust pool
	// for verification — e.g. in tests and the sbxwaf TLS config).
	Cert  *x509.Certificate
	key   crypto.Signer
	mu    sync.Mutex
	cache map[string]*tls.Certificate
}

// LoadCA reads a CA cert and key from PEM files (certPath, keyPath).
// Both files may be combined cert+key bundles (e.g. mitmproxy-ca.pem with
// PRIVATE KEY first then CERTIFICATE); LoadCA scans by block Type.
func LoadCA(certPath, keyPath string) (*CA, error) {
	cpem, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read ca cert: %w", err)
	}
	kpem, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read ca key: %w", err)
	}
	// Scan for the right block TYPE rather than assuming position: the live R3
	// CA the toolbox forges with (mitmproxy confdir `mitmproxy-ca.pem`) is a
	// COMBINED cert+key bundle, and --ca-key may point at it. Tolerate cert and
	// key co-residing in either file, in any order.
	cblk := firstPEMBlock(cpem, func(b *pem.Block) bool { return b.Type == "CERTIFICATE" })
	if cblk == nil {
		return nil, fmt.Errorf("ca cert: no CERTIFICATE PEM block")
	}
	cert, err := x509.ParseCertificate(cblk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse ca cert: %w", err)
	}
	kblk := firstPEMBlock(kpem, func(b *pem.Block) bool { return strings.Contains(b.Type, "PRIVATE KEY") })
	if kblk == nil {
		return nil, fmt.Errorf("ca key: no PRIVATE KEY PEM block")
	}
	key, err := parseKey(kblk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse ca key: %w", err)
	}
	return &CA{Cert: cert, key: key, cache: map[string]*tls.Certificate{}}, nil
}

// firstPEMBlock returns the first PEM block in data satisfying want, or nil.
// Used to pull a specific block (CERTIFICATE / PRIVATE KEY) out of a file that
// may hold several (e.g. mitmproxy's combined CA bundle).
func firstPEMBlock(data []byte, want func(*pem.Block) bool) *pem.Block {
	for {
		blk, rest := pem.Decode(data)
		if blk == nil {
			return nil
		}
		if want(blk) {
			return blk
		}
		data = rest
	}
}

func parseKey(der []byte) (crypto.Signer, error) {
	if k, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		if s, ok := k.(crypto.Signer); ok {
			return s, nil
		}
	}
	if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return k, nil
	}
	if k, err := x509.ParseECPrivateKey(der); err == nil {
		return k, nil
	}
	return nil, fmt.Errorf("unsupported CA key format")
}

// Forge returns a leaf cert for host signed by the CA, cached by lowercased
// hostname. The leaf is valid for 365 days forward with a 48-hour back-skew
// (safely under Apple's 398-day max-validity rule) so it outlives the
// non-evicting cache and never goes stale under long-running workers (#689).
func (c *CA) Forge(host string) (*tls.Certificate, error) {
	host = strings.ToLower(strings.TrimSpace(host))
	c.mu.Lock()
	if tc, ok := c.cache[host]; ok {
		c.mu.Unlock()
		return tc, nil
	}
	c.mu.Unlock()

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		// #689 — forged leaves must outlive the (non-evicting) cert cache, else a
		// long-running worker keeps serving an expired leaf and every client
		// reports "certificat expiré". 365d forward + 48h back-skew = 367d span,
		// safely under Apple's 398-day max-validity rule for server certs.
		NotBefore:    time.Now().Add(-48 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{host},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.Cert, c.key.Public(), c.key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der) // parsed cert has Raw populated (Verify needs it)
	if err != nil {
		return nil, err
	}
	tc := &tls.Certificate{Certificate: [][]byte{der, c.Cert.Raw}, PrivateKey: c.key, Leaf: leaf}
	c.mu.Lock()
	c.cache[host] = tc
	c.mu.Unlock()
	return tc, nil
}
