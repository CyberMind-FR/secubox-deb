// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: anti-track fake-identity jar (#662 Phase 4)
//
// Byte-exact port of the Python anti-track HMAC fake-identity jar
// (packages/secubox-toolbox/secubox_toolbox/privacy.py: _jar_key / _shape /
// fake_id). Python is the source of truth; this mirrors it exactly, proven by
// the cross-engine parity harness (testdata/jar-fixtures.json + jar_test.go ↔
// tests/test_jar_parity.py).
//
// The jar mints a STABLE fabricated cookie value per (client, tracker,
// cookie_name): a deterministic HMAC-SHA256 of stable inputs, never derived
// from real client data, identical across workers and restarts ('rémanent').
//
// Pure standard library — no external modules, no go.sum.
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

// loadJarKey reads the seed key file, trimming surrounding whitespace exactly
// like Python's `Path(JAR_KEY_PATH).read_bytes().strip()`.
//
// Returns nil when the file is missing/unreadable OR strips to empty — both of
// which mirror Python's `_jar_key()` returning None (which makes fake_id return
// None / fakeID return ("", false)). Note: strings.TrimSpace and Python's
// bytes.strip() trim the SAME ASCII whitespace set on byte boundaries
// (space, \t, \n, \r, \v=0x0b, \f=0x0c). The canonical key's first/last bytes
// must be non-whitespace, which the test fixture guarantees.
func loadJarKey(path string) []byte {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	// strings.TrimSpace over the byte string trims the same ASCII whitespace
	// bytes Python's bytes.strip() does (it also strips Unicode space runes,
	// but a key file is raw bytes with ASCII-whitespace padding, so the two
	// agree on the edge bytes the fixture uses).
	key := []byte(strings.TrimSpace(string(raw)))
	if len(key) == 0 {
		return nil
	}
	return key
}

// shape renders the HMAC digest into the cookie's observed format so the
// target accepts it. Mirrors privacy._shape EXACTLY:
//
//	n = (name or "").lower()
//	i = int.from_bytes(digest[:8], "big"); j = int.from_bytes(digest[8:16], "big")
//	if n.startswith("_ga"): return "GA1.2.%d.%d" % (i % 1e10, j % 1e10)
//	if n in ("_fbp",):      return "fb.1.%d.%d" % (i % 1e13, j % 1e10)
//	if n in ("uuid","uid","_pk_id") or len(name) >= 32:
//	    h = digest.hex(); return "%s-%s-%s-%s-%s" % (h[:8],h[8:12],h[12:16],h[16:20],h[20:32])
//	return digest.hex()[:32]
//
// Note: Python `len(name)` is the RUNE (character) length, not byte length;
// we use len([]rune(name)) to match. The GA1/fb int math is on a uint64 read
// big-endian from the first/second 8 bytes; every modulus is < 2^64 so the
// Go uint64 computation matches Python's non-negative int, and fmt "%d" of a
// uint64 matches Python's "%d".
func shape(name string, digest []byte) string {
	n := strings.ToLower(name)
	i := binary.BigEndian.Uint64(digest[:8])
	j := binary.BigEndian.Uint64(digest[8:16])
	switch {
	case strings.HasPrefix(n, "_ga"):
		return fmt.Sprintf("GA1.2.%d.%d", i%10_000_000_000, j%10_000_000_000)
	case n == "_fbp":
		return fmt.Sprintf("fb.1.%d.%d", i%10_000_000_000_000, j%10_000_000_000)
	case n == "uuid" || n == "uid" || n == "_pk_id" || len([]rune(name)) >= 32:
		h := hex.EncodeToString(digest)
		return fmt.Sprintf("%s-%s-%s-%s-%s", h[:8], h[8:12], h[12:16], h[16:20], h[20:32])
	default:
		return hex.EncodeToString(digest)[:32]
	}
}

// fakeID returns a stable fabricated cookie value for (clientHash, tracker,
// cookieName). Mirrors privacy.fake_id EXACTLY:
//
//	if not key or not client_hash or not tracker: return None
//	msg = ("%s|%s|%s" % (client_hash, registrable(tracker), cookie_name)).encode()
//	digest = hmac.new(key, msg, sha256).digest()
//	return _shape(cookie_name, digest)
//
// Returns ("", false) for every case where Python returns None: empty key,
// empty clientHash, or empty tracker. registrable() is the Phase-3 port in
// policy.go (shared single source of truth for eTLD+1 folding) — note Python's
// fake_id uses privacy.registrable, which folds subdomains to the registrable
// domain, so two subdomains of the same tracker yield the SAME fake_id.
func fakeID(clientHash, tracker, cookieName string, key []byte) (string, bool) {
	if len(key) == 0 || clientHash == "" || tracker == "" {
		return "", false
	}
	msg := fmt.Sprintf("%s|%s|%s", clientHash, registrable(tracker), cookieName)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(msg))
	digest := mac.Sum(nil)
	return shape(cookieName, digest), true
}
