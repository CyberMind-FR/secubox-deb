// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// Cross-engine JAR parity harness — Go side (#662 Phase 4).
//
// Loads testdata/jar-fixtures.json + the fixed test key (testdata/jar-test.key,
// NOT the real /etc key), computes fakeID per fixture, and asserts == the
// fixture's expect. The Python side (../secubox-toolbox/tests/test_jar_parity.py)
// loads the SAME files and drives privacy.fake_id; both must agree → the HMAC
// fake-identity jar is byte-exact across engines. Python is the source of truth.
package main

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type jarFixture struct {
	Client     string `json:"client"`
	Tracker    string `json:"tracker"`
	CookieName string `json:"cookie_name"`
	Expect     string `json:"expect"`
	Why        string `json:"why"`
}

type jarFile struct {
	KeyFile  string       `json:"key_file"`
	KeyHex   string       `json:"key_hex"`
	Fixtures []jarFixture `json:"fixtures"`
}

func loadJarFile(t *testing.T) (jarFile, string) {
	t.Helper()
	dir := testdataDir(t) // shared with policy_test.go (cmd/sbxmitm → ../../testdata)
	raw, err := os.ReadFile(filepath.Join(dir, "jar-fixtures.json"))
	if err != nil {
		t.Fatalf("read jar fixtures: %v", err)
	}
	var jf jarFile
	if err := json.Unmarshal(raw, &jf); err != nil {
		t.Fatalf("parse jar fixtures: %v", err)
	}
	if len(jf.Fixtures) == 0 {
		t.Fatal("no jar fixtures")
	}
	return jf, dir
}

// TestJarKeyLoad: loadJarKey strips the file's surrounding whitespace back to
// the canonical key declared in key_hex (proves .strip()/TrimSpace parity).
func TestJarKeyLoad(t *testing.T) {
	jf, dir := loadJarFile(t)
	key := loadJarKey(filepath.Join(dir, jf.KeyFile))
	if key == nil {
		t.Fatal("loadJarKey returned nil")
	}
	want, err := hex.DecodeString(jf.KeyHex)
	if err != nil {
		t.Fatalf("bad key_hex: %v", err)
	}
	if hex.EncodeToString(key) != hex.EncodeToString(want) {
		t.Fatalf("loaded key %x != canonical %x", key, want)
	}
}

// TestJarParity: fakeID == Python-generated expect for every fixture.
func TestJarParity(t *testing.T) {
	jf, dir := loadJarFile(t)
	key := loadJarKey(filepath.Join(dir, jf.KeyFile))
	if key == nil {
		t.Fatal("loadJarKey returned nil — cannot run parity")
	}
	for _, fx := range jf.Fixtures {
		got, ok := fakeID(fx.Client, fx.Tracker, fx.CookieName, key)
		if !ok {
			t.Errorf("fakeID(%q,%q,%q) returned !ok (%s)", fx.Client, fx.Tracker, fx.CookieName, fx.Why)
			continue
		}
		if got != fx.Expect {
			t.Errorf("fakeID(%q,%q,%q)=%q want %q  (%s)",
				fx.Client, fx.Tracker, fx.CookieName, got, fx.Expect, fx.Why)
		}
	}
}

// TestJarShapeCoverage: the fixtures must exercise every _shape branch, else
// "parity" is vacuous for an untested branch.
func TestJarShapeCoverage(t *testing.T) {
	jf, _ := loadJarFile(t)
	var sawGA, sawFB, sawUUID, sawHex bool
	for _, fx := range jf.Fixtures {
		switch {
		case len(fx.Expect) >= 4 && fx.Expect[:4] == "GA1.":
			sawGA = true
		case len(fx.Expect) >= 3 && fx.Expect[:3] == "fb.":
			sawFB = true
		case len(fx.Expect) == 36 && fx.Expect[8] == '-':
			sawUUID = true
		case len(fx.Expect) == 32:
			sawHex = true
		}
	}
	if !sawGA || !sawFB || !sawUUID || !sawHex {
		t.Fatalf("shape coverage incomplete: GA=%v FB=%v UUID=%v HEX=%v", sawGA, sawFB, sawUUID, sawHex)
	}
}

// TestJarFolding: two subdomains of the same registrable tracker, same client &
// cookie name, mint the IDENTICAL fake id (registrable() folding).
func TestJarFolding(t *testing.T) {
	jf, dir := loadJarFile(t)
	key := loadJarKey(filepath.Join(dir, jf.KeyFile))
	a, _ := fakeID("foldclient", "px.doubleclick.net", "uid", key)
	b, _ := fakeID("foldclient", "ads.doubleclick.net", "uid", key)
	if a == "" || a != b {
		t.Fatalf("folding broken: px=%q ads=%q", a, b)
	}
}

// TestJarNilCases: fakeID returns ("",false) exactly where Python returns None.
func TestJarNilCases(t *testing.T) {
	jf, dir := loadJarFile(t)
	key := loadJarKey(filepath.Join(dir, jf.KeyFile))
	cases := []struct {
		name                          string
		client, tracker, cookie string
		k                       []byte
	}{
		{"empty key", "c", "t.example", "uid", nil},
		{"empty client", "", "t.example", "uid", key},
		{"empty tracker", "c", "", "uid", key},
	}
	for _, tc := range cases {
		if v, ok := fakeID(tc.client, tc.tracker, tc.cookie, tc.k); ok || v != "" {
			t.Errorf("%s: fakeID=%q,%v want \"\",false", tc.name, v, ok)
		}
	}
}
