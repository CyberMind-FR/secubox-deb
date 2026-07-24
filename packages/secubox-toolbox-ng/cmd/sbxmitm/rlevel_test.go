// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: R-level per-peer core tests (#rlevel-per-peer)
package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEffective(t *testing.T) {
	cases := []struct {
		chosen, forced, floor RLevel
		hasF                  bool
		want                  RLevel
	}{
		{Active, 0, Passive, true, 0},     // forced wins (off)
		{Off, 0, Passive, false, Passive}, // clamped up to floor
		{Reel, 0, Passive, false, Reel},
		{Active, 0, Active, false, Active},
	}
	for i, c := range cases {
		if got := effective(c.chosen, c.forced, c.floor, c.hasF); got != c.want {
			t.Fatalf("case %d: got %v want %v", i, got, c.want)
		}
	}
}

func TestClampVerdict(t *testing.T) {
	// passive → always splice
	for _, v := range []string{"allow", "block", "mitm", "splice"} {
		if got := clampVerdict(Passive, v); got != "splice" {
			t.Fatalf("passive %s→%s", v, got)
		}
	}
	// active → block downgraded to mitm, splice stays splice (pinned safe)
	if clampVerdict(Active, "block") != "mitm" {
		t.Fatal("active block")
	}
	if clampVerdict(Active, "splice") != "splice" {
		t.Fatal("active splice must stay")
	}
	if clampVerdict(Active, "mitm") != "mitm" {
		t.Fatal("active mitm")
	}
	if clampVerdict(Active, "allow") != "allow" {
		t.Fatal("active allow")
	}
	// reel → verdict unchanged
	for _, v := range []string{"allow", "block", "mitm", "splice"} {
		if clampVerdict(Reel, v) != v {
			t.Fatalf("reel %s changed", v)
		}
	}
	// off → verdict unchanged (never called in practice; must not panic)
	for _, v := range []string{"allow", "block", "mitm", "splice"} {
		if clampVerdict(Off, v) != v {
			t.Fatalf("off %s changed", v)
		}
	}
}

func TestParseRLevel(t *testing.T) {
	cases := []struct {
		in   string
		want RLevel
		ok   bool
	}{
		{"off", Off, true},
		{"passive", Passive, true},
		{"active", Active, true},
		{"reel", Reel, true},
		{"OFF", Off, true},
		{"  Reel  ", Reel, true},
		{"PaSsIvE", Passive, true},
		{"", 0, false},
		{"bogus", 0, false},
		{"activee", 0, false},
	}
	for _, c := range cases {
		got, ok := parseRLevel(c.in)
		if ok != c.ok || (ok && got != c.want) {
			t.Fatalf("parseRLevel(%q) = (%v,%v) want (%v,%v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestEffectiveFloorNeverExceedsReel(t *testing.T) {
	// floor itself must never push past Reel even if misconfigured above it.
	if got := effective(Off, 0, Reel, false); got != Reel {
		t.Fatalf("floor=Reel: got %v want %v", got, Reel)
	}
}

// ── PeerPolicy: peer-rlevel.json ⋈ wg-peers.json ─────────────────────────────

const testRlevelJSON = `{
	"defaults": {"mode": "passive", "floor": "passive"},
	"peers": {
		"PK1": {"chosen": "active", "forced": null, "floor": "passive"},
		"PK2": {"forced": "off"}
	}
}`

const testWgPeersJSON = `{
	"peers": {
		"PK1": {"ip": "10.99.1.5"},
		"PK2": {"ip": "10.99.1.6"}
	}
}`

// writePeerFixtures writes the two backing files into t.TempDir() and returns
// their paths.
func writePeerFixtures(t *testing.T, rlevelJSON, wgPeersJSON string) (rlevelPath, wgPath string) {
	t.Helper()
	dir := t.TempDir()
	rlevelPath = filepath.Join(dir, "peer-rlevel.json")
	wgPath = filepath.Join(dir, "wg-peers.json")
	if err := os.WriteFile(rlevelPath, []byte(rlevelJSON), 0o644); err != nil {
		t.Fatalf("write rlevel fixture: %v", err)
	}
	if err := os.WriteFile(wgPath, []byte(wgPeersJSON), 0o644); err != nil {
		t.Fatalf("write wg-peers fixture: %v", err)
	}
	return rlevelPath, wgPath
}

// TestPeerPolicyModeForIP is the linchpin test from the brief: PK1 (chosen
// active, no force) resolves to Active, PK2 (forced off) resolves to Off
// regardless of chosen/floor, and an IP with no matching peer falls back to
// the file's declared defaults (Passive here).
func TestPeerPolicyModeForIP(t *testing.T) {
	rlevelPath, wgPath := writePeerFixtures(t, testRlevelJSON, testWgPeersJSON)

	pp, err := LoadPeerPolicy(rlevelPath, wgPath)
	if err != nil {
		t.Fatalf("LoadPeerPolicy: %v", err)
	}

	if got := pp.ModeForIP("10.99.1.5"); got != Active {
		t.Fatalf("PK1 (10.99.1.5) = %v, want Active", got)
	}
	if got := pp.ModeForIP("10.99.1.6"); got != Off {
		t.Fatalf("PK2 (10.99.1.6, forced off) = %v, want Off", got)
	}
	if got := pp.ModeForIP("10.99.1.99"); got != Passive {
		t.Fatalf("unknown IP = %v, want Passive (default)", got)
	}
}

// TestPeerPolicyCorruptRlevelFailsSafeToPassive proves the fail-safe: a
// corrupt peer-rlevel.json must never propagate an error or a panic, and
// every peer — even one with a valid wg-peers.json entry — resolves to
// Passive until the file is fixed.
func TestPeerPolicyCorruptRlevelFailsSafeToPassive(t *testing.T) {
	dir := t.TempDir()
	rlevelPath := filepath.Join(dir, "peer-rlevel.json")
	wgPath := filepath.Join(dir, "wg-peers.json")
	if err := os.WriteFile(rlevelPath, []byte("{ this is not valid json"), 0o644); err != nil {
		t.Fatalf("write corrupt rlevel fixture: %v", err)
	}
	if err := os.WriteFile(wgPath, []byte(testWgPeersJSON), 0o644); err != nil {
		t.Fatalf("write wg-peers fixture: %v", err)
	}

	pp, err := LoadPeerPolicy(rlevelPath, wgPath)
	if err != nil {
		t.Fatalf("LoadPeerPolicy must never error on corrupt JSON: %v", err)
	}

	for _, ip := range []string{"10.99.1.5", "10.99.1.6", "10.99.1.99"} {
		if got := pp.ModeForIP(ip); got != Passive {
			t.Fatalf("corrupt rlevel: ModeForIP(%q) = %v, want Passive", ip, got)
		}
	}
}

// TestPeerPolicyMissingFilesFailSafe proves best-effort startup: both files
// absent must not error, and every IP resolves to Passive.
func TestPeerPolicyMissingFilesFailSafe(t *testing.T) {
	dir := t.TempDir()
	rlevelPath := filepath.Join(dir, "does-not-exist-rlevel.json")
	wgPath := filepath.Join(dir, "does-not-exist-wg-peers.json")

	pp, err := LoadPeerPolicy(rlevelPath, wgPath)
	if err != nil {
		t.Fatalf("LoadPeerPolicy must never error on missing files: %v", err)
	}
	if got := pp.ModeForIP("10.99.1.5"); got != Passive {
		t.Fatalf("missing files: ModeForIP = %v, want Passive", got)
	}
}

// TestPeerPolicyHotReload proves the mtime-based hot-reload: editing
// peer-rlevel.json (promoting PK1 from active to forced off) and bumping its
// mtime flips ModeForIP for PK1's IP with no reload from scratch.
func TestPeerPolicyHotReload(t *testing.T) {
	rlevelPath, wgPath := writePeerFixtures(t, testRlevelJSON, testWgPeersJSON)

	pp, err := LoadPeerPolicy(rlevelPath, wgPath)
	if err != nil {
		t.Fatalf("LoadPeerPolicy: %v", err)
	}
	pp.reloadThrottle = 0 // eager: no 15s wait in the test

	if got := pp.ModeForIP("10.99.1.5"); got != Active {
		t.Fatalf("before edit: PK1 = %v, want Active", got)
	}

	const updated = `{
		"defaults": {"mode": "passive", "floor": "passive"},
		"peers": {
			"PK1": {"forced": "off"},
			"PK2": {"forced": "off"}
		}
	}`
	if err := os.WriteFile(rlevelPath, []byte(updated), 0o644); err != nil {
		t.Fatalf("rewrite rlevel fixture: %v", err)
	}
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(rlevelPath, future, future); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	if got := pp.ModeForIP("10.99.1.5"); got != Off {
		t.Fatalf("after edit: PK1 = %v, want Off", got)
	}
}
