// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: R-level per-peer core tests (#rlevel-per-peer)
package main

import "testing"

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
