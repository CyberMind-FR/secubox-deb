// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: sbxwaf :: ban_test — sliding-window ban state machine tests

package main

import (
	"testing"
	"time"
)

// TestBanGraduated verifies that the ban threshold is reached on the 3rd hit
// within the window (default: window=300s, threshold=3).
func TestBanGraduated(t *testing.T) {
	b := NewBan(300*time.Second, 3)
	ip := "1.2.3.4"

	count, banned := b.Record(ip, 0)
	if count != 1 || banned {
		t.Fatalf("after 1st hit: want (1,false), got (%d,%v)", count, banned)
	}

	count, banned = b.Record(ip, 0)
	if count != 2 || banned {
		t.Fatalf("after 2nd hit: want (2,false), got (%d,%v)", count, banned)
	}

	count, banned = b.Record(ip, 0)
	if count != 3 || !banned {
		t.Fatalf("after 3rd hit: want (3,true), got (%d,%v)", count, banned)
	}
}

// TestBanWindowExpiry verifies that hits older than the window are pruned so
// that a previously-banned IP resets its count after the window expires.
func TestBanWindowExpiry(t *testing.T) {
	b := NewBan(300*time.Second, 3)
	ip := "1.2.3.4"

	// Hit 3 times at t=0 → banned.
	b.Record(ip, 0)
	b.Record(ip, 0)
	count, banned := b.Record(ip, 0)
	if count != 3 || !banned {
		t.Fatalf("pre-condition: want (3,true) at t=0, got (%d,%v)", count, banned)
	}

	// At t=400 (> 300s window) all prior hits are pruned; new hit → count=1, not banned.
	count, banned = b.Record(ip, 400)
	if count != 1 || banned {
		t.Fatalf("after window expiry at t=400: want (1,false), got (%d,%v)", count, banned)
	}
}

// TestBanPerIPIsolation verifies that hits on one IP do not bleed into another.
func TestBanPerIPIsolation(t *testing.T) {
	b := NewBan(300*time.Second, 3)
	ipA := "1.2.3.4"
	ipB := "5.6.7.8"

	// Three hits on A → banned.
	b.Record(ipA, 0)
	b.Record(ipA, 0)
	_, bannedA := b.Record(ipA, 0)
	if !bannedA {
		t.Fatal("ipA should be banned after 3 hits")
	}

	// B has had zero hits → count=1, not banned after its first hit.
	countB, bannedB := b.Record(ipB, 0)
	if countB != 1 || bannedB {
		t.Fatalf("ipB isolation: want (1,false), got (%d,%v)", countB, bannedB)
	}
}
