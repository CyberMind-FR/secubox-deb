// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package sentinel

import (
	"fmt"
	"path/filepath"
	"testing"
)

func TestC2CandPromotionRequiresSustained(t *testing.T) {
	c := NewC2Cand(filepath.Join(t.TempDir(), "cand.json"))
	base := int64(1_000_000)
	// window 1
	if p, _ := c.Record("c2.example", "devA", base, 60, []string{"rare", "dga"}); p {
		t.Fatal("must not promote on window 1")
	}
	// window 2 (still < c2MinWindows)
	if p, _ := c.Record("c2.example", "devA", base+900, 60, []string{"rare"}); p {
		t.Fatal("must not promote on window 2")
	}
	// window 3, span now 1800s (>= c2MinSpanSec) → promote once
	p, cand := c.Record("c2.example", "devA", base+1800, 60, []string{"rare"})
	if !p {
		t.Fatal("must promote on window 3 with span met")
	}
	if cand.Windows < c2MinWindows || cand.Host != "c2.example" {
		t.Errorf("bad candidate on promote: %+v", cand)
	}
	// subsequent records must NOT re-promote (latched)
	if p, _ := c.Record("c2.example", "devA", base+2700, 60, []string{"rare"}); p {
		t.Error("must not re-promote after first promotion")
	}
}

func TestC2CandSpanGuard(t *testing.T) {
	c := NewC2Cand(filepath.Join(t.TempDir(), "cand.json"))
	base := int64(2_000_000)
	// 3 windows but all within 10s → span not met → no promote
	c.Record("burst.example", "devA", base, 5, []string{"rare"})
	c.Record("burst.example", "devA", base+3, 5, []string{"rare"})
	p, _ := c.Record("burst.example", "devA", base+9, 5, []string{"rare"})
	if p {
		t.Error("must not promote a tight burst (span < c2MinSpanSec)")
	}
}

func TestC2CandPersistRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cand.json")
	c := NewC2Cand(path)
	c.Record("x.example", "devA", 100, 30, []string{"rare"})
	if err := c.Persist(); err != nil {
		t.Fatal(err)
	}
	c2 := NewC2Cand(path)
	if len(c2.Snapshot()) != 1 {
		t.Errorf("expected 1 candidate after reload, got %d", len(c2.Snapshot()))
	}
}

func TestC2CandSnapshotIsolated(t *testing.T) {
	c := NewC2Cand(filepath.Join(t.TempDir(), "cand.json"))
	c.Record("h.example", "devA", 100, 30, []string{"rare"})
	snap := c.Snapshot()
	// mutating the snapshot's maps must not affect the live candidate
	snap[0].Devices["injected"] = true
	c.Record("h.example", "devB", 200, 30, []string{"dga"})
	for _, cd := range c.Snapshot() {
		if cd.Devices["injected"] {
			t.Error("snapshot map aliases live candidate map (race risk)")
		}
	}
}

func TestC2CandDevicesCapped(t *testing.T) {
	c := NewC2Cand(filepath.Join(t.TempDir(), "cand.json"))
	for i := 0; i < c2MaxDevicesPerHost+50; i++ {
		c.Record("h.example", fmt.Sprintf("dev%d", i), int64(100+i), 30, []string{"rare"})
	}
	for _, cd := range c.Snapshot() {
		if len(cd.Devices) > c2MaxDevicesPerHost {
			t.Errorf("devices not capped: %d", len(cd.Devices))
		}
	}
}
