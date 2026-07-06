// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package sentinel

import (
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := OpenStore(filepath.Join(t.TempDir(), "verdicts.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestStoreRecordAndRecent(t *testing.T) {
	s := openTestStore(t)

	v := &Verdict{
		Class:      ClassBotnetC2,
		Severity:   90,
		Confidence: 90,
		Action:     ActionBlock,
		Evidence:   map[string]string{"ioc_type": "domain", "ioc_value": "evil.example"},
		MacHash:    "mac-abc",
		TS:         1234567890,
	}
	if err := s.Record(v); err != nil {
		t.Fatalf("Record: %v", err)
	}

	got, err := s.Recent(10)
	if err != nil {
		t.Fatalf("Recent: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 verdict, got %d", len(got))
	}
	r := got[0]
	if r.Class != ClassBotnetC2 || r.Severity != 90 || r.Confidence != 90 || r.Action != ActionBlock {
		t.Fatalf("fields not intact: %+v", r)
	}
	if r.MacHash != "mac-abc" {
		t.Fatalf("mac_hash not intact: %+v", r)
	}
	if r.TS != 1234567890 {
		t.Fatalf("TS was re-stamped: got %d want 1234567890", r.TS)
	}
	if r.Evidence["ioc_type"] != "domain" || r.Evidence["ioc_value"] != "evil.example" {
		t.Fatalf("evidence did not round-trip: %+v", r.Evidence)
	}
}

func TestStoreRecentOrderAndLimit(t *testing.T) {
	s := openTestStore(t)

	base := int64(1000)
	for i := 0; i < 5; i++ {
		v := &Verdict{
			Class:    ClassMalware,
			Severity: i,
			Action:   ActionReport,
			MacHash:  "mac",
			TS:       base + int64(i),
		}
		if err := s.Record(v); err != nil {
			t.Fatalf("Record %d: %v", i, err)
		}
	}

	got, err := s.Recent(3)
	if err != nil {
		t.Fatalf("Recent: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3, got %d", len(got))
	}
	// Most recent (highest TS) first.
	if got[0].TS != base+4 || got[1].TS != base+3 || got[2].TS != base+2 {
		t.Fatalf("unexpected order: %+v", got)
	}
}

func TestStoreSameTSNoCollision(t *testing.T) {
	s := openTestStore(t)

	for i := 0; i < 3; i++ {
		v := &Verdict{Class: ClassMalware, Action: ActionReport, MacHash: "mac", TS: 42}
		if err := s.Record(v); err != nil {
			t.Fatalf("Record %d: %v", i, err)
		}
	}
	got, err := s.Recent(10)
	if err != nil {
		t.Fatalf("Recent: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 verdicts at same ts, got %d (collision?)", len(got))
	}
}

func TestStoreByMac(t *testing.T) {
	s := openTestStore(t)

	macs := []string{"mac-a", "mac-b", "mac-a", "mac-c", "mac-a"}
	for i, m := range macs {
		v := &Verdict{Class: ClassPhishing, Action: ActionReport, MacHash: m, TS: int64(2000 + i)}
		if err := s.Record(v); err != nil {
			t.Fatalf("Record %d: %v", i, err)
		}
	}

	got, err := s.ByMac("mac-a", 10)
	if err != nil {
		t.Fatalf("ByMac: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 for mac-a, got %d", len(got))
	}
	for _, v := range got {
		if v.MacHash != "mac-a" {
			t.Fatalf("filter leaked other mac: %+v", v)
		}
	}

	limited, err := s.ByMac("mac-a", 2)
	if err != nil {
		t.Fatalf("ByMac limited: %v", err)
	}
	if len(limited) != 2 {
		t.Fatalf("expected limit 2, got %d", len(limited))
	}
}

func TestStorePrune(t *testing.T) {
	s := openTestStore(t)

	now := time.Now()
	old := &Verdict{Class: ClassMalware, Action: ActionReport, MacHash: "mac", TS: now.Add(-2 * time.Hour).Unix()}
	recent := &Verdict{Class: ClassMalware, Action: ActionReport, MacHash: "mac", TS: now.Unix()}
	if err := s.Record(old); err != nil {
		t.Fatalf("Record old: %v", err)
	}
	if err := s.Record(recent); err != nil {
		t.Fatalf("Record recent: %v", err)
	}

	n, err := s.Prune(time.Hour)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 pruned, got %d", n)
	}

	got, err := s.Recent(10)
	if err != nil {
		t.Fatalf("Recent: %v", err)
	}
	if len(got) != 1 || got[0].TS != recent.TS {
		t.Fatalf("prune left wrong rows: %+v", got)
	}
}

func TestStorePruneAllWithZero(t *testing.T) {
	s := openTestStore(t)

	for i := 0; i < 3; i++ {
		v := &Verdict{Class: ClassMalware, Action: ActionReport, MacHash: "mac", TS: time.Now().Add(-time.Duration(i) * time.Minute).Unix()}
		if err := s.Record(v); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	n, err := s.Prune(0)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if n != 3 {
		t.Fatalf("expected 3 pruned, got %d", n)
	}
	got, err := s.Recent(10)
	if err != nil {
		t.Fatalf("Recent: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty store after Prune(0), got %d", len(got))
	}
}

func TestStoreConcurrentRecord(t *testing.T) {
	s := openTestStore(t)

	const n = 4
	const perGoroutine = 25
	var wg sync.WaitGroup
	errs := make(chan error, n*perGoroutine)
	for g := 0; g < n; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				v := &Verdict{
					Class:    ClassMalware,
					Action:   ActionReport,
					MacHash:  "mac",
					TS:       time.Now().Unix(),
					Evidence: map[string]string{"g": "goroutine"},
				}
				if err := s.Record(v); err != nil {
					errs <- err
				}
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent Record error: %v", err)
	}

	got, err := s.Recent(n * perGoroutine)
	if err != nil {
		t.Fatalf("Recent: %v", err)
	}
	if len(got) != n*perGoroutine {
		t.Fatalf("expected %d verdicts landed, got %d", n*perGoroutine, len(got))
	}
}
