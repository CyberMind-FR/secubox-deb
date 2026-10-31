// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package store

import (
	"testing"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/envelope"
)

// #3320 : un lot = une transaction ; meme contenu qu'une ingestion unitaire.
func TestIngestLot(t *testing.T) {
	s := ouvre(t)
	lot := []*envelope.Envelope{ev(100, "sbxwaf", envelope.ActionBlock), ev(101, "sbxwaf", "observe"), ev(102, "sbxdpi", "observe")}
	if err := s.IngestLot(lot); err != nil {
		t.Fatal(err)
	}
	evs, _ := s.Recent(10)
	if len(evs) != 3 || evs[0].Timestamp != 102 {
		t.Fatalf("recent = %d (%v)", len(evs), evs)
	}
	st, _ := s.Stats(200)
	if st.Total != 3 {
		t.Fatalf("total = %d", st.Total)
	}
}

// #3320 : la purge travaille par lots, jusqu'au bout.
func TestPrunePlusieursLots(t *testing.T) {
	s := ouvre(t)
	var lot []*envelope.Envelope
	for i := 0; i < 2*pruneLot+7; i++ {
		lot = append(lot, ev(int64(i), "sbxwaf", "observe"))
	}
	lot = append(lot, ev(1_000_000, "sbxwaf", "observe"))
	if err := s.IngestLot(lot); err != nil {
		t.Fatal(err)
	}
	n, err := s.Prune(500_000)
	if err != nil || n != 2*pruneLot+7 {
		t.Fatalf("prune = %d, %v", n, err)
	}
	if evs, _ := s.Recent(10); len(evs) != 1 {
		t.Fatalf("reste %d", len(evs))
	}
}
