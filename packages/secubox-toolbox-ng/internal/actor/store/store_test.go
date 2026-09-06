// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package store

import (
	"path/filepath"
	"testing"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/envelope"
)

const now = int64(1788000000)

func ev(ts int64, sensor, action string) *envelope.Envelope {
	return &envelope.Envelope{
		EventID: envelope.NewEventID(), Timestamp: ts, Sensor: sensor,
		SrcIP: "203.0.113.7", Action: action, Severity: 50,
	}
}

func ouvre(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "actord.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestIngestEtStats(t *testing.T) {
	s := ouvre(t)
	must := func(e *envelope.Envelope) {
		if err := s.Ingest(e); err != nil {
			t.Fatal(err)
		}
	}
	must(ev(now-100, envelope.SensorWAF, envelope.ActionBlock))
	must(ev(now-200, envelope.SensorDPI, envelope.ActionObserve))
	must(ev(now-90000, envelope.SensorAuthWatch, envelope.ActionBlock)) // hors fenêtre 24 h
	must(ev(now-50, envelope.SensorWAF, envelope.ActionQuarantps))

	st, err := s.Stats(now)
	if err != nil {
		t.Fatal(err)
	}
	if st.Total != 4 {
		t.Errorf("Total = %d, attendu 4", st.Total)
	}
	if st.Events24h != 3 {
		t.Errorf("Events24h = %d, attendu 3 (l'ancien est hors fenêtre)", st.Events24h)
	}
	if st.Blocked24h != 2 { // block + quarantine
		t.Errorf("Blocked24h = %d, attendu 2", st.Blocked24h)
	}
	if st.Attempts24h != 1 { // observe
		t.Errorf("Attempts24h = %d, attendu 1", st.Attempts24h)
	}
	if st.BySensor[envelope.SensorWAF] != 2 || st.BySensor[envelope.SensorDPI] != 1 {
		t.Errorf("BySensor incohérent : %+v", st.BySensor)
	}
	if st.FirstTS != now-90000 || st.LastTS != now-50 {
		t.Errorf("First/Last = %d/%d", st.FirstTS, st.LastTS)
	}
}

func TestRecentOrdre(t *testing.T) {
	s := ouvre(t)
	_ = s.Ingest(ev(now-300, envelope.SensorWAF, envelope.ActionObserve))
	_ = s.Ingest(ev(now-100, envelope.SensorDPI, envelope.ActionObserve))
	_ = s.Ingest(ev(now-200, envelope.SensorWAF, envelope.ActionObserve))
	rec, err := s.Recent(2)
	if err != nil {
		t.Fatal(err)
	}
	if len(rec) != 2 {
		t.Fatalf("Recent(2) a rendu %d éléments", len(rec))
	}
	if rec[0].Timestamp != now-100 || rec[1].Timestamp != now-200 {
		t.Errorf("ordre attendu du plus récent au plus ancien : %d, %d", rec[0].Timestamp, rec[1].Timestamp)
	}
}

func TestPrune(t *testing.T) {
	s := ouvre(t)
	_ = s.Ingest(ev(now-90000, envelope.SensorWAF, envelope.ActionObserve)) // vieux
	_ = s.Ingest(ev(now-100, envelope.SensorWAF, envelope.ActionObserve))   // récent
	n, err := s.Prune(now - 1000)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("Prune a supprimé %d, attendu 1", n)
	}
	rec, _ := s.Recent(10)
	if len(rec) != 1 || rec[0].Timestamp != now-100 {
		t.Errorf("après prune, seul l'événement récent devrait rester : %+v", rec)
	}
}
