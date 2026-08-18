// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/sentinel"
)

// openTestStore opens a temp bbolt store seeded with the given verdicts.
func openTestStore(t *testing.T, verdicts ...sentinel.Verdict) *sentinel.Store {
	t.Helper()
	store, err := sentinel.OpenStore(filepath.Join(t.TempDir(), "verdicts.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	for i := range verdicts {
		if err := store.Record(&verdicts[i]); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	return store
}

func TestStatusStats(t *testing.T) {
	now := time.Now().Unix()
	store := openTestStore(t,
		sentinel.Verdict{Class: sentinel.ClassSpywarePegasus, Action: sentinel.ActionBlock, MacHash: "a", TS: now},
		sentinel.Verdict{Class: sentinel.ClassBotnetC2, Action: sentinel.ActionSinkhole, MacHash: "b", TS: now},
		sentinel.Verdict{Class: sentinel.ClassZeroClick, Action: sentinel.ActionReport, MacHash: "c", TS: now},
	)
	mux := newStatusMux(store, nil)

	req := httptest.NewRequest(http.MethodGet, "/stats", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var got sentinelStats
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Detections != 3 {
		t.Errorf("detections: want 3 got %d", got.Detections)
	}
	if got.Blocked != 2 { // block + sinkhole are neutralized; report is not
		t.Errorf("blocked: want 2 got %d", got.Blocked)
	}
	if got.Spyware != 1 {
		t.Errorf("spyware: want 1 got %d", got.Spyware)
	}
}

func TestStatusVerdicts(t *testing.T) {
	store := openTestStore(t,
		sentinel.Verdict{
			Class:    sentinel.ClassSpywarePegasus,
			Action:   sentinel.ActionBlock,
			Evidence: map[string]string{"ioc_value": "notif-alert-news.example"},
			MacHash:  "devicehash",
			TS:       time.Now().Unix(),
		},
	)
	mux := newStatusMux(store, nil)

	req := httptest.NewRequest(http.MethodGet, "/verdicts", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var got []verdictView
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 verdict got %d", len(got))
	}
	if got[0].MacHash != "devicehash" {
		t.Errorf("mac_hash: %q", got[0].MacHash)
	}
	if got[0].Report == "" {
		t.Error("expected a rendered report string")
	}
	if !strings.Contains(got[0].Report, "notif-alert-news.example") {
		t.Errorf("report should embed the evidence:\n%s", got[0].Report)
	}
}

func TestVerdictsFilterByMac(t *testing.T) {
	store := openTestStore(t)
	store.Record(&sentinel.Verdict{
		Class: sentinel.ClassSpywarePegasus, Action: sentinel.ActionBlock,
		Evidence: map[string]string{"ioc_value": "a.example"},
		MacHash:  "aaaa", TS: time.Now().Unix(),
	})
	store.Record(&sentinel.Verdict{
		Class: sentinel.ClassSpywarePredator, Action: sentinel.ActionReport,
		Evidence: map[string]string{"ioc_value": "b.example"},
		MacHash:  "bbbb", TS: time.Now().Unix(),
	})
	mux := newStatusMux(store, nil)

	req := httptest.NewRequest(http.MethodGet, "/verdicts?mac=aaaa", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var got []verdictView
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 1 || got[0].MacHash != "aaaa" {
		t.Fatalf("want 1 verdict for aaaa, got %d: %+v", len(got), got)
	}

	// Unknown mac → empty list, still 200.
	req = httptest.NewRequest(http.MethodGet, "/verdicts?mac=zzzz", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("unknown-mac status %d", rec.Code)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode2: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want 0 for unknown mac, got %d", len(got))
	}
}

func TestStatusRejectsNonGet(t *testing.T) {
	store := openTestStore(t)
	mux := newStatusMux(store, nil)

	req := httptest.NewRequest(http.MethodPost, "/stats", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 for POST, got %d", rec.Code)
	}
}
