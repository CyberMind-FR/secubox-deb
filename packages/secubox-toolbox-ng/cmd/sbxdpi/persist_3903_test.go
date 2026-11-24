// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// #3903 : le relevé disque (3,5 Mo sur gk2) ne suit plus le rythme du tour de 30 s.
func TestPersistanceEspaceeDuTour3903(t *testing.T) {
	chemin := filepath.Join(t.TempDir(), "stats.json")
	cfg := withDefaults(Config{CachePath: chemin, FlushInterval: 5 * time.Millisecond, PersistInterval: time.Hour})
	ctx, annule := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer annule()
	flushLoop(ctx, cfg, newAggregator())
	if _, err := os.Stat(chemin); !os.IsNotExist(err) {
		t.Fatalf("relevé écrit avant son intervalle : %v", err)
	}
}

func TestPersistanceAuRythmeDemande3903(t *testing.T) {
	chemin := filepath.Join(t.TempDir(), "stats.json")
	cfg := withDefaults(Config{CachePath: chemin, FlushInterval: 5 * time.Millisecond, PersistInterval: 10 * time.Millisecond})
	ctx, annule := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer annule()
	flushLoop(ctx, cfg, newAggregator())
	if _, err := os.Stat(chemin); err != nil {
		t.Fatalf("relevé jamais écrit : %v", err)
	}
}

func TestPersistanceDefautDixMinutes3903(t *testing.T) {
	if got := withDefaults(Config{}).PersistInterval; got != 10*time.Minute {
		t.Fatalf("défaut %s, attendu 10m", got)
	}
}
