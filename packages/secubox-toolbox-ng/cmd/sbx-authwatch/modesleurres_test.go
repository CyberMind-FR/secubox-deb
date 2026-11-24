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

func ecrireModes(t *testing.T, chemin, contenu string, quand time.Time) {
	t.Helper()
	if err := os.WriteFile(chemin, []byte(contenu), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(chemin, quand, quand); err != nil {
		t.Fatal(err)
	}
}

func TestModesLeurres_FermeParDefaut(t *testing.T) {
	var nul *ModesLeurres
	if nul.Observe("rdp") {
		t.Fatal("nil doit bannir")
	}
	m := NewModesLeurres(filepath.Join(t.TempDir(), "absent.json"))
	if m.Observe("rdp") {
		t.Fatal("fichier absent : doit bannir")
	}
	chemin := filepath.Join(t.TempDir(), "leurres-modes.json")
	ecrireModes(t, chemin, `{"modes": {"rdp": "monitor", "vnc": "observer"}}`, time.Now())
	m = NewModesLeurres(chemin)
	if m.Observe("rdp") || m.Observe("telnet") {
		t.Fatal("valeur inconnue ou service absent : doit bannir")
	}
	if !m.Observe("vnc") {
		t.Fatal("vnc réglé observer")
	}
}

func TestModesLeurres_RelectureAChaud(t *testing.T) {
	chemin := filepath.Join(t.TempDir(), "leurres-modes.json")
	base := time.Now().Add(-time.Hour)
	ecrireModes(t, chemin, `{"modes": {"redis": "bannir"}}`, base)
	m := NewModesLeurres(chemin)
	if m.Observe("redis") {
		t.Fatal("redis réglé bannir")
	}
	ecrireModes(t, chemin, `{"modes": {"redis": "observer"}}`, base.Add(time.Minute))
	if !m.Observe("redis") {
		t.Fatal("changement non relu")
	}
	ecrireModes(t, chemin, `{cassé`, base.Add(2*time.Minute))
	if m.Observe("redis") {
		t.Fatal("fichier cassé : doit bannir")
	}
}

func TestLeurreObserveNeBannitPas(t *testing.T) {
	chemin := filepath.Join(t.TempDir(), "leurres-modes.json")
	ecrireModes(t, chemin, `{"modes": {"rdp": "observer"}}`, time.Now())
	modesLeurres = NewModesLeurres(chemin)
	t.Cleanup(func() { modesLeurres = nil })

	b, fx := banneurTest(t)
	j, cj := journalTest(t)
	lb, _ := NewListeBlanche("")
	ctx, annule := context.WithCancel(context.Background())
	signaux := make(chan Signal, 2)
	signaux <- Signal{IP: "203.0.113.6", Service: "rdp", Categorie: "leurre:rdp", Severite: "high"}
	signaux <- Signal{IP: "203.0.113.7", Service: "vnc", Categorie: "leurre:vnc", Severite: "high"}
	arret := lanceTraite(ctx, signaux, NewCompteur(time.Minute, 99, time.Minute), nil, nil, b, j, lb, false, nil)
	time.Sleep(100 * time.Millisecond)
	annule()
	arret()

	if len(fx.liste()) != 1 || fx.liste()[0] != "203.0.113.7" {
		t.Fatalf("seul vnc doit bannir, obtenu %v", fx.liste())
	}
	lignes := lignesJournal(t, cj)
	if len(lignes) != 2 || lignes[0]["action"] != "detect" || lignes[1]["action"] != "banned" {
		t.Fatalf("journal attendu detect puis banned : %v", lignes)
	}
}
