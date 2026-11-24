// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEtatSeulementCampagnesEtablies(t *testing.T) {
	c := NewCampagnes(time.Hour, 3)
	t0 := time.Unix(1_800_000_000, 0)
	for i, ip := range []string{"8.8.8.8", "1.1.1.1", "9.9.9.9"} {
		c.Note("gerald@exemple.test", ip, t0.Add(time.Duration(i)*time.Minute))
	}
	c.Note("autre@exemple.test", "8.8.8.8", t0)
	c.Note("autre@exemple.test", "1.1.1.1", t0)
	e := c.Etat(t0.Add(10 * time.Minute))
	if len(e) != 1 {
		t.Fatalf("une seule campagne attendue : %v", e)
	}
	if e[0].Compte != "ger…" || e[0].Sources != 3 || len(e[0].ID) != 8 {
		t.Fatalf("état inattendu : %+v", e[0])
	}
	if e[0].Premier != t0.Unix() || e[0].Dernier != t0.Add(2*time.Minute).Unix() {
		t.Fatalf("premier/dernier : %+v", e[0])
	}
}

func TestEtatIgnoreLesSourcesHorsFenetre(t *testing.T) {
	c := NewCampagnes(time.Hour, 3)
	t0 := time.Unix(1_800_000_000, 0)
	for _, ip := range []string{"8.8.8.8", "1.1.1.1", "9.9.9.9"} {
		c.Note("gerald@exemple.test", ip, t0)
	}
	if e := c.Etat(t0.Add(2 * time.Hour)); len(e) != 0 {
		t.Fatalf("campagne périmée : %v", e)
	}
	if (*Campagnes)(nil).Etat(t0) != nil {
		t.Fatal("nil-safe")
	}
}

func TestEtatEcritAtomique(t *testing.T) {
	dir := t.TempDir()
	chemin := filepath.Join(dir, "camp.json")
	c := NewCampagnes(time.Hour, 3)
	now := time.Now()
	for _, ip := range []string{"8.8.8.8", "1.1.1.1", "9.9.9.9"} {
		c.Note("gerald@exemple.test", ip, now)
	}
	if err := EcrireEtat(c, chemin, now); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(chemin)
	if err != nil {
		t.Fatal(err)
	}
	var tab []EtatCampagne
	if err := json.Unmarshal(b, &tab); err != nil || len(tab) != 1 {
		t.Fatalf("tableau JSON invalide : %v %s", err, b)
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Fatalf("fichier temporaire laissé : %v", ents)
	}
	// Aucune campagne : tableau vide, pas null.
	c2 := NewCampagnes(time.Hour, 3)
	if err := EcrireEtat(c2, chemin, now); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(chemin); string(b) != "[]\n" && string(b) != "[]" {
		t.Fatalf("attendu [] : %q", b)
	}
	if err := EcrireEtat(c, filepath.Join(dir, "absent", "x.json"), now); err == nil {
		t.Fatal("répertoire absent : erreur attendue")
	}
}
