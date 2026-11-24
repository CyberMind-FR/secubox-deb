// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/reseau"
)

const etatReference = "testdata/rotation-etat-propose.json"

// Le fichier de référence est l'état RÉEL écrit par le détecteur en `propose` ; le relevé des populations (Python, secubox-waf-ng) le lit dans ses tests.
// Après un changement voulu du format : MAJ_REFERENCE=1 go test -run TestRotationEtatReference ./cmd/sbxwaf/
func TestRotationEtatReference(t *testing.T) {
	t0 := time.Unix(1795518000, 0) // 2026-11-24T11:00:00Z
	cfg := cfgEssai(t, "propose")
	cfg.Horloge = func() time.Time { return t0 }
	cl := &classesFactices{defaut: reseau.ClasseProxyLoue}
	for i := 0; i < 10; i++ {
		cl.poser(adressePublique(i), reseau.ClasseHebergeur)
	}
	cl.poser(adressePublique(103), reseau.ClasseAcces)
	ban := &banFactice{}
	r := NewRotation(cfg, ban, cl)
	etablir(r, 0, 60, t0)
	t1 := t0.Add(30 * time.Second)
	for i := 100; i < 104; i++ {
		page(r, adressePublique(i), t1)
	}
	ressource(r, adressePublique(100), uaFictif, t1.Add(time.Second))
	avancer(r, t1, t1.Add(20*time.Second))
	if len(ban.liste()) != 0 {
		t.Fatal("aucun ban en propose")
	}
	b, err := os.ReadFile(cfg.Etat)
	if err != nil {
		t.Fatal(err)
	}
	b = append(b, '\n')
	if os.Getenv("MAJ_REFERENCE") != "" {
		if err := os.MkdirAll(filepath.Dir(etatReference), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(etatReference, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	ref, err := os.ReadFile(etatReference)
	if err != nil || !bytes.Equal(ref, b) {
		t.Fatalf("état écrit :\n%s\nréférence :\n%s\n%v", b, ref, err)
	}
}

func TestRotationUnSeulProcessus(t *testing.T) {
	etat := filepath.Join(t.TempDir(), "rotation-etat.json")
	if err := verrouillerRotation(etat); err != nil {
		t.Fatal(err)
	}
	premier := rotationVerrou
	if err := verrouillerRotation(etat); err == nil {
		t.Fatal("un second détecteur ne doit pas démarrer")
	}
	premier.Close()
	if err := verrouillerRotation(etat); err != nil {
		t.Fatalf("verrou rendu à la fin du premier : %v", err)
	}
	rotationVerrou.Close()
	rotationVerrou = nil
	if verrouillerRotation("") == nil || verrouillerRotation(filepath.Join(t.TempDir(), "absent", "e.json")) == nil {
		t.Fatal("pas de verrou possible : pas de détecteur")
	}
}
