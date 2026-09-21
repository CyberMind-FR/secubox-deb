// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// Tests de l'ecart « motifs DECLARES vs motifs CHARGES » (#1317).
//
// CE QUE CES TESTS EMPECHENT DE REVENIR. Cinq motifs CVE sont restes inertes
// pendant des mois — ecrits, relus, livres, versionnes — parce qu'un motif
// rejete au chargement et un motif qui n'attrape jamais rien produisent
// exactement la meme chose : zero prise, zero ligne, zero alerte.
//
// Corriger les cinq motifs sans rendre l'ecart MESURABLE revenait a accepter
// de recommencer au prochain. Ces tests verrouillent la mesure, pas les
// motifs.

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func ecrisRegles(t *testing.T, contenu string) string {
	t.Helper()
	f := filepath.Join(t.TempDir(), "waf-rules.json")
	if err := os.WriteFile(f, []byte(contenu), 0o644); err != nil {
		t.Fatalf("ecriture : %v", err)
	}
	return f
}

const toutCompile = `{
  "_meta": {"version": "t"},
  "categories": {
    "scanners": {"name": "S", "severity": "high", "patterns": [
      {"id": "s-1", "pattern": "/\\.env"},
      {"id": "s-2", "pattern": "/wp-login"}
    ]}
  }
}`

// “ est EXACTEMENT ce qui a fait tomber les cinq motifs CVE : RE2 ne
// connait pas cet echappement. On reproduit la panne reelle, pas une panne
// inventee.
const unMotifCasse = `{
  "_meta": {"version": "t"},
  "categories": {
    "scanners": {"name": "S", "severity": "high", "patterns": [
      {"id": "s-1", "pattern": "/\\.env"},
      {"id": "s-2", "pattern": "/wp-login"}
    ]},
    "cve_voip": {"name": "V", "severity": "critical", "patterns": [
      {"id": "cve-ast-2022-42706", "pattern": "Via:.*branch=.*\\u0000"}
    ]}
  }
}`

func TestIntegriteToutChargeQuandToutCompile(t *testing.T) {
	r := LoadRules(ecrisRegles(t, toutCompile))
	d, c, rej := r.Integrite()
	if d != 2 || c != 2 {
		t.Errorf("declares=%d charges=%d, attendu 2/2", d, c)
	}
	if len(rej) != 0 {
		t.Errorf("rejets inattendus : %v", rej)
	}
}

func TestIntegriteRevelLEcart(t *testing.T) {
	// LE test. Sans lui, trois motifs declares et deux charges se lisent
	// exactement comme deux motifs declares et deux charges.
	r := LoadRules(ecrisRegles(t, unMotifCasse))
	d, c, _ := r.Integrite()
	if d != 3 {
		t.Errorf("declares=%d, attendu 3", d)
	}
	if c != 2 {
		t.Errorf("charges=%d, attendu 2 — le motif casse ne doit PAS compter", c)
	}
	if d == c {
		t.Fatal("l'ecart est invisible : c'est precisement le defaut qu'on repare")
	}
}

func TestIntegriteNommeLesMotifsRejetes(t *testing.T) {
	// Savoir qu'il en manque un sans savoir lequel ne permet pas d'agir.
	r := LoadRules(ecrisRegles(t, unMotifCasse))
	_, _, rej := r.Integrite()
	if len(rej) != 1 {
		t.Fatalf("rejets=%v, attendu 1", rej)
	}
	if !strings.Contains(rej[0], "cve-ast-2022-42706") {
		t.Errorf("le rejet ne nomme pas le motif : %q", rej[0])
	}
	if !strings.Contains(rej[0], "cve_voip") {
		t.Errorf("le rejet ne nomme pas la categorie : %q", rej[0])
	}
}

func TestIntegriteSurvitAuRechargementAChaud(t *testing.T) {
	// L'ecart doit PERSISTER tant que le fichier n'est pas corrige. Une
	// mesure qui ne vaut qu'au demarrage laisse repasser le defaut au premier
	// rechargement — et les regles se rechargent a chaud.
	f := ecrisRegles(t, unMotifCasse)
	r := LoadRules(f)
	if d, c, _ := r.Integrite(); d == c {
		t.Fatal("ecart absent avant rechargement")
	}

	if err := os.WriteFile(f, []byte(toutCompile), 0o644); err != nil {
		t.Fatal(err)
	}
	// mtime au moins une seconde plus tard, sinon le veilleur ne voit rien
	plus := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(f, plus, plus); err != nil {
		t.Fatal(err)
	}
	r.Maybe()

	d, c, rej := r.Integrite()
	if d != c || len(rej) != 0 {
		t.Errorf("apres correction du fichier : declares=%d charges=%d rejets=%v", d, c, rej)
	}
}

func TestIntegriteReglesAbsentesNePaniquePas(t *testing.T) {
	// Fichier absent : le moteur se tait, il ne tombe pas. C'est l'etat
	// normal avant que l'exploitant n'ensemence /etc.
	r := LoadRules(filepath.Join(t.TempDir(), "rien.json"))
	d, c, rej := r.Integrite()
	if d != 0 || c != 0 || len(rej) != 0 {
		t.Errorf("regles absentes : %d/%d %v", d, c, rej)
	}
}
