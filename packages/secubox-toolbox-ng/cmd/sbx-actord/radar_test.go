// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"strings"
	"testing"
)

func TestRadar_ServiDansLaVueReduiteSansAdresseNiCibleNiPreuve(t *testing.T) {
	s := serveur(t)
	id := scenario(t, s)
	rec, corps := appelle(s, "/radar", false) // vue réduite : celle du Hall
	if rec.Code != 200 {
		t.Fatalf("le radar est servi dans la vue réduite : %d", rec.Code)
	}
	brut := rec.Body.String()
	for _, interdit := range []string{"203.0.113.9", "git.gk2", "preuves", "src_ip", "target"} {
		if strings.Contains(brut, interdit) {
			t.Fatalf("la vue réduite ne porte jamais %q : %s", interdit, brut)
		}
	}
	acteurs, _ := corps["acteurs"].([]any)
	var a map[string]any
	for _, x := range acteurs { // la fixture crée un acteur par événement : on cherche celui qu'elle a rendu
		if m := x.(map[string]any); m["id"] == id {
			a = m
		}
	}
	if a == nil {
		t.Fatalf("l'acteur %s est dans le radar : %v", id, corps)
	}
	if a["niveau"] == nil || a["risque"] == nil || a["confiance"] == nil {
		t.Fatalf("id, niveau, risque et confiance : %v", a)
	}
	if et, _ := a["etapes"].([]any); len(et) < 3 {
		t.Fatalf("le scénario (étapes) accompagne l'acteur : %v", a)
	}
}

func TestRadar_RisqueEtConfianceSontSepares_FacteursSansPreuves(t *testing.T) {
	s := serveur(t)
	scenario(t, s)
	_, corps := appelle(s, "/radar", false)
	a := corps["acteurs"].([]any)[0].(map[string]any)
	r := a["risque"].(map[string]any)
	if r["valeur"] == nil || len(r["facteurs"].([]any)) == 0 {
		t.Fatalf("le risque porte sa valeur et ses facteurs : %v", r)
	}
	if _, ok := r["facteurs"].([]any)[0].(map[string]any)["preuves"]; ok {
		t.Fatalf("un facteur n'expose pas ses références de preuve")
	}
}

func TestRadar_TrieParRisqueEtBorneLeNombre(t *testing.T) {
	s := serveur(t)
	scenario(t, s)
	_, corps := appelle(s, "/radar?limit=1", false)
	if n := len(corps["acteurs"].([]any)); n != 1 {
		t.Fatalf("limit=1 : %d", n)
	}
}
