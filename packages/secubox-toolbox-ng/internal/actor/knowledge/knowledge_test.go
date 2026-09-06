// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package knowledge

import "testing"

// inBand vérifie qu'une valeur tombe dans la bande [floor,ceil] du niveau.
func inBand(v, level int) bool {
	return v >= bandFloor[level] && v <= bandCeil[level]
}

// TestScoreNil : aucune observation → aucune connaissance → 0.
func TestScoreNil(t *testing.T) {
	if got := Score(nil).Value; got != 0 {
		t.Errorf("Score(nil).Value = %d, attendu 0", got)
	}
	if got := Score([]Observation{}).Value; got != 0 {
		t.Errorf("Score([]).Value = %d, attendu 0", got)
	}
}

// TestBandeK0 : une observation générique reste dans 0..5.
func TestBandeK0(t *testing.T) {
	s := Score([]Observation{{Level: K0Generic, Detail: "login admin", EvidenceID: "ev-k0"}})
	if !inBand(s.Value, K0Generic) {
		t.Errorf("K0 score = %d, hors bande 0..5", s.Value)
	}
}

// TestBandeK3 : un login historique tombe dans 45..75.
func TestBandeK3(t *testing.T) {
	s := Score([]Observation{{Level: K3Historical, Detail: "alias jadis actif", EvidenceID: "ev-k3"}})
	if !inBand(s.Value, K3Historical) {
		t.Errorf("K3 score = %d, hors bande 45..75", s.Value)
	}
}

// TestBandeK4 : un canari touché tombe dans 75..100.
func TestBandeK4(t *testing.T) {
	s := Score([]Observation{{Level: K4Sentinel, Detail: "canari SSH touché", EvidenceID: "ev-k4"}})
	if !inBand(s.Value, K4Sentinel) {
		t.Errorf("K4 score = %d, hors bande 75..100", s.Value)
	}
}

// TestExpositionPublique : une info exposée dans une fuite ne doit jamais être
// surévaluée — même observation, le score chute nettement (rang public).
func TestExpositionPublique(t *testing.T) {
	confidentiel := Score([]Observation{{Level: K3Historical, Detail: "login historique", EvidenceID: "ev-a"}})
	fuite := Score([]Observation{{Level: K3Historical, Detail: "login historique", EvidenceID: "ev-a", PubliclyExposed: true}})

	if fuite.Value >= confidentiel.Value {
		t.Errorf("exposé (%d) devrait être nettement < confidentiel (%d)", fuite.Value, confidentiel.Value)
	}
	// Rétrogradé au rang public : la valeur doit retomber sous le plancher K3.
	if fuite.Value >= bandFloor[K3Historical] {
		t.Errorf("exposé (%d) devrait retomber sous le plancher K3 (%d)", fuite.Value, bandFloor[K3Historical])
	}
	if !inBand(fuite.Value, K1Public) {
		t.Errorf("exposé (%d) hors bande publique 5..20", fuite.Value)
	}
}

// TestBasNiveauNeDepassePasHautNiveau : un cumul d'observations de bas niveau
// ne rattrape jamais une seule observation de niveau supérieur.
func TestBasNiveauNeDepassePasHautNiveau(t *testing.T) {
	bas := make([]Observation, 20)
	for i := range bas {
		bas[i] = Observation{Level: K1Public, Detail: "compte public", EvidenceID: "ev-pub"}
	}
	basScore := Score(bas)
	hautScore := Score([]Observation{{Level: K3Historical, Detail: "login historique", EvidenceID: "ev-hist"}})

	if basScore.Value >= hautScore.Value {
		t.Errorf("20 obs bas niveau (%d) >= 1 obs haut niveau (%d)", basScore.Value, hautScore.Value)
	}
	if !inBand(basScore.Value, K1Public) {
		t.Errorf("cumul K1 (%d) hors bande 5..20", basScore.Value)
	}
}

// TestIncrementObservations : une observation de plus, à niveau max inchangé,
// accroît le score sans quitter la bande.
func TestIncrementObservations(t *testing.T) {
	une := Score([]Observation{{Level: K3Historical, Detail: "login A", EvidenceID: "ev-1"}})
	deux := Score([]Observation{
		{Level: K3Historical, Detail: "login A", EvidenceID: "ev-1"},
		{Level: K3Historical, Detail: "login B", EvidenceID: "ev-2"},
	})
	if deux.Value <= une.Value {
		t.Errorf("2 obs K3 (%d) devrait > 1 obs K3 (%d)", deux.Value, une.Value)
	}
	if !inBand(deux.Value, K3Historical) {
		t.Errorf("2 obs K3 (%d) hors bande 45..75", deux.Value)
	}
	// Une observation de niveau inférieur ajoutée incrémente aussi, sans sortir.
	mixte := Score([]Observation{
		{Level: K3Historical, Detail: "login A", EvidenceID: "ev-1"},
		{Level: K0Generic, Detail: "chemin standard", EvidenceID: "ev-3"},
	})
	if mixte.Value <= une.Value {
		t.Errorf("K3+K0 (%d) devrait > K3 seul (%d)", mixte.Value, une.Value)
	}
	if !inBand(mixte.Value, K3Historical) {
		t.Errorf("K3+K0 (%d) hors bande 45..75", mixte.Value)
	}
}

// TestBorneA100 : une avalanche de canaris reste bornée à 100 et dans la bande.
func TestBorneA100(t *testing.T) {
	obs := make([]Observation, 500)
	for i := range obs {
		obs[i] = Observation{Level: K4Sentinel, Detail: "canari", EvidenceID: "ev-k4"}
	}
	s := Score(obs)
	if s.Value > 100 {
		t.Errorf("score = %d, doit être borné à 100", s.Value)
	}
	if !inBand(s.Value, K4Sentinel) {
		t.Errorf("cumul K4 (%d) hors bande 75..100", s.Value)
	}
}

// TestContributionsTracables : chaque observation devient une contribution
// traçable (Detail→Label, EvidenceID conservé) et les versions sont figées.
func TestContributionsTracables(t *testing.T) {
	s := Score([]Observation{
		{Level: K2Contextual, Detail: "structure interne", EvidenceID: "ev-x"},
		{Level: K1Public, Detail: "domaine public", EvidenceID: "ev-y"},
	})
	if len(s.Contributions) != 2 {
		t.Fatalf("attendu 2 contributions, obtenu %d", len(s.Contributions))
	}
	if s.Contributions[0].Label != "structure interne" || s.Contributions[0].EvidenceID != "ev-x" {
		t.Errorf("contribution 0 mal reportée : %+v", s.Contributions[0])
	}
	if s.AlgorithmVer == "" || s.WeightsVer == "" {
		t.Error("versions d'algorithme/poids non figées")
	}
	// La somme des poids doit égaler la valeur restituée (score explicable).
	sum := 0
	for _, c := range s.Contributions {
		sum += c.Weight
	}
	if sum != s.Value {
		t.Errorf("somme des poids (%d) != Value (%d)", sum, s.Value)
	}
}
