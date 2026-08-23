// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
package cluster

import "testing"

func TestSimTitresProches(t *testing.T) {
	a := "Incendie important près de Marseille"
	b := "Un feu mobilise 300 pompiers près de Marseille"
	c := "Nouvelle hausse des taux de la BCE"
	if SimTitres(a, a) < 0.99 {
		t.Fatalf("identité devrait valoir 1, got %.2f", SimTitres(a, a))
	}
	if s := SimTitres(a, b); s < 0.15 {
		t.Errorf("titres du même événement trop bas : %.2f", s)
	}
	if SimTitres(a, c) >= SimTitres(a, b) {
		t.Errorf("un titre hors-sujet ne doit pas être plus proche")
	}
}

func TestEntitesNomsPropres(t *testing.T) {
	e := Entites("Un feu ravage la région de Marseille dans les Bouches-du-Rhône")
	has := func(x string) bool {
		for _, v := range e {
			if v == x {
				return true
			}
		}
		return false
	}
	if !has("marseille") {
		t.Errorf("Marseille devrait être une entité, got %v", e)
	}
}

// L'exemple canonique de la spec : 3 dépêches sur l'incendie de Marseille
// doivent se regrouper (score ≥ seuil), pas rester 3 sujets séparés.
func TestScoreRegroupeIncendie(t *testing.T) {
	now := int64(1_700_000_000)
	// sujet ouvert par la 1ère dépêche
	tTitre := "Incendie important près de Marseille"
	tEnt := Entites("Incendie important près de Marseille")
	// 2e dépêche, même événement
	aTitre := "Un feu mobilise 300 pompiers près de Marseille dans les Bouches-du-Rhône"
	aEnt := Entites(aTitre)
	sc := Score(aTitre, aEnt, now+600, tTitre, tEnt, now)
	if sc < Seuil {
		t.Fatalf("même événement sous le seuil : %.2f < %.2f", sc, Seuil)
	}
	// dépêche hors-sujet : sous le seuil
	oTitre := "La BCE relève ses taux directeurs"
	scOff := Score(oTitre, Entites(oTitre), now+600, tTitre, tEnt, now)
	if scOff >= Seuil {
		t.Errorf("événement distinct ne doit pas rejoindre : %.2f", scOff)
	}
}

func TestRecenceDecroit(t *testing.T) {
	if Recence(0) < 0.99 || Recence(FenetreSec) != 0 || Recence(FenetreSec/2) <= 0 {
		t.Errorf("récence mal bornée")
	}
}
