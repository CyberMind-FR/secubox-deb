// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
package cluster

import (
	"fmt"
	"testing"
)

// scoreAvant : Score tel qu'il était avant les Formes (#1835), recopié tel
// quel. ScoreFormes doit rendre la MÊME valeur au bit près : un écart, même
// infime, ferait basculer des articles d'un côté ou de l'autre du seuil.
func scoreAvant(titreA string, entA []string, pubA int64, titreT string, entT []string, majT int64) float64 {
	sTitre := SimTitres(titreA, titreT)
	sEnt := Jaccard(ensemble(entA), ensemble(entT))
	sRec := Recence(pubA - majT)
	if sRec <= 0 {
		return 0
	}
	if sEnt == 0 && sTitre < 0.55 {
		return 0
	}
	contenu := 0.35*sTitre + 0.65*sEnt
	return contenu * (0.75 + 0.25*sRec)
}

func TestScoreFormesIdentiqueAuBitPres(t *testing.T) {
	titres := []string{
		"Incendie important près de Marseille",
		"Un feu mobilise 300 pompiers près de Marseille",
		"La BCE relève ses taux directeurs",
		"BCE : nouvelle hausse des taux en zone euro",
		"Grève à la SNCF : trafic perturbé lundi",
		"Séisme de magnitude 7 au Japon",
		"Élections en Allemagne : la CDU en tête",
		"PSG – OM : le Classique tourne à l'avantage de Paris",
		"Vidéo. $content.TitleNoTags",
		"",
	}
	dates := []int64{0, 600, 3600 * 12, FenetreSec - 1, FenetreSec, FenetreSec * 2}
	paires, positifs := 0, 0
	for i, a := range titres {
		for j, b := range titres {
			for _, d := range dates {
				ea, eb := Entites(a), Entites(b)
				const base = int64(1_700_000_000)
				attendu := scoreAvant(a, ea, base+d, b, eb, base)
				obtenu := ScoreFormes(Prepare(a, ea, base+d), Prepare(b, eb, base))
				if obtenu != attendu {
					t.Fatalf("paire %d/%d Δ%d : %v ≠ %v", i, j, d, obtenu, attendu)
				}
				if Score(a, ea, base+d, b, eb, base) != attendu {
					t.Fatalf("Score %d/%d Δ%d diverge", i, j, d)
				}
				paires++
				if attendu > 0 {
					positifs++
				}
			}
		}
	}
	if positifs == 0 {
		t.Fatal("aucune paire au-dessus de zéro : le corpus ne teste rien")
	}
	t.Log(fmt.Sprintf("%d paires, %d non nulles", paires, positifs))
}
