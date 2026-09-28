// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package ser

import (
	"strings"
	"testing"
)

// LE REFUS NE CHANGE PAS ; CE QU'IL DIT, SI (#1333).
//
// Quand la pièce couvre la voix, on refuse de mesurer — c'est juste, et ça le
// restera : deux sources dans les mêmes bandes à la même énergie ne se
// séparent pas. Mais « pas assez de voix » envoie parler quelqu'un qui parle
// déjà, tandis que « la pièce vous couvre » envoie baisser le son. Même
// verdict, deux gestes opposés.

func peuDeVoix() Traits {
	t := ordinaire()
	t.TramesVoisees = 3
	t.PartVoisee = 0.02
	return t
}

func TestSansAmbianceLeRefusParleDeLaVoix(t *testing.T) {
	_, h := etalonne(t)
	lec := h.Evalue(peuDeVoix())
	if lec.Etat != Indetermine {
		t.Fatalf("on devrait refuser, on a eu %q", lec.Etat)
	}
	if lec.Motif != MotifPeuDeVoix {
		t.Errorf("motif %q, attendu %q : sans ambiance, c'est bien la voix qui manque",
			lec.Motif, MotifPeuDeVoix)
	}
}

func TestAvecUneAmbianceLeRefusAccuseLaPieceEtPasLaPersonne(t *testing.T) {
	_, h := etalonne(t)
	tr := peuDeVoix()
	tr.AmbianceBPM = 112
	tr.AmbiancePart = 0.3 // sous le seuil de la garde d'ambiance : c'est bien
	// le chemin « pas assez de voix » qui est emprunté.
	lec := h.Evalue(tr)
	if lec.Etat != Indetermine {
		t.Fatalf("on devrait refuser, on a eu %q", lec.Etat)
	}
	if lec.Motif != MotifAmbiance {
		t.Fatalf("motif %q, attendu %q : un tempo dans la pièce explique la voix "+
			"perdue mieux que « vous ne parlez pas »", lec.Motif, MotifAmbiance)
	}
	joint := strings.Join(lec.Pourquoi, " ")
	if !strings.Contains(joint, "112") {
		t.Errorf("le message ne dit pas le tempo mesuré : %q", joint)
	}
	// LE GESTE À FAIRE, PAS SEULEMENT LE CONSTAT. Un message qui décrit sans
	// proposer laisse le lecteur devant un écran qui a raison et ne sert à rien.
	if !strings.Contains(joint, "baissez") && !strings.Contains(joint, "approchez") {
		t.Errorf("le message ne dit pas quoi faire : %q", joint)
	}
}

func TestLaReserveEstTenueDansLesDeuxCas(t *testing.T) {
	_, h := etalonne(t)
	tr := peuDeVoix()
	tr.AmbianceBPM = 112
	for nom, lec := range map[string]Lecture{
		"sans ambiance": h.Evalue(peuDeVoix()),
		"avec ambiance": h.Evalue(tr),
	} {
		if lec.Confiance != 0 {
			t.Errorf("%s : confiance %.2f alors qu'on refuse de mesurer", nom, lec.Confiance)
		}
		if lec.Reserve == "" {
			t.Errorf("%s : aucune réserve sur un refus", nom)
		}
	}
}
