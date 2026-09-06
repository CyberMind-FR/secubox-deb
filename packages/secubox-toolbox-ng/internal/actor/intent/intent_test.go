// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package intent

import "testing"

// seuil au-dessus duquel un axe est jugé « élevé » dans les tests.
const seuilEleve = 60

// seuil en-dessous duquel un axe est jugé « bas » dans les tests.
const seuilBas = 30

// Signals{} ne doit produire aucune contribution : les trois axes à 0.
func TestScoresVide(t *testing.T) {
	i, a, p := Scores(Signals{})
	if i.Value != 0 || a.Value != 0 || p.Value != 0 {
		t.Fatalf("Scores(Signals{}) = (%d,%d,%d), attendu (0,0,0)", i.Value, a.Value, p.Value)
	}
	if len(i.Contributions) != 0 || len(a.Contributions) != 0 || len(p.Contributions) != 0 {
		t.Error("des contributions ont fuité sur un acteur sans signal")
	}
}

// Profil « scanner automatisé » : automation élevé, intention basse.
func TestScannerAutomatise(t *testing.T) {
	i, a, _ := Scores(Signals{
		RegularCadence:          true,
		IPRotationStablePayload: true,
		HighParallelism:         true,
		IdenticalTestOrder:      true,
	})
	if a.Value < seuilEleve {
		t.Errorf("automation = %d, attendu élevé (>= %d)", a.Value, seuilEleve)
	}
	if i.Value > seuilBas {
		t.Errorf("intention = %d, attendu bas (<= %d) — pas de couplage vers l'axe intention", i.Value, seuilBas)
	}
}

// Profil « ciblé humain » : intention élevée, automation basse.
func TestCibleHumain(t *testing.T) {
	i, a, _ := Scores(Signals{
		AdaptsToResponses:      true,
		ReconAuthEndpointChain: true,
		SpecificIdentifier:     true,
		ServicePivot:           true,
	})
	if i.Value < seuilEleve {
		t.Errorf("intention = %d, attendu élevé (>= %d)", i.Value, seuilEleve)
	}
	if a.Value > seuilBas {
		t.Errorf("automation = %d, attendu bas (<= %d) — pas de couplage vers l'axe automation", a.Value, seuilBas)
	}
}

// La persistence croît strictement avec le nombre de fenêtres de réapparition,
// jusqu'à saturation à 100.
func TestPersistenceCroit(t *testing.T) {
	prev := -1
	for w := 0; w <= 4; w++ {
		_, _, p := Scores(Signals{ReemergenceWindows: w})
		if w > 0 && p.Value <= prev && prev < 100 {
			t.Errorf("persistence(%d fenêtres) = %d, attendu > %d", w, p.Value, prev)
		}
		prev = p.Value
	}
	// Les autres signaux de persistence s'ajoutent bien.
	_, _, base := Scores(Signals{ReemergenceWindows: 1})
	_, _, plus := Scores(Signals{ReemergenceWindows: 1, ReturnsAfterSourceChange: true, SpansMultipleDays: true})
	if plus.Value <= base.Value {
		t.Errorf("persistence enrichie = %d, attendu > %d", plus.Value, base.Value)
	}
}

// Indépendance des axes : un acteur peut être simultanément très automatisé ET
// très ciblé (RFC-0003). Les deux axes doivent monter sans se voler de poids.
func TestAxesIndependants(t *testing.T) {
	i, a, _ := Scores(Signals{
		// automation
		RegularCadence:          true,
		IPRotationStablePayload: true,
		HighParallelism:         true,
		IdenticalTestOrder:      true,
		// intention
		AdaptsToResponses:      true,
		ReconAuthEndpointChain: true,
		SpecificIdentifier:     true,
		ServicePivot:           true,
	})
	if a.Value < seuilEleve {
		t.Errorf("automation = %d, attendu élevé (>= %d)", a.Value, seuilEleve)
	}
	if i.Value < seuilEleve {
		t.Errorf("intention = %d, attendu élevé (>= %d)", i.Value, seuilEleve)
	}

	// Vérifie qu'aucun signal d'un axe ne contribue à l'autre : l'axe automation
	// seul doit être identique qu'on ajoute ou non les signaux d'intention.
	_, aSeul, _ := Scores(Signals{
		RegularCadence:          true,
		IPRotationStablePayload: true,
		HighParallelism:         true,
		IdenticalTestOrder:      true,
	})
	if aSeul.Value != a.Value {
		t.Errorf("l'ajout de signaux d'intention a modifié l'axe automation (%d != %d)", aSeul.Value, a.Value)
	}
}
