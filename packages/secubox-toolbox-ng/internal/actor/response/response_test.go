// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package response

import "testing"

func TestRecommend_FaibleConfianceNEscaladePas(t *testing.T) {
	// Forte gravité/ciblage MAIS confiance faible → jamais au-delà d'OBSERVE.
	r := Recommend(95, 90, 90, 20, nil, true)
	if r.Mode != ModeObserve {
		t.Fatalf("faible confiance devrait rester OBSERVE, obtenu %s", r.Mode)
	}
	// Connaissance élevée → observation renforcée.
	if r.Reason == "" {
		t.Error("raison manquante")
	}
}

func TestRecommend_Escalade(t *testing.T) {
	cas := []struct {
		sev, know, intent, conf int
		mode                    Mode
	}{
		{5, 0, 5, 40, ModeObserve},  // générique
		{30, 10, 20, 50, ModeDelay}, // bruit automatisé
		{50, 40, 45, 60, ModeChallenge},
		{70, 55, 65, 70, ModeTarpit},
		{85, 70, 80, 80, ModeDeny},
		{98, 90, 92, 95, ModeQuarantine},
	}
	for _, c := range cas {
		r := Recommend(c.sev, c.know, c.intent, c.conf, nil, true)
		if r.Mode != c.mode {
			t.Errorf("Recommend(sev=%d know=%d int=%d conf=%d) = %s, attendu %s",
				c.sev, c.know, c.intent, c.conf, r.Mode, c.mode)
		}
	}
}

func TestRecommend_ToujoursReversibleEtShadow(t *testing.T) {
	r := Recommend(98, 90, 92, 95, []string{"ev-1"}, true)
	if !r.Rollbackable {
		t.Error("toute recommandation doit être réversible")
	}
	if !r.Shadow {
		t.Error("Phase 0/1 : Shadow doit être vrai (aucune application)")
	}
	if r.TTL <= 0 {
		t.Error("un blocage doit avoir un TTL (plafond)")
	}
	if len(r.EvidenceRefs) != 1 {
		t.Error("les preuves doivent être portées")
	}
	// OBSERVE n'a pas de TTL (rien à expirer).
	if Recommend(5, 0, 0, 40, nil, true).TTL != 0 {
		t.Error("OBSERVE ne devrait pas avoir de TTL")
	}
}
