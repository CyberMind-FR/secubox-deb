// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
package resume

import (
	"strings"
	"testing"
)

func TestResumePrivilegieCommun(t *testing.T) {
	items := []Item{
		{Titre: "Incendie à Marseille", Corps: "Un incendie mobilise des centaines de pompiers. La circulation est coupée."},
		{Titre: "Feu près de Marseille", Corps: "Un incendie mobilise des centaines de pompiers dans la région. Des évacuations."},
		{Titre: "Wildfire Marseille", Corps: "Un incendie mobilise des centaines de pompiers. Contexte régional."},
	}
	r := Resume(items, 2)
	if r == "" {
		t.Fatal("résumé vide")
	}
	// la phrase commune aux 3 sources doit être retenue.
	if !strings.Contains(strings.ToLower(r), "mobilise des centaines de pompiers") {
		t.Errorf("le résumé devrait retenir la phrase commune : %q", r)
	}
}

func TestResumeReplisurTitre(t *testing.T) {
	r := Resume([]Item{{Titre: "Titre seul sans corps exploitable ici", Corps: ""}}, 3)
	if r == "" {
		t.Errorf("devrait retomber sur le titre")
	}
}
