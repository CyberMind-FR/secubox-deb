// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import "testing"

// #3945 : un relevé toutes les 10 min, douze au plus, jamais le relevé courant dans le passé, rien au-delà de deux heures.
func TestPasseBornee(t *testing.T) {
	var anneau, pub []PaysPasse
	for i := int64(0); i < 200; i++ { // un appel par minute
		now := 1_000_000 + i*60
		pub, anneau = passe(anneau, now, []PaysN{{Code: "FR", N: int(i)}})
		if len(pub) > passeMax || len(anneau) > passeMax {
			t.Fatalf("bornes dépassées : %d publiés, %d gardés", len(pub), len(anneau))
		}
		for k, p := range pub {
			if p.T >= now || p.T <= now-passeAge || (k > 0 && p.T-pub[k-1].T < passePas) {
				t.Fatalf("relevé %d mal daté (%d pour %d)", k, p.T, now)
			}
			if int64(p.Pays[0].N) != (p.T-1_000_000)/60 {
				t.Fatalf("valeur qui n'est pas celle du relevé : %+v", p)
			}
		}
	}
	if len(pub) != passeMax {
		t.Fatalf("douze relevés attendus, %d publiés", len(pub))
	}
	// après une longue absence, rien de périmé ; une horloge reculée n'annonce pas un passé futur
	if pub, _ = passe(anneau, 2_000_000, nil); len(pub) != 0 {
		t.Fatalf("relevés périmés publiés : %+v", pub)
	}
	if pub, _ = passe(anneau, 1_000_000, nil); len(pub) != 0 {
		t.Fatalf("relevés futurs publiés : %+v", pub)
	}
}
