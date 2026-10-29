// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package collecte

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/CyberMind-FR/secubox-deb/secubox-pilotage-agent/internal/modele"
)

const gk5 = "testdata/gk5"

func lireTout(t *testing.T, s modele.Source) map[string]any {
	t.Helper()
	p, err := s.Lire(context.Background())
	if err != nil {
		t.Fatalf("%s : %v", s.Nom(), err)
	}
	return p
}

// gabarit remplace chaque indice numérique d'un chemin par « {i} ».
func gabarit(chemin string) string {
	parts := strings.Split(chemin, ".")
	for i, p := range parts {
		if _, err := fmt.Sscanf(p, "%d", new(int)); err == nil && strings.Trim(p, "0123456789") == "" {
			parts[i] = "{i}"
		}
	}
	return strings.Join(parts, ".")
}

// verifierChemins impose que tout chemin rendu par Lire soit annoncé par Chemins.
func verifierChemins(t *testing.T, s modele.Source, p map[string]any) {
	t.Helper()
	d, ok := s.(modele.Declarant)
	if !ok {
		t.Fatalf("%s n'implémente pas Declarant", s.Nom())
	}
	annonces := map[string]bool{}
	for _, c := range d.Chemins() {
		annonces[c] = true
	}
	for k := range p {
		if !annonces[gabarit(k)] {
			t.Errorf("%s : %s non annoncé par Chemins()", s.Nom(), k)
		}
	}
}
