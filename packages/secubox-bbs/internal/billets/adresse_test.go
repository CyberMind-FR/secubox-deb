// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
package billets

import "testing"

func TestAdressePubliee(t *testing.T) {
	cas := []struct {
		nom                    string
		perma, url, slug, veut string
	}{
		{"permalien d'abord", "https://b.example/b/x", "https://autre/y", "x",
			"https://b.example/b/x"},
		{"url si pas de permalien", "", "https://b.example/b/x", "x",
			"https://b.example/b/x"},
		{"slug en dernier recours", "", "", "titre-abcd", "/b/titre-abcd"},
		{"rien du tout reste vide", "", "", "", ""},
		// Un champ present mais blanc vaut absent : le stocker donnerait un
		// lien vide qui a l'air renseigne.
		{"blancs traites comme vides", "   ", "\t", "x", "/b/x"},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			if got := adressePubliee(c.perma, c.url, c.slug); got != c.veut {
				t.Errorf("adressePubliee(%q,%q,%q) = %q, veut %q",
					c.perma, c.url, c.slug, got, c.veut)
			}
		})
	}
}
