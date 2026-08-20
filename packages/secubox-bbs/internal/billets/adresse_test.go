// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
package billets

import "testing"

func TestAdressePubliee(t *testing.T) {
	const base = "https://billets.gk2.secubox.in"
	cas := []struct {
		nom                          string
		base, perma, url, slug, veut string
	}{
		// Absolue : rendue telle quelle, la base ne s'en mêle pas.
		{"permalien absolu d'abord", base, "https://b.example/b/x", "https://autre/y", "x",
			"https://b.example/b/x"},
		{"url absolue si pas de permalien", base, "", "https://b.example/b/x", "x",
			"https://b.example/b/x"},
		// RELATIVE + base connue : on ABSOLUTISE sur la base publique. C'est le
		// cœur de #1056 — billets (BILLETS_SITE_URL absent) rend un permalien
		// relatif ; le BBS, lui, connaît l'origine publique via --billets-base.
		{"permalien relatif absolutisé", base, "/b/mon-billet", "", "mon-billet",
			"https://billets.gk2.secubox.in/b/mon-billet"},
		{"slug absolutisé sur la base", base, "", "", "titre-abcd",
			"https://billets.gk2.secubox.in/b/titre-abcd"},
		{"base à slash final", base + "/", "/b/x", "", "x",
			"https://billets.gk2.secubox.in/b/x"},
		// Base INCONNUE : on garde le relatif — inventer un hôte donnerait un
		// lien mort présenté comme bon. Comportement honnête d'origine.
		{"sans base, permalien relatif reste relatif", "", "/b/x", "", "x", "/b/x"},
		{"sans base, slug reste relatif", "", "", "", "titre-abcd", "/b/titre-abcd"},
		{"rien du tout reste vide", base, "", "", "", ""},
		// Un champ présent mais blanc vaut absent.
		{"blancs traités comme vides", base, "   ", "\t", "x",
			"https://billets.gk2.secubox.in/b/x"},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			if got := adressePubliee(c.base, c.perma, c.url, c.slug); got != c.veut {
				t.Errorf("adressePubliee(%q,%q,%q,%q) = %q, veut %q",
					c.base, c.perma, c.url, c.slug, got, c.veut)
			}
		})
	}
}
