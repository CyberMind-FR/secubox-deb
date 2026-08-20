// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import "testing"

func TestIdentifierOutil_UANomme(t *testing.T) {
	cas := []struct {
		ua, path string
		nom      string
		certain  bool
	}{
		{"Nuclei - Open-source project (github.com/projectdiscovery/nuclei)", "/", "nuclei", true},
		{"sqlmap/1.7#stable", "/?id=1", "sqlmap", true},
		{"WPScan v3.8", "/", "wpscan", true},
		{"gobuster/3.6", "/admin", "gobuster", true},
		{"Mozilla/5.0 zgrab/0.x", "/", "zgrab", true},
		// UA anodin mais chemin caractéristique → probable (pas certain).
		{"Mozilla/5.0", "/wp-json/wp/v2/users", "wpscan", false},
		// Navigateur normal → rien.
		{"Mozilla/5.0 (X11; Linux x86_64) Firefox/128.0", "/index.html", "", false},
	}
	for _, c := range cas {
		nom, _, certain := identifierOutil(c.ua, c.path)
		if nom != c.nom || certain != c.certain {
			t.Errorf("identifierOutil(%q,%q) = (%q,%v) ; attendu (%q,%v)",
				c.ua, c.path, nom, certain, c.nom, c.certain)
		}
	}
}

func TestEtiquetteOutil(t *testing.T) {
	if got := étiquetteOutil("nuclei/3", "/"); got != "nuclei" {
		t.Errorf("UA nuclei → %q ; attendu nuclei", got)
	}
	if got := étiquetteOutil("Mozilla/5.0", "/wp-json/wp/v2/users"); got != "cms-scanner?" {
		t.Errorf("chemin wpscan sans UA → %q ; attendu cms-scanner?", got)
	}
	if got := étiquetteOutil("Mozilla/5.0 Firefox/128", "/"); got != "" {
		t.Errorf("navigateur → %q ; attendu vide", got)
	}
}
