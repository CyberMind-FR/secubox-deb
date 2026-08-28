// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import "testing"

// TestClassifyPath — le contrat du brief P0-A (#1240) :
//   1. un chemin réel n'est jamais un signal ;
//   2. une 404 quelconque n'est PAS une attaque (le point central du brief) ;
//   3. un appât connu est un signal ;
//   4. une sonde de secret/exécution/admin est un signal FORT.
func TestClassifyPath(t *testing.T) {
	cas := []struct {
		nom     string
		path    string
		routed  bool
		ruleCat string
		class   string
		signal  bool
	}{
		// 1. chemin réel servi par un vhost → aucun signal, quoi qu'il matche.
		{"racine reelle", "/", true, "", pathKnownReal, false},
		{"page reelle", "/hall/index.html", true, "", pathKnownReal, false},

		// 2. 404 anodines → unknown, jamais de signal (ne pas crier au loup).
		{"404 navigateur", "/cette/page/nexiste/pas", false, "", pathUnknown, false},
		{"favicon absent", "/favicon-old.ico", false, "", pathUnknown, false},

		// 3. appâts connus (catégorie de reconnaissance) → known_negative + signal.
		{"honeypot", "/admin.bak", false, "honeypot", pathKnownNegative, true},
		{"scanner generique", "/some/scan/path", false, "scanners", pathKnownNegative, true},

		// 4. sondes HAUTE VALEUR → high_value_probe + signal, par marqueur…
		{"dotenv", "/.env", false, "", pathHighValueProbe, true},
		{"git head", "/.git/HEAD", false, "scanners", pathHighValueProbe, true},
		{"aws creds", "/.aws/credentials", false, "", pathHighValueProbe, true},
		{"actuator env", "/actuator/env", false, "scanners", pathHighValueProbe, true},
		{"phpmyadmin", "/phpMyAdmin/index.php", false, "", pathHighValueProbe, true},
		{"cgi-bin", "/cgi-bin/luci", false, "", pathHighValueProbe, true},
		// …ou par catégorie haute-valeur même sans marqueur de chemin.
		{"cred harvest cat", "/api/login?password=x", false, "credential_harvest", pathHighValueProbe, true},
		{"produit absent", "/global-protect/portal/css/bootstrap.min.css", false, "product_absent_probes", pathHighValueProbe, true},

		// robustesse : la casse ne doit pas faire échapper un marqueur.
		{"dotenv majuscule", "/.ENV", false, "", pathHighValueProbe, true},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			got := classifyPath(c.path, c.routed, c.ruleCat)
			if got.Class != c.class || got.Signal != c.signal {
				t.Fatalf("classifyPath(%q, routed=%v, cat=%q) = {%s, %v} ; attendu {%s, %v}",
					c.path, c.routed, c.ruleCat, got.Class, got.Signal, c.class, c.signal)
			}
		})
	}
}

// TestNegativeSpace_404Sequence — une SÉQUENCE de sondes doit produire plusieurs
// signaux (matière première du profileur : « /.env → /phpmyadmin → /wp-login »),
// tandis qu'une navigation humaine n'en produit aucun.
func TestNegativeSpace_404Sequence(t *testing.T) {
	sondes := []string{"/.env", "/phpmyadmin", "/.git/config"}
	signaux := 0
	for _, p := range sondes {
		if classifyPath(p, false, "").Signal {
			signaux++
		}
	}
	if signaux != len(sondes) {
		t.Fatalf("séquence de sondes : %d signaux sur %d attendus", signaux, len(sondes))
	}
	// Navigation humaine : trois pages absentes mais anodines → zéro signal.
	humain := []string{"/blog/2019/été", "/produits?ref=42", "/contact.html"}
	for _, p := range humain {
		if classifyPath(p, false, "").Signal {
			t.Fatalf("faux positif : %q classé comme signal", p)
		}
	}
}
