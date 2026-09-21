// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// Tests de MatchDetail — l'identifiant du motif qui a touché (#1313).
//
// LE DOSSIER TECHNIQUE ANSSI PROMET « l'explicabilité des décisions de blocage
// et la possibilité de retour arrière ». Une décision qu'on ne peut pas
// rattacher à SA règle n'est pas explicable : on sait qu'on a bloqué, pas sur
// quoi. Ces tests verrouillent le lien.

package main

import (
	"os"
	"path/filepath"
	"testing"
)

const reglesDetail = `{
  "_meta": {"version": "test"},
  "categories": {
    "scanners": {
      "name": "Scanners", "severity": "high", "mode": "detect",
      "patterns": [
        {"id": "scan-aaa", "pattern": "/\\.env", "desc": "secrets"},
        {"id": "scan-bbb", "pattern": "/wp-login", "desc": "wordpress"}
      ]
    },
    "sqli": {
      "name": "SQLi", "severity": "critical", "mode": "block",
      "patterns": [{"id": "sqli-001", "pattern": "union\\s+select", "desc": "union"}]
    }
  }
}`

func reglesPour(t *testing.T) *Rules {
	t.Helper()
	dir := t.TempDir()
	f := filepath.Join(dir, "waf-rules.json")
	if err := os.WriteFile(f, []byte(reglesDetail), 0o644); err != nil {
		t.Fatalf("écriture des règles : %v", err)
	}
	return LoadRules(f)
}

func TestMatchDetailRendLIdentifiantDuMotif(t *testing.T) {
	r := reglesPour(t)

	cas := []struct {
		nom, chemin, cat, motif string
	}{
		{"secrets", "/.env", "scanners", "scan-aaa"},
		{"wordpress", "/wp-login.php", "scanners", "scan-bbb"},
		{"injection", "/x", "sqli", "sqli-001"},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			corps := ""
			if c.cat == "sqli" {
				corps = "union select 1"
			}
			cat, _, _, motif, hit := r.MatchDetail("GET", c.chemin, "", corps, "", true, nil)
			if !hit {
				t.Fatalf("aucune touche pour %q", c.chemin)
			}
			if cat != c.cat || motif != c.motif {
				t.Errorf("MatchDetail(%q) = cat %q motif %q, attendu %q / %q",
					c.chemin, cat, motif, c.cat, c.motif)
			}
		})
	}
}

func TestMatchDetailDistingueDeuxMotifsDeLaMemeCategorie(t *testing.T) {
	// LE POINT DE TOUT L'EXERCICE. La catégorie seule ne suffisait pas : deux
	// motifs très différents de `scanners` rendaient la même ligne de journal.
	// Impossible, en la lisant, de savoir lequel avait décidé — donc impossible
	// de mesurer si l'un d'eux servait encore, ou n'avait jamais rien attrapé
	// depuis qu'on l'avait écrit (#1310, cinq motifs CVE inertes).
	r := reglesPour(t)

	_, _, _, m1, _ := r.MatchDetail("GET", "/.env", "", "", "", true, nil)
	_, _, _, m2, _ := r.MatchDetail("GET", "/wp-login.php", "", "", "", true, nil)

	if m1 == m2 {
		t.Fatalf("les deux motifs rendent le même identifiant %q — la catégorie "+
			"seule ne distingue rien", m1)
	}
}

func TestMatchDetailSansToucheNeRendAucunMotif(t *testing.T) {
	r := reglesPour(t)
	cat, _, _, motif, hit := r.MatchDetail("GET", "/api/v1/hub/status", "", "", "", true, nil)
	if hit || cat != "" || motif != "" {
		t.Errorf("chemin légitime pris à tort : cat=%q motif=%q hit=%v", cat, motif, hit)
	}
}

func TestMatchExceptGardeExactementSonComportement(t *testing.T) {
	// NON-RÉGRESSION. `MatchDetail` est une AJOUT : les trois méthodes
	// existantes gardent leur signature et leur verdict, parce que 25 appels de
	// test en dépendent et que les faire bouger aurait mélangé un changement de
	// fond avec du bruit de refonte.
	r := reglesPour(t)

	cat, sev, mode, hit := r.MatchExcept("GET", "/.env", "", "", "", true, nil)
	catD, sevD, modeD, _, hitD := r.MatchDetail("GET", "/.env", "", "", "", true, nil)

	if cat != catD || sev != sevD || mode != modeD || hit != hitD {
		t.Errorf("MatchExcept et MatchDetail divergent : (%q,%q,%q,%v) vs (%q,%q,%q,%v)",
			cat, sev, mode, hit, catD, sevD, modeD, hitD)
	}
}

func TestMatchDetailHonoreLExclusionDeCategorie(t *testing.T) {
	r := reglesPour(t)
	// `/.env` touche `scanners`. En excluant cette catégorie, plus rien ne doit
	// toucher — et surtout aucun motif ne doit être rendu.
	cat, _, _, motif, hit := r.MatchDetail("GET", "/.env", "", "", "", true,
		map[string]bool{"scanners": true})
	if hit || cat != "" || motif != "" {
		t.Errorf("catégorie exclue mais touche rendue : cat=%q motif=%q", cat, motif)
	}
}

func TestMatchDetailReglesVidesNePaniquePas(t *testing.T) {
	// Un fichier de règles absent rend un jeu vide : le moteur doit se taire,
	// pas tomber. C'est le comportement en production quand le fichier n'a pas
	// encore été ensemencé.
	r := LoadRules(filepath.Join(t.TempDir(), "absent.json"))
	cat, sev, mode, motif, hit := r.MatchDetail("GET", "/.env", "", "", "", true, nil)
	if hit || cat != "" || sev != "" || mode != "" || motif != "" {
		t.Errorf("règles vides : touche inattendue cat=%q motif=%q", cat, motif)
	}
}
