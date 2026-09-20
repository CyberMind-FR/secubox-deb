// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// Tests de la normalisation de chemin (normaliser.go).
//
// Deux propriétés sont à prouver, et la seconde compte autant que la première :
//   1. la normalisation attrape ce que le décodage simple laissait passer ;
//   2. elle ne DÉFAIT rien — ni une prise existante, ni un chemin légitime.

package main

import (
	"strings"
	"testing"
)

func TestNormaliserDecodageRepete(t *testing.T) {
	cas := []struct {
		nom    string
		entree string
		veut   string
	}{
		// Un tour suffit — comportement historique, inchangé.
		{"encodage simple", "/%2eenv", "/.env"},
		{"chemin nu", "/api/v1/hub", "/api/v1/hub"},

		// Deux tours. C'est le trou que ce fichier ferme : `%252e` ne devient
		// `.` qu'au second passage.
		{"encodage double", "/%252eenv", "/.env"},
		{"double sur separateur", "/%252f%252eaws", "/.aws"},

		// Trois tours, la borne.
		{"encodage triple", "/%25252eenv", "/.env"},

		// Au-delà de la borne : on s'arrête, volontairement. Le résultat reste
		// partiellement encodé — c'est le prix assumé d'une borne, et c'est
		// préférable à une boucle que l'attaquant dimensionne.
		{"au-dela de la borne", "/%2525252eenv", "/%2eenv"},
	}

	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			if got := replierChemin(c.entree); got != c.veut {
				t.Errorf("replierChemin(%q) = %q, attendu %q", c.entree, got, c.veut)
			}
		})
	}
}

func TestNormaliserReplieSeparateurs(t *testing.T) {
	cas := []struct {
		nom    string
		entree string
		veut   string
	}{
		{"double slash", "//backend//.env", "/backend/.env"},
		{"slash triple", "///a", "/a"},
		{"segment point", "/a/./b", "/a/b"},
		{"point final", "/a/.", "/a/"},
		{"slash encode", "/%2f%2fetc", "/etc"},
		{"rien a replier", "/a/b/c", "/a/b/c"},
		{"racine", "/", "/"},

		// `..` est PRÉSERVÉ — c'est la signature que les motifs cherchent.
		// Le replier détruirait l'accusation en même temps que le masque.
		{"traversee preservee", "/a/../../etc/passwd", "/a/../../etc/passwd"},
		{"traversee encodee", "/%252e%252e/etc", "/../etc"},
	}

	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			if got := replierChemin(c.entree); got != c.veut {
				t.Errorf("replierChemin(%q) = %q, attendu %q", c.entree, got, c.veut)
			}
		})
	}
}

func TestNormaliserNeCassePasLesCheminsLegitimes(t *testing.T) {
	// Chemins réels du parc. Aucun ne doit être altéré : une normalisation qui
	// déforme le trafic légitime fabriquerait des faux positifs, ce qui est
	// exactement ce qu'on cherche à éviter.
	legitimes := []string{
		"/api/v1/hub/status",
		"/netmodes/",
		"/system/",
		"/portal/",
		"/cardlets/signal.html",
		"/shared/sbxui/spicy.css",
		"/gandalf/secubox-deb/src/commit/0c47765a/apt",
		"/healthz",
	}

	for _, p := range legitimes {
		t.Run(p, func(t *testing.T) {
			if got := replierChemin(p); got != p {
				t.Errorf("chemin legitime altere : %q -> %q", p, got)
			}
		})
	}
}

func TestVarianteNormaliseeVideQuandInutile(t *testing.T) {
	// Le cas NORMAL doit être gratuit : pas de variante, donc rien de plus à
	// scanner. Si ce test casse, chaque requête du parc paie un surcoût inutile.
	cas := []string{
		"/api/v1/hub",
		"/%2eenv", // un seul tour : identique au décodage existant
		"/healthz",
	}

	for _, p := range cas {
		t.Run(p, func(t *testing.T) {
			dejaDecode := unquotePlus(p)
			if v := varianteNormalisee(p, dejaDecode); v != "" {
				t.Errorf("variante inutile produite pour %q : %q", p, v)
			}
		})
	}
}

func TestVarianteNormaliseeProduiteQuandUtile(t *testing.T) {
	cas := []struct{ entree, veut string }{
		{"/%252eenv", "/.env"},
		{"//backend//.env", "/backend/.env"},
	}

	for _, c := range cas {
		t.Run(c.entree, func(t *testing.T) {
			v := varianteNormalisee(c.entree, unquotePlus(c.entree))
			if v != c.veut {
				t.Errorf("varianteNormalisee(%q) = %q, attendu %q", c.entree, v, c.veut)
			}
		})
	}
}

func TestNormaliserEncodageMalforme(t *testing.T) {
	// Un encodage malformé n'est pas une erreur à remonter : c'est le cas
	// ordinaire quand on inspecte du trafic hostile. On ne doit ni paniquer ni
	// rendre du vide.
	malformes := []string{"/%zz", "/%", "/%2", "/a%gg/b", ""}

	for _, p := range malformes {
		t.Run(strings.ReplaceAll(p, "%", "pct"), func(t *testing.T) {
			got := replierChemin(p) // ne doit pas paniquer
			if p != "" && got == "" {
				t.Errorf("replierChemin(%q) a rendu du vide", p)
			}
		})
	}
}

func TestNormaliserBorneLeTravail(t *testing.T) {
	// Garde-fou anti-DoS : une entrée fabriquée pour se redonner du travail ne
	// doit pas en obtenir plus que la borne. On vérifie la borne par son effet
	// observable — le résultat reste encodé au-delà de trois passes.
	profond := "/" + strings.Repeat("%25", 12) + "2eenv"
	got := replierChemin(profond)
	if !strings.Contains(got, "%") {
		t.Errorf("la borne n'a pas tenu : %q entierement decode en %q", profond, got)
	}
}
