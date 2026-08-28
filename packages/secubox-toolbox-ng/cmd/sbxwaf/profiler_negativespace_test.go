// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"strings"
	"testing"
)

// TestProfiler_NegativeSpaceIntensity — le profileur COMPTE les sondes de
// reconnaissance et, parmi elles, les sondes haute-valeur (#1240). C'est ce qui
// transforme une liste de lignes en caractérisation : « cet acteur a mené 3
// sondes de secret ». Les catégories à charge utile (sqli) ne comptent pas.
func TestProfiler_NegativeSpaceIntensity(t *testing.T) {
	// Un attaquant : 2 sondes haute-valeur (/.env, /.git/HEAD), 1 appât connu
	// (/admin.bak), 1 charge utile (sqli, NON étiquetée), 1 chemin anodin.
	lignes := []string{
		`{"client_ip":"185.10.0.1","timestamp":"t1","path":"/.env","category":"scanners","action":"warning","negative_space":"high_value_probe"}`,
		`{"client_ip":"185.10.0.1","timestamp":"t2","path":"/.git/HEAD","category":"scanners","action":"warning","negative_space":"high_value_probe"}`,
		`{"client_ip":"185.10.0.1","timestamp":"t3","path":"/admin.bak","category":"honeypot","action":"warning","negative_space":"known_negative"}`,
		`{"client_ip":"185.10.0.1","timestamp":"t4","path":"/api?id=1","category":"sqli","action":"banned"}`,
		`{"client_ip":"185.10.0.1","timestamp":"t5","path":"/accueil","category":"","action":"detect"}`,
	}
	profs := construireProfils(strings.NewReader(strings.Join(lignes, "\n")))
	p := profs["185.10.0.1"]
	if p == nil {
		t.Fatal("profil attendu pour 185.10.0.1")
	}
	if p.Sondes != 5 {
		t.Errorf("Sondes=%d, attendu 5", p.Sondes)
	}
	if p.Recon != 3 {
		t.Errorf("Recon=%d, attendu 3 (2 haute-valeur + 1 appât)", p.Recon)
	}
	if p.HauteValeur != 2 {
		t.Errorf("HauteValeur=%d, attendu 2 (/.env, /.git/HEAD)", p.HauteValeur)
	}

	// La campagne cumule la haute-valeur de ses attaquants.
	camps := clusteriser(profs)
	if len(camps) == 0 {
		t.Fatal("au moins une campagne attendue")
	}
	var total int
	for _, c := range camps {
		total += c.HauteValeur
	}
	if total != 2 {
		t.Errorf("HauteValeur cumulée des campagnes=%d, attendu 2", total)
	}
}
