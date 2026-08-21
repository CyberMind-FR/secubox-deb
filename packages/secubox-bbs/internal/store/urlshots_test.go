// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
package store

import "testing"

// TestMigrationUrlshotsCreeLaTable prouve que la migration 0023 crée bien la
// table urlshots — une insertion minimale (colonnes par défaut) doit réussir.
func TestMigrationUrlshotsCreeLaTable(t *testing.T) {
	s := ouvre(t)
	if _, err := s.db.Exec(`INSERT INTO urlshots(cle,url) VALUES('abc','https://x')`); err != nil {
		t.Fatalf("table urlshots absente : %v", err)
	}
}

// TestCleUrlshotStableEtNormalisee prouve que CleUrlshot normalise le schéma
// et l'hôte en minuscules, retire le fragment, et rejette les URL non http(s).
func TestCleUrlshotStableEtNormalisee(t *testing.T) {
	a := CleUrlshot("HTTPS://Example.COM/p?a=1#frag")
	b := CleUrlshot("https://example.com/p?a=1")
	if a == "" || a != b {
		t.Fatalf("clé instable/non normalisée : %q vs %q", a, b)
	}
	if len(a) != 32 {
		t.Fatalf("clé de longueur %d, attendu 32", len(a))
	}
	if CleUrlshot("ftp://x") != "" || CleUrlshot("/relatif") != "" {
		t.Fatal("une URL non http(s) doit donner une clé vide")
	}
}

// TestEnfileMonteLaVisibiliteJamaisNeLaBaisse prouve que EnfileUrlshot insère
// une ligne pending, puis MONTE la visibilité à 'public' sans jamais la
// redescendre — une fois public, reste public (miroir /f/ #1114).
func TestEnfileMonteLaVisibiliteJamaisNeLaBaisse(t *testing.T) {
	s := ouvre(t)
	cle := CleUrlshot("https://x.example/a")
	if err := s.EnfileUrlshot(cle, "https://x.example/a", "local"); err != nil {
		t.Fatal(err)
	}
	if err := s.EnfileUrlshot(cle, "https://x.example/a", "public"); err != nil { // monte
		t.Fatal(err)
	}
	if err := s.EnfileUrlshot(cle, "https://x.example/a", "local"); err != nil { // ne redescend pas
		t.Fatal(err)
	}
	_, vis, ok := s.StatutUrlshot(cle)
	if !ok || vis != "public" {
		t.Fatalf("visibilité = %q (ok=%v), attendu public", vis, ok)
	}
}
