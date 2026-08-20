// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
package store

import "testing"

// deuxAuteurs crée deux comptes (ids 1 et 2) — la clé étrangère des articles
// vers users est active dans le schéma.
func deuxAuteurs(t *testing.T, s *Store) {
	t.Helper()
	for _, h := range []string{"gandalf", "anibal"} {
		if _, err := s.db.Exec(
			`INSERT INTO users(handle,display_name,role,created_at) VALUES(?,?,'member',1)`, h, h); err != nil {
			t.Fatal(err)
		}
	}
}

func TestArticleCollaboratif(t *testing.T) {
	s := ouvre(t)
	deuxAuteurs(t, s)
	id, err := s.CreerArticle("Notre lecture", 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	// Trois contributions, deux auteurs distincts (1 puis 2 puis 1).
	for _, c := range []struct {
		auteur int64
		corps  string
	}{{1, "Intro."}, {2, "Contexte."}, {1, "Conclusion."}} {
		if err := s.AjouterPart(id, c.auteur, c.corps); err != nil {
			t.Fatal(err)
		}
	}
	a, parts, err := s.Article(id)
	if err != nil {
		t.Fatal(err)
	}
	if len(parts) != 3 {
		t.Fatalf("%d contributions, attendu 3", len(parts))
	}
	if parts[0].Position != 1 || parts[2].Position != 3 {
		t.Errorf("positions non ordonnées : %d..%d", parts[0].Position, parts[2].Position)
	}
	if len(a.CoAuteurs) != 2 {
		t.Fatalf("%d co-auteurs, attendu 2 (déduplication par auteur)", len(a.CoAuteurs))
	}
	if a.NbParts != 3 {
		t.Errorf("NbParts=%d, attendu 3", a.NbParts)
	}
	if d, _ := s.Articles("draft", 10); len(d) != 1 {
		t.Fatalf("%d brouillons, attendu 1", len(d))
	}
	// Publication : l'article quitte les brouillons et retient son adresse.
	if err := s.MarquerArticlePublie(id, "https://billets.gk2.secubox.in/b/x"); err != nil {
		t.Fatal(err)
	}
	a2, _, _ := s.Article(id)
	if a2.Status != "published" || a2.PublishedURL == "" {
		t.Errorf("publication non enregistrée : %+v", a2)
	}
	if d, _ := s.Articles("draft", 10); len(d) != 0 {
		t.Errorf("%d brouillons après publication, attendu 0", len(d))
	}
	if d, _ := s.Articles("published", 10); len(d) != 1 {
		t.Errorf("%d publiés, attendu 1", len(d))
	}
}

func TestAjouterPartVideRefusee(t *testing.T) {
	s := ouvre(t)
	deuxAuteurs(t, s)
	id, _ := s.CreerArticle("X", 0, 1)
	if err := s.AjouterPart(id, 1, "   "); err == nil {
		t.Error("une contribution vide doit être refusée")
	}
}
