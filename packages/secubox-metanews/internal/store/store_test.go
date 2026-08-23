// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
package store

import (
	"path/filepath"
	"testing"
)

func ouvrir(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("open : %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestSourceCRUD(t *testing.T) {
	s := ouvrir(t)
	id, err := s.AddSource(Source{Slug: "fi", Name: "France Info", URL: "https://x/rss", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	srcs, _ := s.Sources()
	if len(srcs) != 1 || srcs[0].ID != id || !srcs[0].Enabled || srcs[0].RefreshSec != 900 {
		t.Fatalf("source inattendue : %+v", srcs)
	}
	// due car last_sync=0
	dues, _ := s.SourcesDues(10000)
	if len(dues) != 1 {
		t.Errorf("source devrait être due")
	}
	_ = s.MarquerSync(id, 10000, "")
	if dues, _ := s.SourcesDues(10001); len(dues) != 0 {
		t.Errorf("source synchronisée ne devrait plus être due")
	}
}

func TestUpsertIdempotent(t *testing.T) {
	s := ouvrir(t)
	sid, _ := s.AddSource(Source{Slug: "a", Name: "A", URL: "u", Enabled: true})
	a := Article{SourceID: sid, Ref: "r1", Title: "T", URL: "http://x", Fingerprint: "fp", PublishedAt: 5}
	id1, neuf1, _ := s.UpsertArticle(a)
	id2, neuf2, _ := s.UpsertArticle(a) // même (source,ref)
	if !neuf1 || neuf2 || id1 != id2 {
		t.Fatalf("idempotence cassée : neuf1=%v neuf2=%v %d/%d", neuf1, neuf2, id1, id2)
	}
	arts, _ := s.ArticlesSansSujet(10)
	if len(arts) != 1 {
		t.Errorf("un seul article attendu, got %d", len(arts))
	}
}

func TestSujetsEtRattachement(t *testing.T) {
	s := ouvrir(t)
	if err := s.CreerSujet(Topic{ID: "mn_1", Title: "Sujet", CreatedAt: 100, UpdatedAt: 100, Entities: []string{"marseille"}}); err != nil {
		t.Fatal(err)
	}
	if ts, _ := s.SujetsRecents(50); len(ts) != 1 || ts[0].Entities[0] != "marseille" {
		t.Fatalf("sujet récent inattendu : %+v", ts)
	}
	sid, _ := s.AddSource(Source{Slug: "a", Name: "A", URL: "u", Enabled: true})
	aid, _, _ := s.UpsertArticle(Article{SourceID: sid, Ref: "r", Title: "T", URL: "x"})
	_ = s.SetArticleSujet(aid, "mn_1")
	if arts, _ := s.ArticlesDuSujet("mn_1"); len(arts) != 1 {
		t.Errorf("article non rattaché")
	}
	if arts, _ := s.ArticlesSansSujet(10); len(arts) != 0 {
		t.Errorf("plus d'article orphelin attendu")
	}
}
