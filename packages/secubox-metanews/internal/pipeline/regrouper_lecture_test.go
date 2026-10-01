// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
package pipeline

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/CyberMind-FR/secubox-deb/secubox-metanews/internal/cluster"
	"github.com/CyberMind-FR/secubox-deb/secubox-metanews/internal/linker"
	"github.com/CyberMind-FR/secubox-deb/secubox-metanews/internal/store"
)

// UNE LECTURE DES CANDIDATS PAR PASSAGE (#1835). Relue pour chaque article,
// la fenêtre de ~8 000 sujets de gk2 coûtait vingt minutes de processeur au
// démarrage et une salve à chaque sondage.
func TestRegrouperLitLesCandidatsUneFois(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := int64(1_700_000_000)
	sid, _ := st.AddSource(store.Source{Slug: "s", Name: "S", URL: "u", Enabled: true})
	sujets := []string{"Incendie près de Marseille", "La BCE relève ses taux",
		"Grève à la SNCF", "Séisme au Japon", "Élections en Allemagne"}
	for i := 0; i < 40; i++ {
		titre := sujets[i%len(sujets)]
		corps := fmt.Sprintf("%s — dépêche %d", titre, i)
		st.UpsertArticle(store.Article{
			SourceID: sid, Ref: fmt.Sprint(i), Title: titre, URL: fmt.Sprint("http://x/", i),
			Summary: corps, PublishedAt: now + int64(i), Fingerprint: linker.Empreinte(titre, corps),
			Entities: cluster.Entites(titre + " " + corps),
		})
	}
	p := New(st, linker.NewRSS(nil), nil)
	lectures := 0
	p.sujetsRecents = func(since int64) ([]store.Topic, error) {
		lectures++
		return st.SujetsRecents(since)
	}
	if _, err := p.Regrouper(now + 600); err != nil {
		t.Fatal(err)
	}
	if lectures != 1 {
		t.Fatalf("candidats lus %d fois pour 40 articles, attendu 1", lectures)
	}
	// Les sujets créés pendant le passage restent candidats : cinq thèmes,
	// cinq sujets — pas un par dépêche.
	tops, _ := st.SujetsListe("", 100)
	if len(tops) != len(sujets) {
		t.Fatalf("attendu %d sujets, got %d", len(sujets), len(tops))
	}
}

// RECLASSER NE RAJEUNIT PAS CE QU'IL NE TOUCHE PAS (#1835). Un sujet cohérent,
// dont aucun article n'est détaché, garde sa date ; seul celui qui perd un
// intrus est recomposé.
func TestReclasserNeRajeunitPasLesSujetsIntacts(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := int64(1_700_000_000)
	sid, _ := st.AddSource(store.Source{Slug: "s", Name: "S", URL: "u", Enabled: true})
	ajoute := func(ref, titre, corps string, pub int64) {
		st.UpsertArticle(store.Article{
			SourceID: sid, Ref: ref, Title: titre, URL: "http://x/" + ref, Summary: corps,
			PublishedAt: pub, Fingerprint: linker.Empreinte(titre, corps),
			Entities: cluster.Entites(titre + " " + corps),
		})
	}
	ajoute("a", "Incendie important près de Marseille", "Des centaines de pompiers près de Marseille.", now)
	ajoute("b", "Un feu mobilise 300 pompiers près de Marseille", "Des centaines de pompiers près de Marseille.", now+60)
	ajoute("c", "La BCE relève ses taux directeurs", "La Banque centrale européenne augmente ses taux.", now+120)
	ajoute("d", "La BCE annonce une hausse de ses taux", "La Banque centrale européenne augmente ses taux.", now+180)
	p := New(st, linker.NewRSS(nil), nil)
	if _, err := p.Regrouper(now + 600); err != nil {
		t.Fatal(err)
	}
	avant := map[string]int64{}
	tops, _ := st.SujetsListe("", 100)
	for _, s := range tops {
		avant[s.ID] = s.UpdatedAt
	}
	if len(tops) != 2 {
		t.Fatalf("attendu 2 sujets cohérents, got %d", len(tops))
	}
	plusTard := now + 3600
	n, err := p.Reclasser(plusTard)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("rien à détacher, got %d", n)
	}
	tops, _ = st.SujetsListe("", 100)
	for _, s := range tops {
		if s.UpdatedAt != avant[s.ID] {
			t.Errorf("sujet %q rajeuni par Reclasser : %d → %d", s.Title, avant[s.ID], s.UpdatedAt)
		}
	}
}

// RECLASSER NE DÉFAIT PLUS CE QUE REGROUPER VIENT DE FAIRE (#1835). Le sujet
// T (P et Q : titres proches, entités différentes) porte l'union {a,b,c} ;
// Z {b,c} la reconnaît par l'union, mais aucun article de T ne lui ressemble.
// Rattaché par l'union, il était détaché par Reclasser au démarrage suivant,
// puis rattaché de nouveau — 185, 29, 162 fois sur gk2.
func TestRegrouperExigeUnArticleFrere(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := int64(1_700_000_000)
	sid, _ := st.AddSource(store.Source{Slug: "s", Name: "S", URL: "u", Enabled: true})
	ajoute := func(ref, titre string, ent []string, pub int64) {
		st.UpsertArticle(store.Article{
			SourceID: sid, Ref: ref, Title: titre, URL: "http://x/" + ref, Summary: titre,
			PublishedAt: pub, Fingerprint: linker.Empreinte(titre, ref), Entities: ent,
		})
	}
	ajoute("p", "Grande tempete sur la cote atlantique", []string{"a", "b"}, now+100)
	ajoute("q", "Grande tempete sur la cote atlantique hier soir", []string{"a", "c"}, now+200)
	p := New(st, linker.NewRSS(nil), nil)
	if _, err := p.Regrouper(now + 300); err != nil {
		t.Fatal(err)
	}
	tops, _ := st.SujetsListe("", 100)
	if len(tops) != 1 {
		t.Fatalf("P et Q devaient former un seul sujet, got %d", len(tops))
	}
	sujetPQ := tops[0].ID

	ajoute("z", "Marche financier europeen en baisse", []string{"b", "c"}, now+250)
	if _, err := p.Regrouper(now + 400); err != nil {
		t.Fatal(err)
	}
	arts, _ := st.ArticlesDuSujet(sujetPQ)
	for _, a := range arts {
		if a.Ref == "z" {
			t.Fatal("Z rattaché par l'union seule : aucun article du sujet ne lui ressemble")
		}
	}
	if n, err := p.Reclasser(now + 500); err != nil || n != 0 {
		t.Fatalf("Reclasser défait le travail de Regrouper : %d détachés (err %v)", n, err)
	}
}
