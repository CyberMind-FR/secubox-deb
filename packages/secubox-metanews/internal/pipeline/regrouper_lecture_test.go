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
