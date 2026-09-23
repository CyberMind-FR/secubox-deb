// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
package pipeline

import (
	"path/filepath"
	"testing"

	"github.com/CyberMind-FR/secubox-deb/secubox-metanews/internal/cluster"
	"github.com/CyberMind-FR/secubox-deb/secubox-metanews/internal/linker"
	"github.com/CyberMind-FR/secubox-deb/secubox-metanews/internal/store"
)

// Regrouper n'appelle pas le réseau : on insère des articles à la main puis on
// vérifie le clustering. L'exemple canonique : 3 dépêches sur l'incendie de
// Marseille (dont un clone) → UN sujet, 2 origines.
func TestRegrouperIncendieUnSeulSujet(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := int64(1_700_000_000)

	sFI, _ := st.AddSource(store.Source{Slug: "fi", Name: "France Info", URL: "u1", Enabled: true})
	sRTL, _ := st.AddSource(store.Source{Slug: "rtl", Name: "RTL", URL: "u2", Enabled: true})
	sClone, _ := st.AddSource(store.Source{Slug: "clone", Name: "Clone", URL: "u3", Enabled: true})

	inserer := func(sid int64, ref, titre, corps string, pub int64) {
		st.UpsertArticle(store.Article{
			SourceID: sid, Ref: ref, Title: titre, URL: "http://x/" + ref, Summary: corps,
			PublishedAt: pub, Fingerprint: linker.Empreinte(titre, corps),
			Entities: cluster.Entites(titre + " " + corps),
		})
	}
	inserer(sFI, "a", "Incendie important près de Marseille",
		"Un incendie mobilise des centaines de pompiers dans les Bouches-du-Rhône.", now)
	inserer(sRTL, "b", "Un feu mobilise 300 pompiers près de Marseille",
		"Un incendie mobilise des centaines de pompiers dans les Bouches-du-Rhône.", now+300)
	// clone EXACT de la dépêche France Info (autre site) → même empreinte
	inserer(sClone, "c", "Incendie important près de Marseille",
		"Un incendie mobilise des centaines de pompiers dans les Bouches-du-Rhône.", now+400)
	// événement DISTINCT
	inserer(sFI, "d", "La BCE relève ses taux directeurs",
		"La Banque centrale européenne augmente ses taux.", now+500)

	p := New(st, linker.NewRSS(nil), nil)
	if _, err := p.Regrouper(now + 600); err != nil {
		t.Fatal(err)
	}

	tops, _ := st.SujetsListe("", 100)
	if len(tops) != 2 {
		t.Fatalf("attendu 2 sujets (incendie + BCE), got %d : %+v", len(tops), tops)
	}
	// le sujet incendie : 3 articles, mais 2 ORIGINES (clone fondu).
	var incendie *store.Topic
	for i := range tops {
		if len(tops[i].Entities) > 0 && contient(tops[i].Entities, "marseille") {
			incendie = &tops[i]
		}
	}
	if incendie == nil {
		t.Fatalf("sujet incendie introuvable : %+v", tops)
	}
	arts, _ := st.ArticlesDuSujet(incendie.ID)
	if len(arts) != 3 {
		t.Errorf("le sujet incendie devrait avoir 3 articles, got %d", len(arts))
	}
	if incendie.SourcesCount != 2 {
		t.Errorf("clones mal fondus : sources_count=%d, attendu 2", incendie.SourcesCount)
	}
	if incendie.Summary == "" {
		t.Errorf("résumé manquant")
	}
}

func contient(l []string, x string) bool {
	for _, v := range l {
		if v == x {
			return true
		}
	}
	return false
}

// LE TITRE DU SUJET SUIT LE PLUS RÉCENT (#1323).
//
// Un sujet nourri sur plusieurs jours gardait le titre de l'article FONDATEUR :
// « JOURNAL DE 7H du 26 août » s'affichait en tête d'un fil alimenté jusqu'au
// 14 septembre. La vignette et le résumé suivaient déjà la fraîcheur ; le
// titre restait en arrière, et c'est pourtant lui qu'on lit en premier.
func TestSujetPorteLeTitreLePlusRecent(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	src, _ := st.AddSource(store.Source{Slug: "radio", Name: "Radio", URL: "u", Enabled: true})
	now := int64(1_800_000_000)
	inserer := func(ref, titre string, pub int64) {
		st.UpsertArticle(store.Article{
			SourceID: src, Ref: ref, Title: titre, URL: "http://r/" + ref,
			Summary:     "Le journal de la rédaction, édition du jour.",
			PublishedAt: pub, Fingerprint: linker.Empreinte(titre, ref),
			Entities: cluster.Entites(titre),
		})
	}
	p := New(st, linker.NewRSS(nil), nil)

	// EN DEUX TEMPS, comme dans la vraie vie : le sujet naît un jour, et des
	// éditions le rejoignent les jours suivants. Tout insérer d'un coup ne
	// prouverait rien — le plus récent pourrait fonder le sujet lui-même.
	inserer("j1", "JOURNAL DE 7H, du mercredi", now)
	if _, err := p.Regrouper(now + 60); err != nil {
		t.Fatal(err)
	}
	if tops, _ := st.SujetsListe("", 10); len(tops) != 1 || tops[0].Title != "JOURNAL DE 7H, du mercredi" {
		t.Fatalf("le sujet devait naître avec le titre du premier article, got %+v", tops)
	}

	inserer("j2", "JOURNAL DE 12H30, du mercredi", now+3600)
	inserer("j3", "JOURNAL DE 18H, du mercredi", now+7200)
	if _, err := p.Regrouper(now + 8000); err != nil {
		t.Fatal(err)
	}
	tops, _ := st.SujetsListe("", 100)
	if len(tops) != 1 {
		t.Fatalf("attendu 1 sujet (même journal), got %d : %+v", len(tops), tops)
	}
	if got := tops[0].Title; got != "JOURNAL DE 18H, du mercredi" {
		t.Fatalf("le sujet doit porter le titre le PLUS RÉCENT, got %q", got)
	}
}
