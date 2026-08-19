// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package ingest

import (
	"testing"

	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/store"
)

// #1049 — le chaînon end-to-end : Importer doit AUSSI peupler gateway_contenu
// (via le pont Item→Contenu), ce que GatewayRecents relit pour la mosaïque.
// Sans ça, la mosaïque reste vide même quand l'ingest tourne.
func TestImporterPeupleLaPasserellePourLaMosaique(t *testing.T) {
	s, cat, uid := banc(t)
	src := Source{Nom: "peertube", Categorie: cat, Auteur: uid,
		Visibilite: store.VisPublic, Noeud: "gk2"}
	items := []Item{{
		Ref: "u1", Titre: "Une vidéo",
		Lien: "https://peertube.gk2.secubox.in/w/u1", Date: 1000, Kind: "video",
		Vignette: "https://peertube.gk2.secubox.in/static/thumbnails/u1.jpg",
	}}

	if _, err := Importer(s, src, items); err != nil {
		t.Fatal(err)
	}

	recents, err := s.GatewayRecents(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(recents) != 1 {
		t.Fatalf("gateway_contenu attendu peuplé (1), obtenu %d", len(recents))
	}
	c := recents[0]
	if c.Connecteur != "peertube" || c.RefNative != "u1" {
		t.Fatalf("Contenu mal peuplé : %+v", c)
	}
	if len(c.Medias) != 1 || c.Medias[0].Mime != "image/jpeg" {
		t.Fatalf("vignette perdue : %+v", c.Medias)
	}
}
