// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package ingest

import (
	"testing"

	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/gateway"
)

// #1049 — le CHAÎNON MANQUANT : convertir un Item de collecteur en gateway.Contenu
// pour peupler gateway_contenu, ce que GatewayRecents (déjà écrit) relira pour la
// mosaïque. La vignette devient un média IMAGE, que la tuile relaiera localement.
func TestContenuDepuisItemPorteLaVignetteEnMediaImage(t *testing.T) {
	it := Item{
		Ref: "u1", Titre: "Une vidéo", Corps: "desc",
		Lien: "https://peertube.gk2.secubox.in/w/s1", Date: 1000,
		Kind:     "video",
		Vignette: "https://peertube.gk2.secubox.in/static/thumbnails/u1.jpg",
	}

	c := ContenuDepuisItem(it, "peertube", "gk2", gateway.ProprieteTiers)

	if err := c.Valider(); err != nil {
		t.Fatalf("Contenu invalide : %v", err)
	}
	if c.RefNative != "u1" || c.Connecteur != "peertube" || c.PublieLe != 1000 {
		t.Fatalf("champs mal mappés : %+v", c)
	}
	if c.Genre != gateway.GenreVideo {
		t.Fatalf("genre = %q, veut %q", c.Genre, gateway.GenreVideo)
	}
	if len(c.Medias) != 1 || c.Medias[0].Chemin != it.Vignette {
		t.Fatalf("média vignette manquant : %+v", c.Medias)
	}
	if c.Medias[0].Mime != "image/jpeg" {
		t.Fatalf("mime = %q, veut image/jpeg", c.Medias[0].Mime)
	}
	if c.Empreinte == "" {
		t.Fatal("empreinte non calculée")
	}
}

func TestContenuDepuisItemSansVignetteNAPasDeMedia(t *testing.T) {
	it := Item{Ref: "b1", Titre: "Billet", Lien: "https://billets.gk2/b1",
		Date: 5, Kind: "texte"}
	c := ContenuDepuisItem(it, "billets", "gk2", gateway.ProprieteSoi)
	if err := c.Valider(); err != nil {
		t.Fatalf("Contenu invalide : %v", err)
	}
	if len(c.Medias) != 0 {
		t.Fatalf("aucun média attendu, obtenu %+v", c.Medias)
	}
	if c.Genre != gateway.GenreTexte {
		t.Fatalf("genre = %q, veut texte", c.Genre)
	}
}
