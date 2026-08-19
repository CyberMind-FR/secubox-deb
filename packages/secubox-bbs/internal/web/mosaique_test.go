// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package web

import (
	"net/url"
	"testing"

	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/gateway"
)

// La contrainte qui commande #1049/#1056 : la vignette d'un média DISTANT ne
// doit JAMAIS être servie depuis l'hôte tiers — chaque affichage lui dirait qui
// regarde, quand, et depuis quelle IP. Elle passe par le relais local, qui ne
// transmet aucun en-tête du membre.
func TestTuileVignetteRelaiLocalPourMediaDistant(t *testing.T) {
	src := "https://podcaster.gk2.secubox.in/img/ep1.jpg"
	c := gateway.Contenu{
		Titre:      "Un épisode",
		Connecteur: "podcaster",
		Medias:     []gateway.Media{{Chemin: src, Mime: "image/jpeg"}},
	}

	tuile := tuileDepuisContenu(c)

	want := "/media-vignette?u=" + url.QueryEscape(src)
	if tuile.Vignette != want {
		t.Fatalf("vignette = %q, veut le relais local %q", tuile.Vignette, want)
	}
	if tuile.Source != "podcaster" {
		t.Fatalf("source = %q, veut %q", tuile.Source, "podcaster")
	}
	if tuile.Titre != "Un épisode" {
		t.Fatalf("titre = %q, veut %q", tuile.Titre, "Un épisode")
	}
}

// Le relais ne sert que des images (media_relais.go). Un flux podcast porte
// l'audio ET une pochette : la vignette doit viser l'image, pas l'enclosure
// audio — sinon le relais 404 sur un mime refusé et la mosaïque est trouée.
func TestTuileVignetteIgnoreLesMediasNonImage(t *testing.T) {
	c := gateway.Contenu{
		Connecteur: "podcaster",
		Medias: []gateway.Media{
			{Chemin: "https://podcaster.gk2.secubox.in/audio/ep1.mp3", Mime: "audio/mpeg"},
			{Chemin: "https://podcaster.gk2.secubox.in/img/ep1.jpg", Mime: "image/jpeg"},
		},
	}
	tuile := tuileDepuisContenu(c)
	want := "/media-vignette?u=" + url.QueryEscape("https://podcaster.gk2.secubox.in/img/ep1.jpg")
	if tuile.Vignette != want {
		t.Fatalf("vignette = %q, veut l'image %q (pas l'audio)", tuile.Vignette, want)
	}
}

// Un contenu sans image ne fabrique pas de vignette : le front montre un glyphe
// (place réservée), il ne demande pas au relais un média qu'il refusera.
func TestTuileSansImageNAPasDeVignette(t *testing.T) {
	c := gateway.Contenu{
		Connecteur: "radio",
		Medias:     []gateway.Media{{Chemin: "https://radio.gk2.secubox.in/live.mp3", Mime: "audio/mpeg"}},
	}
	if v := tuileDepuisContenu(c).Vignette; v != "" {
		t.Fatalf("vignette = %q, veut vide", v)
	}
}

// La mosaïque mêle des flux hétérogènes en une grille unique : l'ordre est le
// temps (plus récent d'abord), et la grille est bornée — une page ne charge pas
// mille tuiles pour en montrer dix.
func TestMosaiqueTrieDuPlusRecentEtBorne(t *testing.T) {
	contenus := []gateway.Contenu{
		{Titre: "vieux", Connecteur: "billets", PublieLe: 100},
		{Titre: "recent", Connecteur: "mastodon", PublieLe: 300},
		{Titre: "moyen", Connecteur: "peertube", PublieLe: 200},
	}
	tuiles := assemblerMosaique(contenus, 2)
	if len(tuiles) != 2 {
		t.Fatalf("len = %d, veut 2 (borne)", len(tuiles))
	}
	if tuiles[0].Titre != "recent" || tuiles[1].Titre != "moyen" {
		t.Fatalf("ordre = [%q, %q], veut [recent, moyen]", tuiles[0].Titre, tuiles[1].Titre)
	}
}
