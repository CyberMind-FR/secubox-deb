// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package web

import (
	"strings"
	"testing"

	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/gateway"
)

func TestEmbedYouTubeURLLienNu(t *testing.T) {
	h, ok := embedYouTubeURL("https://youtu.be/kFuf9xUInzA?si=7DvT2wtSMprn4NHI")
	if !ok || !strings.Contains(h, "youtube-nocookie.com/embed/kFuf9xUInzA") {
		t.Fatalf("embed nocookie attendu : %q ok=%v", h, ok)
	}
}

func TestEmbedYouTubeURLNonYoutube(t *testing.T) {
	if _, ok := embedYouTubeURL("https://exemple.org/x"); ok {
		t.Fatal("une URL non-YouTube ne doit PAS produire d'embed")
	}
}

// Le lecteur youtube-nocookie a besoin de l'ORIGINE pour se configurer. La page
// pose `Referrer-Policy: same-origin` (coupe le référent tiers) → sans surcharge
// l'embed montre « Erreur 153 / Erreur de configuration du lecteur vidéo ».
// Garde-fou : l'iframe DOIT surcharger avec strict-origin-when-cross-origin, et
// ne JAMAIS couper le référent (no-referrer).
func TestEmbedYouTubeEnvoieLOrigine(t *testing.T) {
	h, _ := embedYouTubeURL("https://youtu.be/kFuf9xUInzA")
	if strings.Contains(h, "no-referrer") {
		t.Fatalf("no-referrer casse le lecteur youtube : %q", h)
	}
	if !strings.Contains(h, `referrerpolicy="strict-origin-when-cross-origin"`) {
		t.Fatalf("l'iframe doit surcharger le Referrer-Policy de page pour envoyer l'origine : %q", h)
	}
}

// LE test qui reproduit la capture utilisateur : une URL nue dans un corps.
func TestRenderCorpsEmbarqueLecteurYoutube(t *testing.T) {
	html := string(Render("Il explique ici https://youtu.be/kFuf9xUInzA les agendas"))
	if !strings.Contains(html, "youtube-nocookie.com/embed/kFuf9xUInzA") {
		t.Fatalf("le corps doit embarquer le lecteur, pas un simple lien : %s", html)
	}
	if strings.Contains(html, `href="https://youtu.be/kFuf9xUInzA"`) {
		t.Fatalf("l'URL YouTube nue ne doit pas rester un <a> : %s", html)
	}
}

// L'upgrade souverain (Task 8) s'appuie sur embedYouTube(Contenu).
//
// LE MIROIR DOIT ENCADRER L'URL D'INTEGRATION, PAS LA PAGE DE VISIONNAGE.
// PeerTube protege ses pages `/w/…` du cadrage (`X-Frame-Options`) : les
// encadrer donne « Firefox ne peut pas ouvrir cette page ». Seule l'URL
// `/videos/embed/…` est concue pour l'iframe (#1131b).
func TestEmbedContenuMirrorRendPeertube(t *testing.T) {
	c := gateway.Contenu{Genre: gateway.GenreVideo, Connecteur: "youtube",
		Metadonnees: map[string]string{"video_id": "dQw4w9WgXcQ", "etat": "mirror"},
		Repliques:   []gateway.Replique{{Cible: "peertube", CibleURL: "https://peertube.gk2/w/xy", Mode: gateway.ModeMiroir}}}
	h := embedYouTube(c)
	if !strings.Contains(h, "<iframe") || !strings.Contains(h, "peertube.gk2/videos/embed/xy") {
		t.Fatalf("miroir → iframe d'INTEGRATION peertube attendu : %s", h)
	}
	if strings.Contains(h, "/w/xy") {
		t.Fatalf("le miroir encadre la page de visionnage (bloquee par X-Frame) : %s", h)
	}
}

func TestPeertubeEmbedURL(t *testing.T) {
	cas := map[string]string{
		"https://peertube.gk2.secubox.in/w/jDerWdgx1NrBTiRkFt9xuV":        "https://peertube.gk2.secubox.in/videos/embed/jDerWdgx1NrBTiRkFt9xuV",
		"https://peertube.gk2.secubox.in/videos/watch/abc-123":            "https://peertube.gk2.secubox.in/videos/embed/abc-123",
		"https://peertube.gk2.secubox.in/videos/embed/deja":               "https://peertube.gk2.secubox.in/videos/embed/deja",
		"https://autre.example/chemin/quelconque":                        "https://autre.example/chemin/quelconque",
	}
	for in, want := range cas {
		if got := peertubeEmbedURL(in); got != want {
			t.Errorf("peertubeEmbedURL(%q) = %q, attendu %q", in, got, want)
		}
	}
}
