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
func TestEmbedContenuMirrorRendPeertube(t *testing.T) {
	c := gateway.Contenu{Genre: gateway.GenreVideo, Connecteur: "youtube",
		Metadonnees: map[string]string{"video_id": "dQw4w9WgXcQ", "etat": "mirror"},
		Repliques:   []gateway.Replique{{Cible: "peertube", CibleURL: "https://peertube.gk2/w/xy", Mode: gateway.ModeMiroir}}}
	if h := embedYouTube(c); !strings.Contains(h, "<iframe") || !strings.Contains(h, "peertube.gk2/w/xy") {
		t.Fatalf("miroir → iframe peertube attendu : %s", h)
	}
}
