// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package web

import (
	"strings"
	"testing"
)

// Un lien SEUL dans son paragraphe devient une carte (#3713) : sur téléphone,
// une adresse de 150 caractères débordait de l'écran.
func TestUnLienSeulDevientUneCarte(t *testing.T) {
	cas := []struct{ src, titre, sous, ico string }{
		{"https://www.linkedin.com/feed/update/urn:li:activity:7525050761186177024/",
			"Publication LinkedIn", "linkedin.com", "carte-li"},
		{"https://www.facebook.com/stories/122096388890359668/UzpfSVNDOjk2MzM4MDEwOTgyNTIwOA==/?bucket_count=9&source=story_tray",
			"Story Facebook", "facebook.com", "carte-fb"},
		{"https://www.facebook.com/share/v/1A3WD8mohx/", "Vidéo Facebook", "facebook.com", "carte-fb"},
		{"https://x.com/GKerma42760/status/2119292201142210619", "Post de @GKerma42760", "x.com", "carte-x"},
		{"https://github.com/CyberMind-FR/secubox-deb", "CyberMind-FR / secubox-deb", "github.com", "carte-gh"},
		{"https://github.com/CyberMind-FR/secubox-deb/blob/master/docs/PREMIER-PAS-TUTORIEL.md",
			"PREMIER-PAS-TUTORIEL.md", "github.com · secubox-deb/docs", "carte-gh"},
		{"https://example.org/un-article-interessant", "un article interessant", "example.org", "carte-autre"},
		{"https://example.org/", "example.org", "example.org", "carte-autre"},
	}
	for _, c := range cas {
		h := string(Render(c.src))
		if !strings.Contains(h, `class="carte-lien `+c.ico+`"`) {
			t.Fatalf("%s : pas de carte %s : %s", c.src, c.ico, h)
		}
		if !strings.Contains(h, "<b>"+c.titre+"</b>") || !strings.Contains(h, "<small>"+c.sous+"</small>") {
			t.Fatalf("%s : titre ou domaine faux : %s", c.src, h)
		}
		if !strings.Contains(h, `rel="noopener noreferrer"`) {
			t.Fatalf("%s : rel manquant : %s", c.src, h)
		}
		if strings.Contains(h, "<p>") {
			t.Fatalf("%s : la carte reste dans un paragraphe : %s", c.src, h)
		}
	}
}

// L'adresse garde son échappement : un & reste &amp; dans l'attribut.
func TestLaCarteGardeLEchappement(t *testing.T) {
	h := string(Render("https://example.org/a?b=1&c=2"))
	if !strings.Contains(h, `href="https://example.org/a?b=1&amp;c=2"`) {
		t.Fatalf("échappement perdu : %s", h)
	}
	h = string(Render(`https://example.org/"><script>alert(1)</script>`))
	if strings.Contains(h, "<script>") {
		t.Fatalf("injection : %s", h)
	}
}

// Un lien au milieu d'une phrase reste un lien : la carte n'est que pour le
// lien posé seul.
func TestUnLienDansUnePhraseResteUnLien(t *testing.T) {
	h := string(Render("voir https://example.org/page pour la suite"))
	if strings.Contains(h, "carte-lien") {
		t.Fatalf("carte dans une phrase : %s", h)
	}
	h = string(Render("[la page](https://example.org/page)"))
	if strings.Contains(h, "carte-lien") {
		t.Fatalf("un lien Markdown nommé garde son texte : %s", h)
	}
}
