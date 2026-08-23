// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package linker

import (
	"strings"
	"testing"

	"golang.org/x/net/html"
)

const echantillonMbasic = `<html><body>
<div id="m_group_stories_container">
<article role="article" data-ft='{"tn":"H"}'>
  <header><h3><a href="/profile.php?id=100">Alice Martin</a></h3></header>
  <div>Beau coucher de soleil sur la vallée aujourd'hui</div>
  <div><a href="/photo.php?fbid=999&amp;id=100"><img src="https://scontent.xx.fbcdn.net/v/t1/pic.jpg"/></a></div>
  <footer><a href="/story.php?story_fbid=999&amp;id=100&amp;refid=18">J'aime · Commenter</a></footer>
</article>
<article role="article">
  <div>Deuxieme post sans image</div>
  <a href="/groups/473/permalink/888/?refid=18">permalien</a>
</article>
</body></html>`

func TestExtraireMbasic(t *testing.T) {
	root, err := html.Parse(strings.NewReader(echantillonMbasic))
	if err != nil {
		t.Fatal(err)
	}
	posts := extraireMbasic(root, 1000)
	if len(posts) != 2 {
		t.Fatalf("attendu 2 posts, obtenu %d", len(posts))
	}
	p0 := posts[0]
	if !strings.Contains(p0.Texte, "coucher de soleil") {
		t.Fatalf("texte post 0 = %q", p0.Texte)
	}
	if len(p0.Medias) != 1 || !strings.Contains(p0.Medias[0].URL, "scontent") {
		t.Fatalf("image post 0 = %v", p0.Medias)
	}
	// permalien absolutisé + paramètres de suivi coupés
	if !strings.HasPrefix(p0.URL, "https://www.facebook.com/photo.php?fbid=999") || strings.Contains(p0.URL, "refid") {
		t.Fatalf("permalien post 0 = %q", p0.URL)
	}
	if p0.Reseau != "facebook" {
		t.Fatalf("reseau = %q", p0.Reseau)
	}
	p1 := posts[1]
	if !strings.Contains(p1.Texte, "Deuxieme post") {
		t.Fatalf("texte post 1 = %q", p1.Texte)
	}
	if p1.URL != "https://www.facebook.com/groups/473/permalink/888/" {
		t.Fatalf("permalien post 1 = %q", p1.URL)
	}
	if len(p1.Medias) != 0 {
		t.Fatalf("post 1 ne devrait pas avoir d'image : %v", p1.Medias)
	}
}
