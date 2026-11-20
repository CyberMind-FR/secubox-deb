// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package linker

import (
	"fmt"
	"net/url"
	"testing"
	"time"
)

// Fixture calquée sur la page réelle blogs.mediapart.fr/sudfa/blog (gabarit du
// 2026-11) : li.teaser avec data-id, h3.title > a (href relatif, avec espaces et
// retour à la ligne internes), div.author > time[datetime] + rel="author", et
// une image static.mediapart.fr.
const fixtureSudfa = `
<ul class="post-list">
  <li class="teaser" data-id="1360220" data-type="blog">
    <h3 class="title">
      <a href="    /sudfa/blog/151126/bombardements-la-frontiere-egypto-soudanaise-une-histoire-de-domination-coloniale
">
        Bombardements à la frontière égypto-soudanaise&nbsp;: une histoire de domination coloniale
      </a>
    </h3>
    <div class="author">
      <time datetime="2026-11-15">15 nov. 2026</time> Par <a rel="author" href="https://blogs.mediapart.fr/sudfa" class="subscriber">Sudfa</a>
    </div>
    <a href="/sudfa/blog/151126/bombardements-la-frontiere-egypto-soudanaise-une-histoire-de-domination-coloniale" class=""><img src="https://static.mediapart.fr/etmagine/default/files/2026/11/15/image.jpg" alt=""></a>
  </li>
  <li class="teaser" data-id="1354036" data-type="blog">
    <h3 class="title">
      <a href="https://blogs.mediapart.fr/sudfa/blog/021026/soudan-le-dialogue-national-peut-il-reparer-un-pays-profondement-dechire">
        Soudan&nbsp;: le dialogue national peut-il réparer un pays profondément déchiré&nbsp;?
      </a>
    </h3>
    <div class="author">
      <time datetime="2026-10-02">2 oct. 2026</time> Par <a rel="author" href="https://blogs.mediapart.fr/sudfa" class="subscriber">Sudfa</a>
    </div>
  </li>
</ul>`

func TestAnalyserBlogMediapart(t *testing.T) {
	base, _ := url.Parse("https://blogs.mediapart.fr/sudfa/blog")
	items := AnalyserBlogMediapart(fixtureSudfa, base)
	if len(items) != 2 {
		t.Fatalf("attendu 2 billets, obtenu %d : %+v", len(items), items)
	}

	a := items[0]
	if a.Titre != "Bombardements à la frontière égypto-soudanaise : une histoire de domination coloniale" {
		t.Errorf("titre inattendu : %q", a.Titre)
	}
	// Lien relatif avec espaces/retour-ligne internes → absolu et nettoyé.
	if a.URL != "https://blogs.mediapart.fr/sudfa/blog/151126/bombardements-la-frontiere-egypto-soudanaise-une-histoire-de-domination-coloniale" {
		t.Errorf("url inattendue : %q", a.URL)
	}
	if a.Ref != "mediapart-blog:1360220" {
		t.Errorf("ref inattendue (data-id) : %q", a.Ref)
	}
	if a.Auteur != "Sudfa" {
		t.Errorf("auteur inattendu : %q", a.Auteur)
	}
	if a.Langue != "fr" || a.Connecteur != "mediapart-blog" {
		t.Errorf("métadonnées inattendues : langue=%q connecteur=%q", a.Langue, a.Connecteur)
	}
	if a.Vignette != "https://static.mediapart.fr/etmagine/default/files/2026/11/15/image.jpg" {
		t.Errorf("vignette inattendue : %q", a.Vignette)
	}
	want := time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC).Unix()
	if a.PublieLe != want {
		t.Errorf("date inattendue : %d (attendu %d)", a.PublieLe, want)
	}

	// Deuxième billet : lien déjà absolu, pas d'image → vignette vide, date lue.
	b := items[1]
	if b.URL != "https://blogs.mediapart.fr/sudfa/blog/021026/soudan-le-dialogue-national-peut-il-reparer-un-pays-profondement-dechire" {
		t.Errorf("url #2 inattendue : %q", b.URL)
	}
	if b.Ref != "mediapart-blog:1354036" {
		t.Errorf("ref #2 inattendue : %q", b.Ref)
	}
	if b.Vignette != "" {
		t.Errorf("vignette #2 devrait être vide, obtenu %q", b.Vignette)
	}
	if b.PublieLe != time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC).Unix() {
		t.Errorf("date #2 inattendue : %d", b.PublieLe)
	}
}

// Non-régression SSRF : le chemin Mediapart de Collecter passe par la garde,
// comme le chemin RSS, avant tout accès réseau.
func TestCollecterPasseParLaGarde(t *testing.T) {
	var vus []string
	r := NewRSS(func(h string) error { vus = append(vus, h); return fmt.Errorf("refus:%s", h) })
	urls := []string{
		"https://blogs.mediapart.fr/sudfa/blog", // → MediapartBlog
		"https://www.mediapart.fr/articles/feed", // → Flux
		"http://127.0.0.1/sudfa/blog",            // SSRF : doit être refusé
	}
	for _, u := range urls {
		if _, err := r.Collecter("", u); err == nil {
			t.Errorf("%s : la garde aurait dû refuser", u)
		}
	}
	if len(vus) != 3 || vus[0] != "blogs.mediapart.fr" || vus[1] != "www.mediapart.fr" || vus[2] != "127.0.0.1" {
		t.Errorf("garde non appelée comme attendu : %v", vus)
	}
}

func TestEstBlogMediapart(t *testing.T) {
	cas := map[string]bool{
		"https://blogs.mediapart.fr/sudfa/blog":  true,
		"https://BLOGS.Mediapart.FR/sudfa":       true,
		"https://www.mediapart.fr/articles/feed": false,
		"https://example.org/blog":               false,
		"pas une url":                            false,
	}
	for u, veut := range cas {
		if got := EstBlogMediapart(u); got != veut {
			t.Errorf("EstBlogMediapart(%q) = %v, attendu %v", u, got, veut)
		}
	}
}
