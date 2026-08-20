// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
package web

import "testing"

func TestTyperSource(t *testing.T) {
	cas := []struct {
		url, want string
	}{
		{"https://www.youtube.com/watch?v=abc", "video"},
		{"https://youtu.be/abc", "video"},
		{"https://peertube.gk2.secubox.in/w/xyz", "video"},
		{"https://open.spotify.com/episode/123", "podcast"},
		{"https://exemple.fr/mon-podcast/feed.rss", "podcast"},
		{"https://www.imdb.com/title/tt0111161/", "film"},
		{"https://letterboxd.com/film/heat/", "film"},
		{"https://www.goodreads.com/book/show/1", "livre"},
		{"https://www.ted.com/talks/xyz", "conference"},
		{"https://fosdem.org/2026/schedule/", "conference"},
		{"https://lemonde.fr/article", "web"},
		{"https://exemple.org/", "web"},
		{"pas une url", "web"},
		{"javascript:alert(1)", "web"},
	}
	for _, c := range cas {
		if got := typerSource(c.url).Source; got != c.want {
			t.Errorf("typerSource(%q).Source = %q ; attendu %q", c.url, got, c.want)
		}
	}
}

func TestAdresseSource(t *testing.T) {
	if _, ok := adresseSource("https://ok.example/x"); !ok {
		t.Error("une url https valide doit passer")
	}
	for _, mauvais := range []string{"javascript:alert(1)", "file:///etc/passwd", "/local", "  ", "ftp://x"} {
		if _, ok := adresseSource(mauvais); ok {
			t.Errorf("%q ne doit pas être accepté comme source", mauvais)
		}
	}
}
