package ingest

import "testing"

// #1024 bis — le feed billets rend l'URL interne du module (http://billets/…) ;
// elle doit être rattachée à l'origine publique --billets-base pour être
// cliquable hors de la board.

func TestLienBilletPublic(t *testing.T) {
	const base = "https://billets.gk2.secubox.in"
	cas := []struct{ in, base, want string }{
		// L'URL interne absolue (host sans domaine) est rebasée sur son chemin.
		{"http://billets/b/suivi-kdgxsxdg", base, "https://billets.gk2.secubox.in/b/suivi-kdgxsxdg"},
		{"http://localhost:8910/b/x", base, "https://billets.gk2.secubox.in/b/x"},
		// Une URL relative est rebasée aussi.
		{"/b/x", base, "https://billets.gk2.secubox.in/b/x"},
		// La query est conservée.
		{"http://billets/b/x?utm=1", base, "https://billets.gk2.secubox.in/b/x?utm=1"},
		// Une URL déjà publique (vrai domaine) est laissée intacte.
		{"https://billets.gk2.secubox.in/b/x", base, "https://billets.gk2.secubox.in/b/x"},
		{"https://example.com/article", base, "https://example.com/article"},
		// Sans base, on ne touche à rien.
		{"http://billets/b/x", "", "http://billets/b/x"},
		{"", base, ""},
	}
	for _, c := range cas {
		if got := lienBilletPublic(c.in, c.base); got != c.want {
			t.Errorf("lienBilletPublic(%q, %q) = %q, veut %q", c.in, c.base, got, c.want)
		}
	}
}
