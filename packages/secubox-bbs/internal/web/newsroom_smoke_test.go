// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
package web

import (
	"bytes"
	"html/template"
	"strings"
	"testing"

	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/store"
)

// Le gabarit newsroom (#1056 stage 1) rend la RACINE : une erreur d'exécution y
// renverrait un 500 sur la page la plus vue. Ce test l'exécute hors-ligne avec
// des données réalistes (fil, podcast, vidéo, billet) avant tout déploiement.
func TestNewsroomExecute(t *testing.T) {
	fn := template.FuncMap{
		"rendu": Render, "date": humain, "taille": octets,
		"vignette": func(a int64, i string) map[string]any { return map[string]any{"A": a, "I": i} },
		"decalage": func(n int) string { return "" },
	}
	tpl, err := template.New("newsroom.html").Funcs(fn).ParseFS(assets, "templates/newsroom.html")
	if err != nil {
		t.Fatalf("parse : %v", err)
	}
	p := page{
		Titre: "AletheiaVox", Site: "SecuBox", Hote: "gk2", Initiale: "S",
		Stats: store.Stats{Threads: 3, Posts: 9, Billets: 2},
		Cats:  []store.Category{{Slug: "g", Title: "Général", Threads: 3}},
		Threads: []store.Thread{
			{ID: 1, Title: "Discussion locale", Author: "gandalf", Visibility: store.VisPublic, Posts: 4, LastPostAt: 1700000000},
			{ID: 2, Title: "Podcast épisode", Author: "anibal", MediaKind: "audio", MediaURL: "/media/ep/2", Visibility: store.VisPublic, Posts: 1, LastPostAt: 1700000000},
			{ID: 3, Title: "Vidéo miroir", Author: "nova", MediaKind: "video", MediaURL: "https://peertube.example/embed", Source: "peertube", Visibility: store.VisLocal, Posts: 0, LastPostAt: 1700000000, Published: "https://billets.gk2.secubox.in/b/x"},
		},
		Billets: []billetVue{{Titre: "Un billet", Resume: "un extrait", Lien: "https://billets.gk2.secubox.in/b/x"}},
	}
	var buf bytes.Buffer
	if err := tpl.ExecuteTemplate(&buf, "newsroom", p); err != nil {
		t.Fatalf("exécution : %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"AletheiaVox", "Général", "Podcast épisode",
		`data-media="/media/ep/2"`, `data-k="podcast"`, `data-k="video"`,
		"stamp pub", "billets.gk2.secubox.in", "newsroom.js", "newsroom.css",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("sortie sans %q", want)
		}
	}
	// Garde CSP : aucun style ni onclick en ligne dans la page rendue.
	if strings.Contains(out, "style=") {
		t.Error("style en ligne — interdit par la CSP")
	}
	if strings.Contains(out, "onclick") {
		t.Error("onclick en ligne — interdit par la CSP")
	}
}
