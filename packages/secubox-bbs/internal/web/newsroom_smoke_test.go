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
		"rendu": Render, "lien": LienApercu, "date": humain, "taille": octets, "glypheSalon": func(string, int) string { return "◆" },
		"vignette": func(a int64, i string) map[string]any { return map[string]any{"A": a, "I": i} },
		"decalage": func(n int) string { return "" },
	}
	tpl, err := template.New("newsroom.html").Funcs(fn).ParseFS(assets, "templates/newsroom.html")
	if err != nil {
		t.Fatalf("parse : %v", err)
	}
	filDiscussion := store.Thread{ID: 1, Title: "Discussion locale", Author: "gandalf", Visibility: store.VisPublic, Posts: 4, LastPostAt: 1700000000}
	filVideo := store.Thread{ID: 3, Title: "Vidéo miroir", Author: "nova", MediaKind: "video", MediaURL: "https://peertube.example/embed", Source: "peertube", Visibility: store.VisLocal, Posts: 0, LastPostAt: 1700000000, Published: "https://billets.gk2.secubox.in/b/x"}
	feed := PodFeed{ID: 2, Titre: "Neuromania", Type: "audiobook", Glyphe: "📖", Vignette: "/media-cover/2", Date: 1700000500,
		Episodes: []PodEpisode{{ID: 10, Titre: "Chapitre 1", Media: "/media/ep/10", Duree: "12:04", Numero: 1}}}
	p := page{
		Titre: "AletheiaVox", Site: "SecuBox", Hote: "gk2", Initiale: "S",
		Stats: store.Stats{Threads: 3, Posts: 9, Billets: 2},
		Cats:  []store.Category{{Slug: "g", Title: "Général", Threads: 3}},
		News: []NewsItem{
			{Feed: &feed, Date: feed.Date},
			{Fil: &filVideo, Date: filVideo.LastPostAt},
			{Fil: &filDiscussion, Date: filDiscussion.LastPostAt},
		},
		Billets: []billetVue{{Titre: "Un billet", Resume: "un extrait", Lien: "https://billets.gk2.secubox.in/b/x"}},
	}
	var buf bytes.Buffer
	if err := tpl.ExecuteTemplate(&buf, "newsroom", p); err != nil {
		t.Fatalf("exécution : %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"AletheiaVox", "Général", "Neuromania", "livre audio",
		`data-media="/media/ep/10"`, `data-k="audiobook"`, `data-k="video"`,
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

func TestMediathequeExecute(t *testing.T) {
	fn := template.FuncMap{
		"rendu": Render, "lien": LienApercu, "date": humain, "taille": octets, "glypheSalon": func(string, int) string { return "◆" },
		"vignette": func(a int64, i string) map[string]any { return map[string]any{"A": a, "I": i} },
		"decalage": func(n int) string { return "" },
	}
	tpl, err := template.New("mediatheque.html").Funcs(fn).ParseFS(assets, "templates/mediatheque.html")
	if err != nil {
		t.Fatalf("parse : %v", err)
	}
	p := page{
		Titre: "Médiathèque", Site: "SecuBox", Hote: "gk2", Initiale: "S",
		Medias: []PodFeed{
			{ID: 2, Titre: "Neuromania", Type: "audiobook", Glyphe: "📖", Vignette: "/media-cover/2",
				Episodes: []PodEpisode{
					{ID: 10, Titre: "Chapitre 1", Media: "/media/ep/10", Duree: "12:04", Numero: 1},
					{ID: 11, Titre: "Chapitre 2", Media: "/media/ep/11", Duree: "10:41", Numero: 2},
				}},
			{ID: 1, Titre: "Si besoin", Type: "podcast", Glyphe: "🎧", Vignette: "/media-cover/1",
				Episodes: []PodEpisode{{ID: 20, Titre: "Épisode récent", Media: "/media/ep/20", Numero: 1}}},
		},
	}
	var buf bytes.Buffer
	if err := tpl.ExecuteTemplate(&buf, "mediatheque", p); err != nil {
		t.Fatalf("exécution : %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"Neuromania", "livre audio", "chapitres 1→2", `data-media="/media/ep/10"`,
		`data-act="playfeed"`, `src="/media-cover/2"`, `id="f2"`, "newsroom.js",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("sortie sans %q", want)
		}
	}
	if strings.Contains(out, "style=") || strings.Contains(out, "onclick") {
		t.Error("style/onclick en ligne — interdit par la CSP")
	}
}

func TestArticleExecute(t *testing.T) {
	fn := template.FuncMap{
		"rendu": Render, "lien": LienApercu, "date": humain, "taille": octets, "glypheSalon": func(string, int) string { return "◆" },
		"vignette":   func(a int64, i string) map[string]any { return map[string]any{"A": a, "I": i} },
		"decalage":   func(n int) string { return "" },
		"initiales2": func(h string) string { return "XX" },
	}
	tpl, err := template.New("article.html").Funcs(fn).ParseFS(assets, "templates/article.html")
	if err != nil {
		t.Fatalf("parse : %v", err)
	}
	// Édition d'un brouillon à deux mains.
	edit := page{Titre: "Notre lecture", Site: "SecuBox",
		Art:   store.Article{ID: 5, Title: "Notre lecture", Status: "draft", CoAuteurs: []string{"gandalf", "anibal"}, NbParts: 2},
		Parts: []store.ArticlePart{{Auteur: "gandalf", Body: "Intro."}, {Auteur: "anibal", Body: "Contexte."}},
		V:     visiteur{Connecte: true, CSRF: "tok", UserInfo: store.UserInfo{Handle: "gandalf"}}}
	var b1 bytes.Buffer
	if err := tpl.ExecuteTemplate(&b1, "article", edit); err != nil {
		t.Fatalf("exécution (édition) : %v", err)
	}
	for _, want := range []string{"Notre lecture", "Intro.", "/article/5/part", "/article/5/publier", "Publier dans la gazette"} {
		if !strings.Contains(b1.String(), want) {
			t.Errorf("édition sans %q", want)
		}
	}
	// Création depuis un dossier.
	create := page{Titre: "Nouveau", Site: "SecuBox",
		Art: store.Article{ThreadID: 3, Title: "Depuis un dossier"},
		V:   visiteur{Connecte: true, CSRF: "tok"}}
	var b2 bytes.Buffer
	if err := tpl.ExecuteTemplate(&b2, "article", create); err != nil {
		t.Fatalf("exécution (création) : %v", err)
	}
	for _, want := range []string{"Co-écrire un article", `name="thread_id" value="3"`, `action="/article/nouveau"`} {
		if !strings.Contains(b2.String(), want) {
			t.Errorf("création sans %q", want)
		}
	}
	if strings.Contains(b1.String(), "onclick") || strings.Contains(b2.String(), "onclick") {
		t.Error("onclick en ligne — interdit par la CSP")
	}
}

func TestPlayerExecute(t *testing.T) {
	fn := template.FuncMap{
		"rendu": Render, "lien": LienApercu, "date": humain, "taille": octets, "glypheSalon": func(string, int) string { return "◆" },
		"vignette": func(a int64, i string) map[string]any { return map[string]any{"A": a, "I": i} },
		"decalage": func(n int) string { return "" },
	}
	tpl, err := template.New("player.html").Funcs(fn).ParseFS(assets, "templates/player.html")
	if err != nil {
		t.Fatalf("parse : %v", err)
	}
	feed := PodFeed{ID: 2, Titre: "Neuromania", Type: "audiobook", Glyphe: "📖", Vignette: "/media-cover/2",
		Episodes: []PodEpisode{
			{ID: 10, Titre: "Chapitre 1", Media: "/media/ep/10", Duree: "12:04", Numero: 1},
			{ID: 11, Titre: "Chapitre 2", Media: "/media/ep/11", Duree: "10:41", Numero: 2},
		}}
	p := page{Titre: "Lecteur", Site: "SecuBox", PlayerFeed: &feed, PlayerEp: "11", PlayerT: "42"}
	var buf bytes.Buffer
	if err := tpl.ExecuteTemplate(&buf, "player", p); err != nil {
		t.Fatalf("exécution : %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"Neuromania", `data-src="/media/ep/10"`, `data-ep="11"`,
		`data-start-ep="11"`, `data-start-t="42"`, "player.js", "pl-audio",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("sortie sans %q", want)
		}
	}
	if strings.Contains(out, "style=") || strings.Contains(out, "onclick") {
		t.Error("style/onclick en ligne — interdit par la CSP")
	}
}
