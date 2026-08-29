// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package web

import (
	"bytes"
	"html/template"
	"strings"
	"testing"

	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/store"
)

func funcsNewsroom() template.FuncMap {
	return template.FuncMap{
		"rendu": Render, "lien": LienApercu, "date": humain, "taille": octets,
		"glypheSalon": func(string, int) string { return "◆" },
		"vignette":    func(a int64, i string) map[string]any { return map[string]any{"A": a, "I": i} },
		"decalage":    func(n int) string { return "" }, "urlembed": func(s string) string { return s }, "vignetteVideo": func(string) string { return "" },
	}
}

// #1167 : le salon « reseaux » (p.Mur = true) se rend en MUR de cardlets — média
// en fond, texte par-dessus — et PAS en liste « Tous les dossiers ». Le média,
// une couverture déjà relayée same-origin (/media-vignette), devient le fond.
func TestNewsroomMurReseaux(t *testing.T) {
	tpl, err := template.New("newsroom.html").Funcs(funcsNewsroom()).ParseFS(assets, "templates/newsroom.html", "templates/dock.html")
	if err != nil {
		t.Fatalf("parse : %v", err)
	}
	fil := store.Thread{ID: 12, Title: "Un post relayé de Mastodon", Author: "passerelle",
		Visibility: store.VisPublic, LastPostAt: 1700000000}
	p := page{
		Titre: "Réseaux", Site: "SecuBox", Hote: "gk2", Initiale: "S",
		Mur: true,
		Cat: store.Category{Slug: "reseaux", Title: "Réseaux"},
		News: []NewsItem{{
			Fil: &fil, Date: fil.LastPostAt,
			Medias: []cardMedia{{Ref: "/media-vignette?u=x", Kind: "image"}},
		}},
	}
	var buf bytes.Buffer
	if err := tpl.ExecuteTemplate(&buf, "newsroom", p); err != nil {
		t.Fatalf("exécution : %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		`class="rgrid"`,          // la grille du mur
		`class="rcard hasbg"`,    // carte AVEC fond (média présent)
		`class="rbg" src="/media-vignette?u=x"`, // le média RELAYÉ en fond
		"Un post relayé de Mastodon",            // le texte du post par-dessus
		"/t/12",                                 // lien vers le fil pour discuter
	} {
		if !strings.Contains(out, want) {
			t.Errorf("mur sans %q", want)
		}
	}
	// Le mur REMPLACE la liste standard : pas de « Tous les dossiers » ici.
	if strings.Contains(out, "Tous les dossiers") {
		t.Error("le salon reseaux ne doit pas rendre la liste « Tous les dossiers »")
	}
	// Garde CSP : le fond est une classe + <img>, jamais un style en ligne.
	if strings.Contains(out, "style=") {
		t.Error("style en ligne — interdit par la CSP")
	}
}

// Contre-épreuve : un salon ORDINAIRE (Mur = false) garde la liste « Tous les
// dossiers » et ne produit AUCUNE grille de mur. Sans quoi le test ci-dessus
// pourrait passer sur un gabarit qui rend toujours le mur.
func TestNewsroomSansMur(t *testing.T) {
	tpl, err := template.New("newsroom.html").Funcs(funcsNewsroom()).ParseFS(assets, "templates/newsroom.html", "templates/dock.html")
	if err != nil {
		t.Fatalf("parse : %v", err)
	}
	fil := store.Thread{ID: 1, Title: "Discussion", Author: "a", Visibility: store.VisPublic, LastPostAt: 1700000000}
	p := page{
		Titre: "Général", Site: "SecuBox", Initiale: "S",
		News: []NewsItem{{Fil: &fil, Date: fil.LastPostAt}},
	}
	var buf bytes.Buffer
	if err := tpl.ExecuteTemplate(&buf, "newsroom", p); err != nil {
		t.Fatalf("exécution : %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Tous les dossiers") {
		t.Error("un salon ordinaire doit garder la liste « Tous les dossiers »")
	}
	if strings.Contains(out, `class="rgrid"`) {
		t.Error("un salon ordinaire ne doit PAS rendre le mur réseaux")
	}
}
