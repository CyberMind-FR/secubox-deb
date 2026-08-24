// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package web

import (
	"encoding/json"
	"net/http"
)

// apiMenu expose les RUBRIQUES publiques du BBS en JSON. Le Hall WebOS les lit
// côté serveur (via son adaptateur menu, sur la socket bbs) pour construire le
// SOUS-MENU BBS dans le mégamenu — la « navbar embarquée » remontée dans le
// bureau (#1175). Rubriques publiques uniquement : rien de sensible.
func (s *Server) apiMenu(w http.ResponseWriter, r *http.Request) {
	cats, _ := s.st.Categories(true)
	type item struct {
		Slug    string `json:"slug,omitempty"`
		Path    string `json:"path,omitempty"`
		Icon    string `json:"icon,omitempty"`
		Title   string `json:"title"`
		Threads int    `json:"threads,omitempty"`
	}
	out := make([]item, 0, len(cats))
	for _, c := range cats {
		out = append(out, item{Slug: c.Slug, Title: c.Title, Threads: c.Threads})
	}

	// Seconde section de la navbar BBS : « Accès » (#1187). Elle remonte telle
	// quelle dans le menu contextuel du Hall.
	//
	// PUBLIQUE UNIQUEMENT. Le Hall lit cette route par la socket, donc SANS
	// session : « Messages » (avec son compteur de non-lus) et « Sysop » n'y
	// figurent PAS — ils dépendent de qui regarde, et les publier ici les
	// exposerait à tout le monde. Ils restent dans la navbar du BBS, où la
	// session existe.
	st, _ := s.st.Stats()
	acces := []item{
		{Path: "/media", Icon: "🎧", Title: "Médiathèque"},
		{Path: "/biblio", Icon: "📚", Title: "Bibliothèque", Threads: st.Files},
		{Path: "/billets", Icon: "📝", Title: "Billets", Threads: st.Billets},
		{Path: "/c/reseaux", Icon: "🌐", Title: "Réseaux"},
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=30")
	// `categories` est conservé tel quel : l'adaptateur Hall d'avant #1187 le
	// lit encore. `access` s'y ajoute sans rien casser.
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"categories": out,
		"access":     acces,
	})
}
