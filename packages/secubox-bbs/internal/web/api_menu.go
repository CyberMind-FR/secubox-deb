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
		Slug    string `json:"slug"`
		Title   string `json:"title"`
		Threads int    `json:"threads"`
	}
	out := make([]item, 0, len(cats))
	for _, c := range cats {
		out = append(out, item{Slug: c.Slug, Title: c.Title, Threads: c.Threads})
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=30")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"categories": out})
}
