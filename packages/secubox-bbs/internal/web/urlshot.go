// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Endpoint de lecture seule des vignettes-snapshot d'URL (#1120).
package web

import (
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var cleUrlshotRe = regexp.MustCompile(`^[0-9a-f]{32}$`)

// urlshotBase : racine du cache des snapshots — layout secubox_core.screenshots
// (<base>/<cle>/screenshot.png). VARIABLE, pas constante : les tests la
// redirigent vers un repertoire temporaire pour deposer un faux PNG sans
// toucher au systeme de fichiers reel.
var urlshotBase = "/var/cache/secubox/bbs/urlshots"

// servirUrlshot rend la vignette-snapshot d'une URL. NE CAPTURE JAMAIS : soit
// le cache contient deja le PNG, soit le visiteur recoit le placeholder — la
// capture est le travail du worker Python, hors requete web (voir plan #1120,
// "Global Constraints" : jamais de capture bloquant une requete).
//
// GATING DE VISIBILITE, MIROIR DE /f/ (#1114) : un visiteur anonyme ne recoit
// le vrai snapshot que si au moins un post PUBLIC cite l'URL. Sinon —
// visibilite 'local', ou cle inconnue — c'est le placeholder, jamais une
// erreur : la carte doit toujours pouvoir charger son <img>.
func (s *Server) servirUrlshot(w http.ResponseWriter, r *http.Request) {
	cle := strings.TrimPrefix(r.URL.Path, "/urlshot/")
	if !cleUrlshotRe.MatchString(cle) {
		http.NotFound(w, r)
		return
	}
	_, vis, ok := s.st.StatutUrlshot(cle)
	v := s.qui(r)
	autorise := ok && (vis == "public" || v.Connecte)
	if autorise {
		png := filepath.Join(urlshotBase, cle, "screenshot.png")
		if b, err := os.ReadFile(png); err == nil {
			w.Header().Set("Content-Type", "image/png")
			w.Header().Set("Cache-Control", "private, max-age=300")
			w.Write(b)
			return
		}
	}
	// Placeholder embarque (assets FS) — toujours 200 pour que l'<img> charge,
	// que la cle soit inconnue, la visibilite refusee, ou la capture pas
	// encore faite.
	if b, err := assets.ReadFile("static/urlshot-placeholder.png"); err == nil {
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "private, max-age=60")
		w.Write(b)
		return
	}
	http.NotFound(w, r)
}
