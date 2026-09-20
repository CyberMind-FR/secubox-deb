// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Package web embarque les documents servis par le demon.
//
// L'embarquement vit ICI et non dans internal/api parce que `go:embed` ne
// peut pas designer un chemin hors du repertoire de son paquet. Le cardlet
// est donc lu par le demon lui-meme, sans dependre du systeme de fichiers —
// ce qui le rend servable meme si /usr/share n'est pas monte.
package web

import (
	"embed"
	"io/fs"
)

//go:embed static
var embarque embed.FS

// Static rend l'arborescence des documents, racinee sur static/.
func Static() fs.FS {
	sous, err := fs.Sub(embarque, "static")
	if err != nil {
		panic(err) // impossible : le chemin est fige a la compilation
	}
	return sous
}
