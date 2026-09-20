// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Package pairing trace le QR d'appairage.
//
// L'URI `sgnl://linkdevice?uuid=…&pub_key=…` est un SECRET DE COURTE DUREE :
// quiconque la scanne lie SON appareil au compte. Elle n'est donc jamais
// journalisee, jamais ecrite sur disque, et ne quitte le processus que sous
// forme d'IMAGE — le navigateur recoit des pixels, pas la chaine.
package pairing

import (
	"bytes"
	"fmt"

	qrcode "github.com/skip2/go-qrcode"
)

// SVG trace l'URI en SVG. Le trace est fait COTE SERVEUR : aucune
// bibliotheque JS, et l'URI ne transite pas en clair dans le DOM.
func SVG(uri string, taille int) (string, error) {
	if uri == "" {
		return "", fmt.Errorf("URI d'appairage vide")
	}
	// Correction de niveau Medium : le QR est lu a l'ecran, pas sur un papier
	// froisse ; monter la redondance ne ferait qu'epaissir le motif.
	q, err := qrcode.New(uri, qrcode.Medium)
	if err != nil {
		return "", err
	}
	grille := q.Bitmap()
	n := len(grille)
	if n == 0 {
		return "", fmt.Errorf("QR vide")
	}
	cell := taille / n
	if cell < 1 {
		cell = 1
	}

	var b bytes.Buffer
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" `+
		`viewBox="0 0 %d %d" shape-rendering="crispEdges" role="img" `+
		`aria-label="QR d'appairage Signal">`, n*cell, n*cell, n, n)
	b.WriteString(`<rect width="100%" height="100%" fill="#fff"/><path fill="#000" d="`)
	for y, ligne := range grille {
		for x, noir := range ligne {
			if noir {
				fmt.Fprintf(&b, "M%d %dh1v1h-1z", x, y)
			}
		}
	}
	b.WriteString(`"/></svg>`)
	return b.String(), nil
}
