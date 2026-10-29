// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// SecuBox-Deb :: toolbox-ng :: sbxwaf — octets magiques non raster (#3273, R-IMG1)
//
// Roundcube passe une photo de contact ou une image envoyée à ImageMagick
// (CVE-2026-114727) : SVG, EPS, PostScript, PDF et MVG y appellent des
// délégués ou des ressources externes. R-IMG1 regarde les premiers octets
// d'une partie fichier et dit si le contenu est l'un de ces formats.
//
// COÛT BORNÉ : au plus magiqueOctets (64) octets sont lus, recopiés dans un
// tableau de pile, jamais journalisés (spécification § 3.3).

package main

import "bytes"

// magiqueOctets : octets examinés par partie fichier (spécification § 3.3,
// R-IMG1, valeur sourcée).
const magiqueOctets = 64

// magiqueNonRaster cherche, dans debut[:min(len, 64)], les marqueurs d'un
// format non raster (insensibles à la casse ASCII). Rend "eps"
// (\xC5\xD0\xD3\xC6), "ps" (%!PS), "pdf" (%PDF-), "mvg" (push graphic-context),
// "svg" (<svg, ou <?xml suivi plus loin de <image), sinon "".
// Ordre de test : eps, ps, pdf, mvg, svg. L'étiquette ne sert qu'aux tests :
// la signature ne retient que le booléen.
func magiqueNonRaster(debut []byte) string {
	if len(debut) > magiqueOctets {
		debut = debut[:magiqueOctets]
	}
	var tampon [magiqueOctets]byte
	b := tampon[:len(debut)]
	for i, c := range debut {
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		b[i] = c
	}
	switch {
	case bytes.Contains(b, []byte("\xc5\xd0\xd3\xc6")):
		return "eps"
	case bytes.Contains(b, []byte("%!ps")):
		return "ps"
	case bytes.Contains(b, []byte("%pdf-")):
		return "pdf"
	case bytes.Contains(b, []byte("push graphic-context")):
		return "mvg"
	case bytes.Contains(b, []byte("<svg")):
		return "svg"
	}
	if i := bytes.Index(b, []byte("<?xml")); i >= 0 && bytes.Contains(b[i:], []byte("<image")) {
		return "svg"
	}
	return ""
}
