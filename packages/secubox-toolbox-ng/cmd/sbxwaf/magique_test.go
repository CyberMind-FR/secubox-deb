// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// SecuBox-Deb :: toolbox-ng :: sbxwaf — tests des octets magiques non raster (#3273, R-IMG1)
package main

import "testing"

func TestMagiqueNonRaster(t *testing.T) {
	cas := []struct{ entree, attendu string }{
		{"<svg xmlns=\"http://www.w3.org/2000/svg\">", "svg"},
		{"<SVG>", "svg"},
		{"<?xml version=\"1.0\"?>\n<image href=\"x\"/>", "svg"},
		{"<?xml version=\"1.0\"?>\n<rien/>", ""},
		{"<image href=\"x\"/>", ""},
		{"%!PS-Adobe-3.0", "ps"},
		{"\xC5\xD0\xD3\xC6\x20\x00", "eps"},
		{"%PDF-1.7", "pdf"},
		{"push graphic-context\nviewbox 0 0 1 1", "mvg"},
		{"PUSH GRAPHIC-CONTEXT", "mvg"},
		{"\x89PNG\r\n\x1a\n", ""},
		{"\xFF\xD8\xFF\xE0", ""},
		{"", ""},
		// Au-delà de 64 octets, rien n'est lu.
		{"                                                                      <svg", ""},
		// Dernier octet de la fenêtre : « <svg » tient dans les 64 premiers.
		{"                                                            <svg", "svg"},
	}
	for _, c := range cas {
		if got := magiqueNonRaster([]byte(c.entree)); got != c.attendu {
			t.Errorf("magiqueNonRaster(%q) = %q, attendu %q", c.entree, got, c.attendu)
		}
	}
}

// Ordre de test : eps, ps, pdf, mvg, svg.
func TestMagiqueNonRasterOrdre(t *testing.T) {
	if got := magiqueNonRaster([]byte("%PDF-1 %!PS <svg")); got != "ps" {
		t.Errorf("ps avant pdf et svg : %q", got)
	}
	if got := magiqueNonRaster([]byte("<svg \xC5\xD0\xD3\xC6")); got != "eps" {
		t.Errorf("eps avant svg : %q", got)
	}
	if got := magiqueNonRaster([]byte("push graphic-context <svg")); got != "mvg" {
		t.Errorf("mvg avant svg : %q", got)
	}
}
