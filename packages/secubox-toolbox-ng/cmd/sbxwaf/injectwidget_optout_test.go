// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"bytes"
	"testing"
)

// Une page qui porte <meta name="sbx-no-health-banner"> refuse la banniere.
// Ce refus est DOCUMENTE (layout.html du BBS s'y fie) mais n'etait pas
// implemente : la banniere etait injectee quand meme, et ses styles inline
// heurtaient le CSP strict de la page (style-src 'self').
func TestUnePageQuiRefuseLaBanniereNEstPasInjectee(t *testing.T) {
	page := []byte(`<!doctype html><html><head>` +
		`<meta name="sbx-no-health-banner"></head><body>salut</body></html>`)
	out := injectWidgetHTML(page, "https://admin.gk2.secubox.in")
	if !bytes.Equal(out, page) {
		t.Fatalf("banniere injectee malgre l'opt-out :\n%s", out)
	}
}

func TestLOptOutTolereLesEspacesEtLaCasse(t *testing.T) {
	// La balise peut s'ecrire de plusieurs facons ; l'opt-out ne doit pas
	// dependre d'une graphie exacte.
	for _, meta := range []string{
		`<meta name="sbx-no-health-banner">`,
		`<meta name='sbx-no-health-banner' content="1">`,
		`<META  NAME = "sbx-no-health-banner" >`,
	} {
		page := []byte(`<html><head>` + meta + `</head><body>x</body></html>`)
		out := injectWidgetHTML(page, "https://o")
		if !bytes.Equal(out, page) {
			t.Fatalf("opt-out non reconnu pour : %s", meta)
		}
	}
}

func TestSansOptOutLaBanniereEstBienInjectee(t *testing.T) {
	// Regression inverse : une page ordinaire recoit toujours le loader.
	page := []byte(`<html><body>contenu</body></html>`)
	out := injectWidgetHTML(page, "https://admin.gk2.secubox.in")
	if bytes.Equal(out, page) || !bytes.Contains(out, []byte(widgetGuard)) {
		t.Fatal("le loader devrait etre injecte sur une page ordinaire")
	}
}
