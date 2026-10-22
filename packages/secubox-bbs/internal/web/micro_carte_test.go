// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package web

import (
	"os"
	"strings"
	"testing"
)

// #2996 — encarté par le Hall v2 ({sbx:'carte'}), le micro range sa marque (icône, titre) : la Card la porte déjà.
func TestMicroEncarteRangeSaMarque(t *testing.T) {
	js, err := os.ReadFile("static/micro.js")
	if err != nil {
		t.Fatal(err)
	}
	css, err := os.ReadFile("static/micro.css")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(js), "d.sbx === 'carte'") || !strings.Contains(string(js), "classList.add('sbx-carte')") {
		t.Fatal("micro.js n'écoute pas {sbx:'carte'}")
	}
	if !strings.Contains(string(css), "html.sbx-carte .tete .ic, html.sbx-carte .tete b { display:none; }") {
		t.Fatal("micro.css ne range pas la marque une fois encarté")
	}
}
