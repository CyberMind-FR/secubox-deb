// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package web

import (
	"strings"
	"testing"
)

// #2996 — encarté par le Hall v2 ({sbx:'carte'}), le micro range sa marque (icône, titre) : la Card la porte déjà.
func TestMicroEncarteRangeSaMarque(t *testing.T) {
	b, err := assets.ReadFile("static/micro.html")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.Contains(s, "d.sbx === 'carte'") || !strings.Contains(s, "classList.add('sbx-carte')") {
		t.Fatal("micro.html n'écoute pas {sbx:'carte'}")
	}
	if !strings.Contains(s, "html.sbx-carte .tete .ic, html.sbx-carte .tete b { display:none; }") {
		t.Fatal("micro.html ne range pas sa marque une fois encarté")
	}
}
