// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
package web

import (
	"strings"
	"testing"
)

// Le gabarit sysop reference des champs de page ; un nom errone ne se voit
// qu'a l'execution, sur la page rendue au sysop. Ce test les confronte.
func TestGabaritSysopReferenceDesChampsExistants(t *testing.T) {
	src, err := assets.ReadFile("templates/sysop.html")
	if err != nil {
		t.Fatalf("lecture du gabarit : %v", err)
	}
	texte := string(src)
	for _, attendu := range []string{
		"/mod/salon",         // le formulaire de creation de salon
		"{{.V.CSRF}}",        // sans jeton, le formulaire serait rejete
		"range .Cats",        // la liste des parents possibles
		"range .Moderations", // le journal des gestes
	} {
		if !strings.Contains(texte, attendu) {
			t.Errorf("le panneau sysop ne contient pas %q", attendu)
		}
	}
}
