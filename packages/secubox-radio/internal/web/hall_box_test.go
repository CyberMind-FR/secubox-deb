// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package web

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// confDe pose un secubox.conf de test et rend la fonction de remise en état.
func confDe(t *testing.T, contenu string) {
	t.Helper()
	f := filepath.Join(t.TempDir(), "secubox.conf")
	if contenu != "" {
		if err := os.WriteFile(f, []byte(contenu), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	ancien := fichierConfBox
	fichierConfBox = f
	confBox.lu = time.Time{}
	t.Cleanup(func() { fichierConfBox = ancien; confBox.lu = time.Time{} })
}

// #1725 : sur gk3, le Hall de la box (hall.gk3) doit pouvoir encadrer ses services.
func TestHallDeLaBoxSuitLeDomaine(t *testing.T) {
	confDe(t, "[api]\ndomain = \"faux.example\"\n[global]\nhostname = \"gk3\"\ndomain    = \"gk3.secubox.in\"  # la box\n")
	if got := hallDeLaBox(); got != " https://hall.gk3.secubox.in" {
		t.Fatalf("hallDeLaBox() = %q", got)
	}
	if got := origineBox("bbs"); got != "https://bbs.gk3.secubox.in" {
		t.Fatalf("origineBox(bbs) = %q", got)
	}
}

// gk2 n'a pas de [global] domain : son domaine vient du cookie de session,
// comme pour secubox_core.auth.domaine_box().
func TestDomaineParLeCookieCommeGk2(t *testing.T) {
	confDe(t, "[global]\nhostname = \"secubox-mochabin\"\n[api]\nsso_cookie_domain = \".gk2.secubox.in\"\n")
	if got := origineBox("admin"); got != "https://admin.gk2.secubox.in" {
		t.Fatalf("origineBox(admin) = %q", got)
	}
	confDe(t, "[global]\ndomain = \"gk3.secubox.in\"\n[api]\nsso_cookie_domain = \".gk2.secubox.in\"\n")
	if got := domaineBox(); got != "gk3.secubox.in" {
		t.Fatalf("[global] domain doit primer : %q", got)
	}
}

func TestHallDeLaBoxRienSurGk2NiSansDomaine(t *testing.T) {
	confDe(t, "[global]\ndomain = \"gk2.secubox.in\"\n")
	if got := hallDeLaBox(); got != "" {
		t.Fatalf("gk2 : hall.gk2 est déjà nommé, hallDeLaBox() = %q", got)
	}
	confDe(t, "")
	if got := hallDeLaBox(); got != "" {
		t.Fatalf("sans fichier : %q", got)
	}
	confDe(t, "[global]\ndomain = \"*.evil; script-src *\"\n")
	if got := hallDeLaBox(); got != "" {
		t.Fatalf("domaine invalide accepté : %q", got)
	}
}

// La politique de radio nomme hall.gk3 sur gk3 — l'erreur relevée dans la
// console du Hall de gk3 — et le cadre parent devient bbs.gk3.
func TestPolitiqueRadioSurGk3(t *testing.T) {
	confDe(t, "[global]\ndomain = \"gk3.secubox.in\"\n")
	s := &Serveur{}
	for nom, p := range map[string]string{"normale": s.politique(), "mini": s.politiqueMini()} {
		if !contient(p, "https://hall.gk3.secubox.in") {
			t.Fatalf("politique %s sans hall.gk3 : %s", nom, p)
		}
	}
	if !contient(s.politiqueMini(), "https://bbs.gk3.secubox.in") {
		t.Fatalf("cadre parent non dérivé : %s", s.politiqueMini())
	}
	s.CadreParent = "https://bbs.autre.example"
	if !contient(s.politiqueMini(), "https://bbs.autre.example") {
		t.Fatal("un cadre parent imposé par l'unité doit primer")
	}
}
