// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package web

import (
	"testing"

	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/store"
)

// UN ADMINISTRATEUR SECUBOX N'EST PAS D'OFFICE SYSOP. Ce sont deux
// responsabilites distinctes : les confondre donnerait la moderation du forum a
// quiconque obtient l'administration de la box.
func TestRoleDepuisProfilNeDonneJamaisSysop(t *testing.T) {
	for _, p := range []string{"admin", "sysop", "root", "ADMIN", " admin "} {
		if got := roleDepuisProfil(p); got == store.RoleSysop {
			t.Fatalf("roleDepuisProfil(%q) = sysop — jamais", p)
		}
	}
	if got := roleDepuisProfil("admin"); got != store.RoleMember {
		t.Errorf("admin doit donner member, pas %q", got)
	}
	if got := roleDepuisProfil("user"); got != store.RoleMember {
		t.Errorf("user doit donner member, pas %q", got)
	}
	// Tout le reste — guest, vide, inconnu — reste invite.
	for _, p := range []string{"guest", "", "n'importe quoi"} {
		if got := roleDepuisProfil(p); got != store.RoleGuest {
			t.Errorf("roleDepuisProfil(%q) = %q, veut guest", p, got)
		}
	}
}

// LE NOM DE COMPTE EST BORNE. Il devient un pseudonyme AFFICHE et sert de cle :
// ce qui n'a pas la forme d'un compte SecuBox n'entre pas.
func TestCompteSbxBorne(t *testing.T) {
	bons := []string{"sbx-4e943496630e", "admin", "gk2", "operator", "a.b-c_d"}
	for _, c := range bons {
		if !reCompteSbx.MatchString(c) {
			t.Errorf("%q devrait etre accepte", c)
		}
	}
	mauvais := []string{
		"", "ab", // trop court
		"Majuscule",              // nginx rend du minuscule ; on n'invente pas
		"avec espace",            //
		"../../etc/passwd",       // traversee
		"<script>alert(1)</script>",
		"nom\navec\nsaut",        // injection d'en-tete
	}
	for _, c := range mauvais {
		if reCompteSbx.MatchString(c) {
			t.Errorf("%q NE devrait PAS etre accepte", c)
		}
	}
}
