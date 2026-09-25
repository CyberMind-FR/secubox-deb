// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// #1440 — une session BBS ouverte par le Hall ne survit pas à sa session SecuBox.
func TestLaSessionDuHallNeSurvitPasASaSource(t *testing.T) {
	srv, s := banc(t)
	srv.verif = verifFixe("sbx-ff90aec2d8d8", "user")
	w := auto(t, srv, "/", true)
	bbs := cookieNomme(w, cookieSession)
	if bbs == nil {
		t.Fatal("aucune session BBS posée")
	}
	req := func(avecHall bool) *http.Request {
		r := httptest.NewRequest("GET", "/", nil)
		r.AddCookie(bbs)
		if avecHall {
			r.AddCookie(&http.Cookie{Name: "secubox_session", Value: "jeton-du-hall"})
		}
		return r
	}
	if v := srv.qui(req(true)); !v.Connecte {
		t.Fatal("session SecuBox vivante : la BBS devait rester ouverte")
	}
	// Le Hall a été quitté / l'appareil révoqué : plus de session SecuBox.
	if v := srv.qui(req(false)); v.Connecte {
		t.Fatal("session BBS encore ouverte sans sa source")
	}
	if _, err := s.UserBySession(bbs.Value); err == nil {
		t.Fatal("la session BBS n'a pas été fermée")
	}
}

// Rattaché à un autre compte : la session SecuBox vaut, mais pas pour ce membre.
func TestUneSourceDUnAutreCompteNeSuffitPas(t *testing.T) {
	srv, s := banc(t)
	srv.verif = verifFixe("sbx-ff90aec2d8d8", "user")
	bbs := cookieNomme(auto(t, srv, "/", true), cookieSession)
	srv.verif = verifFixe("gk2", "admin")
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(bbs)
	r.AddCookie(&http.Cookie{Name: "secubox_session", Value: "jeton-du-hall"})
	srv.qui(r)
	if _, err := s.UserBySession(bbs.Value); err == nil {
		t.Fatal("session d'un autre compte conservée")
	}
}

// Une session LOCALE (formulaire) n'est pas concernée.
func TestUneSessionLocaleNEstPasTouchee(t *testing.T) {
	srv, s := banc(t)
	id, err := s.CreateUser("cedre83", "Cèdre", "member")
	if err != nil {
		t.Fatal(err)
	}
	jeton, _ := s.NewSession(id, "", "")
	srv.verif = verifFixe("gk2", "admin")
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: cookieSession, Value: jeton})
	if v := srv.qui(r); !v.Connecte {
		t.Fatal("session locale fermée à tort")
	}
}
