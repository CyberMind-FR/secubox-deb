// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package fbauth

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func storeAvecApp(t *testing.T, contenu string) *Store {
	t.Helper()
	d := t.TempDir()
	app := filepath.Join(d, "app")
	if contenu != "" {
		if err := os.WriteFile(app, []byte(contenu), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return New(app, filepath.Join(d, "token.json"), "https://socialrelay.gk2.secubox.in/")
}

func TestConfiguredFauxSansApp(t *testing.T) {
	s := storeAvecApp(t, "")
	if s.Configured() {
		t.Fatal("Configured devrait être faux sans secret app")
	}
}

func TestAppCredsDeuxLignesEtKV(t *testing.T) {
	for _, c := range []string{"1234567890\nsupersecret", "1234567890:supersecret", "app_id=1234567890\napp_secret=supersecret"} {
		s := storeAvecApp(t, c)
		if !s.Configured() {
			t.Fatalf("Configured faux pour %q", c)
		}
	}
}

func TestURLAutorisationContient(t *testing.T) {
	s := storeAvecApp(t, "1234567890\nsupersecret")
	st, err := s.NouvelÉtat()
	if err != nil {
		t.Fatal(err)
	}
	u, err := s.URLAutorisation(st)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(u, dialogURL+"?") {
		t.Fatalf("mauvais préfixe : %q", u)
	}
	pu, _ := url.Parse(u)
	q := pu.Query()
	if q.Get("client_id") != "1234567890" {
		t.Fatalf("client_id=%q", q.Get("client_id"))
	}
	if q.Get("state") != st {
		t.Fatalf("state=%q attendu %q", q.Get("state"), st)
	}
	if q.Get("redirect_uri") != "https://socialrelay.gk2.secubox.in/api/v1/socialrelay/fb/callback" {
		t.Fatalf("redirect_uri=%q", q.Get("redirect_uri"))
	}
	if q.Get("response_type") != "code" {
		t.Fatalf("response_type=%q", q.Get("response_type"))
	}
}

func TestÉtatUsageUnique(t *testing.T) {
	s := storeAvecApp(t, "1234567890\nsupersecret")
	st, _ := s.NouvelÉtat()
	if !s.ConsommerÉtat(st) {
		t.Fatal("premier usage devrait valider")
	}
	if s.ConsommerÉtat(st) {
		t.Fatal("second usage devrait échouer (usage unique)")
	}
	if s.ConsommerÉtat("inconnu") {
		t.Fatal("état inconnu devrait échouer")
	}
}

func TestJetonCacheEtExpiration(t *testing.T) {
	s := storeAvecApp(t, "1234567890\nsupersecret")
	if s.Jeton() != "" {
		t.Fatal("aucun jeton attendu au départ")
	}
	// jeton valide (expire dans 60 j)
	if err := s.écrireCache(jetonCache{AccessToken: "T_ok", ExpiresAt: time.Now().Add(60 * 24 * time.Hour).Unix()}); err != nil {
		t.Fatal(err)
	}
	if s.Jeton() != "T_ok" {
		t.Fatalf("jeton valide attendu, obtenu %q", s.Jeton())
	}
	if st := s.Statut(); !st.Connected {
		t.Fatal("Statut.Connected devrait être vrai")
	}
	// jeton périmé (expire dans 1 h < marge 24 h)
	if err := s.écrireCache(jetonCache{AccessToken: "T_old", ExpiresAt: time.Now().Add(time.Hour).Unix()}); err != nil {
		t.Fatal(err)
	}
	if s.Jeton() != "" {
		t.Fatal("jeton quasi-périmé devrait être rejeté")
	}
}
