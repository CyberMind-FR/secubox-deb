// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"testing"
)

const origineGk2 = "https://admin.gk2.secubox.in"

func avecCSP(pols ...string) http.Header {
	h := http.Header{}
	for _, p := range pols {
		h.Add("Content-Security-Policy", p)
	}
	return h
}

// L'empreinte que la radio déclare dans son unité (--banniere-hash) est celle
// du chargeur pour admin.gk2 : notre calcul est donc le même que le sien.
func TestEmpreinteDuChargeurEgaleCelleDeLaRadio(t *testing.T) {
	s := sha256.Sum256([]byte(chargeurBanniere(origineGk2)))
	if got := "sha256-" + base64.StdEncoding.EncodeToString(s[:]); got != "sha256-eDTYsncfrGT/tlGmdDgSPq9JNg8lg8MeoFWIUtAxVHs=" {
		t.Fatalf("empreinte du chargeur = %s", got)
	}
}

// #1725 : SBX OS et la messagerie (script-src 'self' 'unsafe-inline') refusaient
// le bandeau d'admin.gk2 — erreurs en console. On n'injecte plus.
func TestLaCSPDeLaPageALeDernierMot(t *testing.T) {
	cas := []struct {
		nom    string
		h      http.Header
		permis bool
	}{
		{"pas de CSP", avecCSP(), true},
		{"sbxos : self + unsafe-inline", avecCSP("default-src 'self'; script-src 'self' 'unsafe-inline'; frame-ancestors 'self'"), false},
		{"inline + origine", avecCSP("script-src 'self' 'unsafe-inline' https://admin.gk2.secubox.in"), true},
		{"inline + joker du domaine", avecCSP("script-src 'self' 'unsafe-inline' https://*.gk2.secubox.in"), true},
		{"origine mais pas d'inline", avecCSP("script-src 'self' https://admin.gk2.secubox.in"), false},
		{"inline annulé par un nonce", avecCSP("script-src 'self' 'unsafe-inline' 'nonce-abc' https://admin.gk2.secubox.in"), false},
		{"radio : empreinte + origine", avecCSP("script-src 'self' https://admin.gk2.secubox.in 'sha256-eDTYsncfrGT/tlGmdDgSPq9JNg8lg8MeoFWIUtAxVHs='"), true},
		{"default-src seul, permissif", avecCSP("default-src * 'unsafe-inline'"), true},
		{"sans script-src ni default-src", avecCSP("frame-ancestors 'self'"), true},
		{"deux politiques, la seconde refuse", avecCSP("script-src * 'unsafe-inline'", "script-src 'self'"), false},
	}
	for _, c := range cas {
		if got := laCSPPermet(c.h, origineGk2); got != c.permis {
			t.Errorf("%s : laCSPPermet = %v, attendu %v", c.nom, got, c.permis)
		}
	}
}
