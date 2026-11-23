// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: sbxwaf :: pages 403 du WAF sur la mire commune (#3885).
package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWarningPageMarqueurEnTeteEtCategorie(t *testing.T) {
	rec := httptest.NewRecorder()
	writeWarning(rec, "sqli")
	if rec.Code != http.StatusForbidden || rec.Header().Get("X-SecuBox-WAF") != "warning" {
		t.Fatalf("statut %d, en-tête %q", rec.Code, rec.Header().Get("X-SecuBox-WAF"))
	}
	b := rec.Body.String()
	for _, attendu := range []string{"<!-- sbxwaf-warning -->", "<b>sqli</b>", `lang="fr"`, "REQUÊTE BLOQUÉE PAR LE PARE-FEU"} {
		if !strings.Contains(b, attendu) {
			t.Errorf("page d'avertissement sans %q", attendu)
		}
	}
	if strings.Contains(b, "{categorie}") || strings.Contains(b, "sbxwaf-banned") {
		t.Error("espace réservé restant ou mauvais marqueur")
	}
}

func TestWarningPageEchappeLaCategorie(t *testing.T) {
	b := string(warningPage(`"><script>alert(1)</script>`))
	if strings.Contains(b, "<script>") {
		t.Fatal("catégorie reflétée sans échappement")
	}
	if !strings.Contains(b, "&lt;script&gt;") {
		t.Fatal("catégorie absente ou mal échappée")
	}
}

func TestBanPageMarqueurEtEnTete(t *testing.T) {
	rec := httptest.NewRecorder()
	writeBan(rec)
	if rec.Code != http.StatusForbidden || rec.Header().Get("X-SecuBox-WAF") != "banned" {
		t.Fatalf("statut %d, en-tête %q", rec.Code, rec.Header().Get("X-SecuBox-WAF"))
	}
	b := rec.Body.String()
	if !strings.Contains(b, "<!-- sbxwaf-banned -->") || !strings.Contains(b, "ADRESSE BLOQUÉE") || strings.Contains(b, "sbxwaf-warning") {
		t.Fatal("page de bannissement sans son marqueur ou sa phrase")
	}
}

func TestErrorPagesSubstituentHoteEtHeure(t *testing.T) {
	for _, code := range []int{502, 503, 504} {
		b := string(errorPage(code, "hote.exemple"))
		if strings.Contains(b, "{host}") || strings.Contains(b, "{time}") || !strings.Contains(b, "<b>hote.exemple</b>") {
			t.Errorf("errorPage(%d) : espaces réservés mal substitués", code)
		}
		if strings.Contains(b, "<script") {
			t.Errorf("errorPage(%d) : JavaScript inattendu", code)
		}
	}
}
