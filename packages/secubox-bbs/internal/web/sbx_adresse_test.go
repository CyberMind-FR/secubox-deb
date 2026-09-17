// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package web

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// On teste la LECTURE du registre sans dependre du fichier de la box : le
// comportement qui compte est « qui rend une adresse, et qui n'en rend pas ».
func lit(t *testing.T, contenu registreSbx) func(string) string {
	t.Helper()
	f := filepath.Join(t.TempDir(), "appareils.json")
	b, _ := json.Marshal(contenu)
	if err := os.WriteFile(f, b, 0o640); err != nil {
		t.Fatal(err)
	}
	return func(compte string) string {
		brut, err := os.ReadFile(f)
		if err != nil {
			return ""
		}
		var r registreSbx
		if json.Unmarshal(brut, &r) != nil {
			return ""
		}
		for _, a := range r.Appareils {
			if a.Compte == compte && a.Actif {
				return a.Email
			}
		}
		return ""
	}
}

// UN APPAREIL REVOQUE NE REND RIEN. C'est ICI que la revocation prend effet
// pour les notifications — sans qu'aucun message n'ait eu a circuler, et sans
// qu'une copie ait eu a etre effacee quelque part.
func TestUnAppareilRevoqueNAPlusDAdresse(t *testing.T) {
	get := lit(t, registreSbx{Appareils: []appareilSbx{
		{Compte: "sbx-aaa", Email: "vivant@example.fr", Actif: true},
		{Compte: "sbx-bbb", Email: "ecarte@example.fr", Actif: false},
	}})
	if got := get("sbx-aaa"); got != "vivant@example.fr" {
		t.Errorf("appareil actif : %q", got)
	}
	if got := get("sbx-bbb"); got != "" {
		t.Errorf("appareil REVOQUE doit rendre \"\", pas %q", got)
	}
	if got := get("sbx-inconnu"); got != "" {
		t.Errorf("inconnu doit rendre \"\", pas %q", got)
	}
}

// L'ADRESSE EST FACULTATIVE a l'admission : son absence n'est pas une erreur,
// c'est un membre qu'on ne notifie pas.
func TestSansAdresseDeclareeOnNeNotifiePas(t *testing.T) {
	get := lit(t, registreSbx{Appareils: []appareilSbx{
		{Compte: "sbx-ccc", Email: "", Actif: true},
	}})
	if got := get("sbx-ccc"); got != "" {
		t.Errorf("sans adresse : %q", got)
	}
}

// On ne cherche PAS hors du prefixe : un membre du BBS qui n'est pas un
// appareil n'a rien a faire dans ce registre.
func TestOnNeChercheQueLesComptesAppareil(t *testing.T) {
	var s Server
	if got := s.adresseSbx("sysop"); got != "" {
		t.Errorf("compte hors prefixe : %q", got)
	}
	if got := s.adresseSbx(""); got != "" {
		t.Errorf("compte vide : %q", got)
	}
}

// UN TITRE DE FIL NE DOIT PAS POUVOIR INJECTER D'EN-TETES.
//
// Le sujet du courriel est construit a partir d'un texte ecrit par un membre.
// Un saut de ligne dedans ajouterait des en-tetes arbitraires — un « Bcc: »
// vers n'importe qui, par exemple, depuis l'adresse de la box. On les RETIRE
// plutot que de les echapper : un titre de fil n'a aucune raison d'en contenir.
func TestUnTitreNInjectePasDEnTetes(t *testing.T) {
	nettoie := func(v string) string {
		v = strings.ReplaceAll(v, "\r", " ")
		v = strings.ReplaceAll(v, "\n", " ")
		if len(v) > 120 {
			v = v[:120]
		}
		return strings.TrimSpace(v)
	}
	mauvais := "Salut\r\nBcc: victime@ailleurs.example\r\n\r\nCorps injecte"
	got := nettoie(mauvais)
	if strings.ContainsAny(got, "\r\n") {
		t.Fatalf("le titre nettoye contient encore un saut de ligne : %q", got)
	}
	if strings.Contains(got, "Bcc:") && strings.ContainsAny(got, "\r\n") {
		t.Fatalf("en-tete injectable : %q", got)
	}
	// Et il reste borne : un titre de dix mille signes ne fait pas un sujet.
	if n := len(nettoie(strings.Repeat("a", 500))); n > 120 {
		t.Fatalf("titre non borne : %d", n)
	}
}
