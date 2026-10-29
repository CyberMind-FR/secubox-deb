// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Vhosts PHP déclarés (#3257) : php_services dans vhost_profiles.json.
package main

import (
	"log"
	"os"
	"strings"
	"testing"
)

func TestVhostProfilesEstPHP(t *testing.T) {
	vp, err := chargerVhostProfilesDepuis([]byte(`{
		"services": {"nextcloud": {"legit_paths": []}, "gitea": {"legit_paths": []}},
		"vhosts": {"nc.example": "nextcloud", "git.example": "gitea"},
		"php_services": ["nextcloud"]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if !vp.estPHP("NC.example:443") {
		t.Error("NC.example:443 devrait être PHP")
	}
	if vp.estPHP("autre.example") {
		t.Error("hôte inconnu : pas PHP")
	}
	if vp.estPHP("git.example") {
		t.Error("service non déclaré PHP : pas PHP")
	}
}

func TestVhostProfilesEstPHPNil(t *testing.T) {
	if (*VhostProfiles)(nil).estPHP("x") {
		t.Error("récepteur nil : false attendu")
	}
}

func TestVhostProfilesPHPCleAbsente(t *testing.T) {
	vp, err := chargerVhostProfilesDepuis([]byte(`{
		"services": {"nextcloud": {"legit_paths": []}},
		"vhosts": {"nc.example": "nextcloud"}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if vp.estPHP("nc.example") {
		t.Error("clé absente : aucun vhost PHP")
	}
}

func TestVhostProfilesPHPServiceInconnu(t *testing.T) {
	vp, err := chargerVhostProfilesDepuis([]byte(`{
		"services": {"nextcloud": {"legit_paths": []}},
		"vhosts": {"nc.example": "nextcloud"},
		"php_services": ["fantome"]
	}`))
	if err != nil {
		t.Fatalf("service PHP inconnu ne doit pas invalider le fichier : %v", err)
	}
	if vp.estPHP("nc.example") || vp.estPHP("fantome") {
		t.Error("aucun hôte PHP attendu")
	}
}

func TestVhostProfilesLivreChargeAvecPHP(t *testing.T) {
	vp, err := chargerVhostProfiles(fichierLivreWafNg(t, "vhost_profiles.json"))
	if err != nil {
		t.Fatalf("fichier livré : %v", err)
	}
	for _, h := range []string{"webmail.gk2.secubox.in", "nc.gk2.secubox.in"} {
		if !vp.estPHP(h) {
			t.Errorf("%s devrait être PHP", h)
		}
	}
	if vp.estPHP("gitea.gk2.secubox.in") {
		t.Error("gitea n'est pas PHP")
	}
}

// I3 (R15) : motifs d'hôte PHP, pour les vhosts qu'aucune liste de box ne nomme.
const profilsMotifs = `{
	"services": {"nextcloud": {"legit_paths": []}, "gitea": {"legit_paths": []}},
	"vhosts": {"nc.gk2.example": "nextcloud", "git.example": "gitea"},
	"php_services": ["nextcloud"],
	"php_hotes": ["^(nc|nextcloud|cloud)\\.", "^(webmail|roundcube)\\."]
}`

func TestVhostProfilesPHPHotes(t *testing.T) {
	vp, err := chargerVhostProfilesDepuis([]byte(profilsMotifs))
	if err != nil {
		t.Fatal(err)
	}
	cas := map[string]bool{
		"nextcloud.gk1.secubox.in":     true, // alias sans liste propre
		"NC.Autre-Box.example:443":     true, // hôte normalisé (casse, port)
		"cloud.example":                true,
		"webmail.gk1.secubox.in":       true,
		"roundcube.x.example":          true,
		"nc.gk2.example":               true, // explicite
		"git.example":                  false,
		"monnc.example":                false,
		"gitea.gk1.secubox.in":         false,
		"nextcloudx.example":           false,
		"webmail":                      false,
		"peertube.nextcloud.example.x": false,
	}
	for h, want := range cas {
		if got := vp.estPHP(h); got != want {
			t.Errorf("estPHP(%q) = %v, attendu %v", h, got, want)
		}
	}
	if n, m := vp.armementPHP(); n != 1 || m != 2 {
		t.Errorf("armementPHP = (%d, %d), attendu (1 explicite, 2 motifs)", n, m)
	}
}

func TestVhostProfilesPHPHoteInvalideRejeteSeul(t *testing.T) {
	var journal strings.Builder
	log.SetOutput(&journal)
	defer log.SetOutput(os.Stderr)
	vp, err := chargerVhostProfilesDepuis([]byte(`{
		"services": {}, "vhosts": {},
		"php_hotes": ["(", "^webmail\\.", 7]
	}`))
	if err != nil {
		t.Fatalf("un motif invalide ne doit pas refuser tout le fichier : %v", err)
	}
	if !vp.estPHP("webmail.example") {
		t.Error("le motif valide doit rester armé")
	}
	if _, m := vp.armementPHP(); m != 1 {
		t.Errorf("%d motif(s) armé(s), attendu 1", m)
	}
	if !strings.Contains(journal.String(), "php_hotes") || strings.Count(journal.String(), "rejeté") != 2 {
		t.Errorf("chaque motif rejeté doit être journalisé : %q", journal.String())
	}
}

func TestJournaliserArmementPHP(t *testing.T) {
	vp, err := chargerVhostProfilesDepuis([]byte(profilsMotifs))
	if err != nil {
		t.Fatal(err)
	}
	if got := ligneArmementPHP(vp); got != "sbxwaf: vhosts PHP armés : 1 explicites, 2 motifs" {
		t.Errorf("ligne : %q", got)
	}
	if got := ligneArmementPHP(nil); !strings.HasPrefix(got, "sbxwaf: vhosts PHP armés : 0 explicites, 0 motifs") {
		t.Errorf("sans profils : %q", got)
	}
}

func TestVhostProfilesLivreMotifsPHP(t *testing.T) {
	vp, err := chargerVhostProfiles(fichierLivreWafNg(t, "vhost_profiles.json"))
	if err != nil {
		t.Fatalf("fichier livré : %v", err)
	}
	for _, h := range []string{"nextcloud.gk2.secubox.in", "nc.gk1.secubox.in", "cloud.box.example", "webmail.gk1.secubox.in", "roundcube.gk3.secubox.in"} {
		if !vp.estPHP(h) {
			t.Errorf("%s devrait être PHP par motif livré", h)
		}
	}
	if _, m := vp.armementPHP(); m != 2 {
		t.Errorf("motifs livrés armés : %d, attendu 2", m)
	}
}
