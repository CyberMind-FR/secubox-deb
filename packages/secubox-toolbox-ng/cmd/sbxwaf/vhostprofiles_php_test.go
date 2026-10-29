// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Vhosts PHP déclarés (#3257) : php_services dans vhost_profiles.json.
package main

import "testing"

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
