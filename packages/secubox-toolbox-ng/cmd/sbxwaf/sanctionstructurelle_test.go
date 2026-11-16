// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// #3741 : sanction des détections structurelles selon le mode de la catégorie,
// et relecture à chaud de vhost_profiles.json.
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func serveurStructurel(t *testing.T, mode, extra string) (*Server, *fauxNft) {
	t.Helper()
	corpus := `{"categories": {"php2shell": {"severity": "high", "mode": "` + mode + `"` + extra + `,
	  "structural": [{"id": "h-1", "check": "filename_charge"}]}}}`
	s := &Server{rules: LoadRules(ecrisRegles(t, corpus))}
	s.escalateBan = NewBan(24*time.Hour, 3)
	fx := &fauxNft{}
	b := banneurTest(t, fx)
	if err := b.Ensure(); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	s.nftBan = b
	return s, fx
}

func detectionsStructurelles(t *testing.T, s *Server) []DetectionStructurelle {
	t.Helper()
	ds := s.rules.EvaluerStructurel(ResultatMultipart{FilenamePHP: true})
	if len(ds) != 1 {
		t.Fatalf("%d détections, attendu 1", len(ds))
	}
	return ds
}

func TestSanctionStructurelle_DetectNeBannitPas(t *testing.T) {
	s, fx := serveurStructurel(t, "detect", "")
	d := detectionsStructurelles(t, s)[0]
	for i := 0; i < 5; i++ {
		if a := s.sanctionStructurelle("203.0.113.90", d); a != "detect" {
			t.Fatalf("action %q, attendu detect", a)
		}
	}
	if n := len(ajoutsNft(fx, 0)); n != 0 {
		t.Fatalf("detect a banni %d fois", n)
	}
}

func TestSanctionStructurelle_BlockBannitAuPremier(t *testing.T) {
	s, fx := serveurStructurel(t, "block", `, "ban_duree": "24h"`)
	d := detectionsStructurelles(t, s)[0]
	if a := s.sanctionStructurelle("203.0.113.91", d); a != "banned" {
		t.Fatalf("action %q, attendu banned", a)
	}
	a := ajoutsNft(fx, 1)
	if len(a) != 1 || !strings.Contains(a[0], "timeout 86400s") {
		t.Fatalf("ban attendu 24h, obtenu %v", a)
	}
}

func TestSanctionStructurelle_EscalateSuitLeSeuil(t *testing.T) {
	s, fx := serveurStructurel(t, "escalate", `, "ban_seuil": 2`)
	d := detectionsStructurelles(t, s)[0]
	if a := s.sanctionStructurelle("203.0.113.92", d); a != "detect" {
		t.Fatalf("1re touche : %q, attendu detect", a)
	}
	if a := s.sanctionStructurelle("203.0.113.92", d); a != "banned" {
		t.Fatalf("2e touche : %q, attendu banned", a)
	}
	if n := len(ajoutsNft(fx, 1)); n != 1 {
		t.Fatalf("banneur appelé %d fois, attendu 1", n)
	}
}

func TestSanctionStructurelle_EscalateSeuilGlobal(t *testing.T) {
	s, _ := serveurStructurel(t, "escalate", "")
	d := detectionsStructurelles(t, s)[0]
	for i := 1; i <= 2; i++ {
		if a := s.sanctionStructurelle("203.0.113.93", d); a != "detect" {
			t.Fatalf("touche %d : %q, attendu detect", i, a)
		}
	}
	if a := s.sanctionStructurelle("203.0.113.93", d); a != "banned" {
		t.Fatalf("3e touche : %q, attendu banned (seuil global 3)", a)
	}
}

func TestVhostProfiles_RelectureAChaud(t *testing.T) {
	f := filepath.Join(t.TempDir(), "vhost_profiles.json")
	ecrire := func(contenu string, mtime time.Time) {
		if err := os.WriteFile(f, []byte(contenu), 0o640); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(f, mtime, mtime); err != nil {
			t.Fatal(err)
		}
	}
	base := time.Now().Add(-time.Hour)
	ecrire(`{"php_hotes": []}`, base)
	vp, err := chargerVhostProfiles(f)
	if err != nil {
		t.Fatal(err)
	}
	w := surveillerVhostProfiles(f, vp)
	if _, php := vp.servicePHP("blog.exemple.fr"); php {
		t.Fatal("hôte PHP avant cochage")
	}
	ecrire(`{"php_hotes": ["^blog\\.exemple\\.fr$"]}`, base.Add(time.Minute))
	w.Maybe()
	if _, php := vp.servicePHP("blog.exemple.fr"); !php {
		t.Fatal("hôte coché non couvert après relecture (mémoire non vidée ?)")
	}
	// Fichier cassé : les profils précédents restent.
	ecrire(`{pas du json`, base.Add(2*time.Minute))
	w.Maybe()
	if _, php := vp.servicePHP("blog.exemple.fr"); !php {
		t.Fatal("un fichier illisible a fait perdre la couverture")
	}
}
