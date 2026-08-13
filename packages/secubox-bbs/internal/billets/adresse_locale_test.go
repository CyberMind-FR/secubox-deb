// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
package billets

import (
	"database/sql"
	"path/filepath"
	"testing"
)

func baseEssai(t *testing.T) string {
	t.Helper()
	chemin := filepath.Join(t.TempDir(), "billets.db")
	db, err := sql.Open("sqlite", chemin)
	if err != nil {
		t.Fatalf("ouverture : %v", err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE billet (id TEXT PRIMARY KEY, slug TEXT)`); err != nil {
		t.Fatalf("schema : %v", err)
	}
	if _, err := db.Exec(`INSERT INTO billet VALUES ('01ABC','mon-billet-01abc'), ('01VIDE','')`); err != nil {
		t.Fatalf("donnees : %v", err)
	}
	return chemin
}

func TestAdresseLocale(t *testing.T) {
	db := baseEssai(t)
	got, err := AdresseLocale(db, "https://billets.gk2.secubox.in", "01ABC")
	if err != nil {
		t.Fatalf("AdresseLocale : %v", err)
	}
	if want := "https://billets.gk2.secubox.in/b/mon-billet-01abc"; got != want {
		t.Errorf("= %q, veut %q", got, want)
	}
}

func TestBarreFinaleAbsorbee(t *testing.T) {
	db := baseEssai(t)
	got, _ := AdresseLocale(db, "https://b.example/", "01ABC")
	if got != "https://b.example/b/mon-billet-01abc" {
		t.Errorf("= %q", got)
	}
}

func TestSansBaseUnCheminRelatif(t *testing.T) {
	// Un hote invente serait un lien mort presente comme bon ; la page Billets
	// sait deja dire « adresse manquante », ce qui est plus honnete.
	db := baseEssai(t)
	got, _ := AdresseLocale(db, "", "01ABC")
	if got != "/b/mon-billet-01abc" {
		t.Errorf("= %q", got)
	}
}

func TestBilletAbsentSignale(t *testing.T) {
	db := baseEssai(t)
	if _, err := AdresseLocale(db, "https://b.example", "01INCONNU"); err == nil {
		t.Error("un billet absent doit lever")
	}
}

func TestSlugVideSignale(t *testing.T) {
	db := baseEssai(t)
	if _, err := AdresseLocale(db, "https://b.example", "01VIDE"); err == nil {
		t.Error("un slug vide doit lever plutot que rendre /b/")
	}
}

func TestOuvertureEnLectureSeule(t *testing.T) {
	// Un outil de rattrapage n'a aucune raison de pouvoir ecrire chez le
	// voisin. Le mode `ro` le GARANTIT au lieu de le promettre.
	db := baseEssai(t)
	conn, err := sql.Open("sqlite", "file:"+db+"?mode=ro")
	if err != nil {
		t.Fatalf("ouverture : %v", err)
	}
	defer conn.Close()
	if _, err := conn.Exec(`INSERT INTO billet VALUES ('X','y')`); err == nil {
		t.Error("une ecriture doit etre refusee en mode ro")
	}
}
