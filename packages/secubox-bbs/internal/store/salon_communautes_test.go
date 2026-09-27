// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package store

import (
	"database/sql"
	"path/filepath"
	"testing"
)

// fausseSbx : le strict necessaire de sbx.db — alice est liee a la personne
// « alice », membre de la communaute « Chorale ». bob n'est lie a personne.
func fausseSbx(t *testing.T) *sql.DB {
	t.Helper()
	chemin := filepath.Join(t.TempDir(), "sbx.db")
	db, err := sql.Open("sqlite", chemin)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	for _, q := range []string{
		`CREATE TABLE sbx_users (user_uuid TEXT PRIMARY KEY, pseudo TEXT, status TEXT)`,
		`CREATE TABLE sbx_app_links (user_uuid TEXT, app TEXT, app_id TEXT, app_handle TEXT)`,
		`CREATE TABLE sbx_communities (community_uuid TEXT PRIMARY KEY, name TEXT, archived_at INTEGER)`,
		`CREATE TABLE sbx_community_members (community_uuid TEXT, user_uuid TEXT, role TEXT)`,
		`INSERT INTO sbx_users VALUES ('u-alice','alice','active')`,
		`INSERT INTO sbx_app_links VALUES ('u-alice','bbs','Alice','Alice')`,
		`INSERT INTO sbx_communities VALUES ('k-chorale','Chorale',NULL)`,
		`INSERT INTO sbx_community_members VALUES ('k-chorale','u-alice','member')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	ancien := SbxDB
	SbxDB = chemin
	t.Cleanup(func() { SbxDB = ancien })
	return db
}

func TestUneCommunauteOuvreLeSalonASesMembres(t *testing.T) {
	s, sysop, alice, bob, prive, _ := magasinSalons(t)
	sbxdb := fausseSbx(t)
	if ok, _ := s.PeutVoirSalon(prive, alice, false); ok {
		t.Fatal("avant rattachement, alice ne doit pas voir le salon prive")
	}
	if err := s.OuvreACommunaute(prive, Communaute{UUID: "k-chorale", Nom: "Chorale"}, sysop); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.PeutVoirSalon(prive, alice, false); !ok {
		t.Fatal("membre de la communaute : alice doit voir le salon")
	}
	if ok, _ := s.PeutVoirSalon(prive, bob, false); ok {
		t.Fatal("bob n'est ni convie ni membre : le salon doit rester cache")
	}
	caches, err := s.SalonsCachesPour(alice, false)
	if err != nil || caches[prive] {
		t.Fatalf("la liste d'exclusion d'alice ne doit plus contenir le salon (%v, %v)", caches, err)
	}
	if caches, _ := s.SalonsCachesPour(bob, false); !caches[prive] {
		t.Fatal("pour bob, le salon reste dans la liste d'exclusion")
	}
	// Communaute archivee : l'acces tombe.
	sbxdb.Exec(`UPDATE sbx_communities SET archived_at = 1`)
	if ok, _ := s.PeutVoirSalon(prive, alice, false); ok {
		t.Fatal("communaute archivee : plus d'acces")
	}
	sbxdb.Exec(`UPDATE sbx_communities SET archived_at = NULL`)
	// Personne suspendue : l'acces tombe.
	sbxdb.Exec(`UPDATE sbx_users SET status = 'suspended'`)
	if ok, _ := s.PeutVoirSalon(prive, alice, false); ok {
		t.Fatal("personne suspendue : plus d'acces")
	}
	sbxdb.Exec(`UPDATE sbx_users SET status = 'active'`)
	// Refermer a la communaute.
	if err := s.FermeACommunaute(prive, "k-chorale"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.PeutVoirSalon(prive, alice, false); ok {
		t.Fatal("salon referme a la communaute : alice ne le voit plus")
	}
}

func TestSansSbxDbSeulsLesMembresNommesEntrent(t *testing.T) {
	s, sysop, alice, _, prive, _ := magasinSalons(t)
	ancien := SbxDB
	SbxDB = filepath.Join(t.TempDir(), "absente.db")
	t.Cleanup(func() { SbxDB = ancien })
	s.OuvreACommunaute(prive, Communaute{UUID: "k-chorale", Nom: "Chorale"}, sysop)
	if ok, _ := s.PeutVoirSalon(prive, alice, false); ok {
		t.Fatal("sbx.db illisible : on cache trop, jamais trop peu")
	}
	if err := s.AjouteMembre(prive, alice, sysop); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.PeutVoirSalon(prive, alice, false); !ok {
		t.Fatal("le membre convie nommement garde son acces")
	}
	if cs, _ := s.CommunautesDuSalon(prive); len(cs) != 1 || cs[0].Nom != "Chorale" {
		t.Fatalf("la console garde le nom de la communaute rattachee : %v", cs)
	}
}
