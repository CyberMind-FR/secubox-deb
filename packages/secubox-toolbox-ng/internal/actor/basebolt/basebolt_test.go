// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package basebolt

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"go.etcd.io/bbolt"
)

var seau = []byte("s")

// listeSurDisque lit la meta courante du fichier : vrai si la liste des pages
// libres y est écrite (sinon bbolt parcourt toute la base à l'ouverture).
func listeSurDisque(t *testing.T, chemin string) bool {
	t.Helper()
	b, err := os.ReadFile(chemin)
	if err != nil {
		t.Fatal(err)
	}
	page := int(binary.LittleEndian.Uint32(b[16+8:])) // pageSize, dans la meta de la page 0
	var tx, libre uint64
	for _, p := range []int{0, page} {
		m := b[p+16:]
		if id := binary.LittleEndian.Uint64(m[48:]); id >= tx {
			tx, libre = id, binary.LittleEndian.Uint64(m[32:])
		}
	}
	return libre != ^uint64(0)
}

func remplir(t *testing.T, db *bbolt.DB, de, a int) {
	t.Helper()
	if err := db.Update(func(tx *bbolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(seau)
		for i := de; i < a && err == nil; i++ {
			err = b.Put([]byte(fmt.Sprintf("%08d", i)), make([]byte, 200))
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestListeEcriteAuSeulArretPropre(t *testing.T) {
	chemin := filepath.Join(t.TempDir(), "x.db")
	db, err := bbolt.Open(chemin, 0o600, Options())
	if err != nil {
		t.Fatal(err)
	}
	remplir(t, db, 0, 5000)
	if err := db.Update(func(tx *bbolt.Tx) error { // des pages libres
		for i := 0; i < 3000; i++ {
			if err := tx.Bucket(seau).Delete([]byte(fmt.Sprintf("%08d", i))); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if listeSurDisque(t, chemin) {
		t.Fatal("#3320 : la liste ne doit pas être écrite à chaque transaction")
	}
	if err := Fermer(db); err != nil {
		t.Fatal(err)
	}
	if !listeSurDisque(t, chemin) {
		t.Fatal("arrêt propre : la liste des pages libres doit être sur disque")
	}

	// Réouverture : contenu intact, pages libres connues, base cohérente ; la
	// première écriture retire la liste (les suivantes ne la réécrivent pas).
	db, err = bbolt.Open(chemin, 0o600, Options())
	if err != nil {
		t.Fatal(err)
	}
	if db.Stats().FreePageN == 0 {
		t.Error("pages libres perdues")
	}
	remplir(t, db, 10000, 10010)
	if listeSurDisque(t, chemin) {
		t.Error("liste réécrite par une transaction ordinaire")
	}
	if err := db.View(func(tx *bbolt.Tx) error {
		if n := tx.Bucket(seau).Stats().KeyN; n != 2010 {
			t.Errorf("%d clés, attendu 2010", n)
		}
		for e := range tx.Check() {
			t.Errorf("incohérence : %v", e)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := Fermer(db); err != nil {
		t.Fatal(err)
	}
	if err := Fermer(db); err != nil {
		t.Errorf("seconde fermeture : %v", err)
	}
}

// TestArretBrutal : sans Fermer (processus tué), la base se rouvre comme avant.
func TestArretBrutal(t *testing.T) {
	chemin := filepath.Join(t.TempDir(), "x.db")
	db, err := bbolt.Open(chemin, 0o600, Options())
	if err != nil {
		t.Fatal(err)
	}
	remplir(t, db, 0, 500)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if listeSurDisque(t, chemin) {
		t.Fatal("précondition")
	}
	db, err = bbolt.Open(chemin, 0o600, Options())
	if err != nil {
		t.Fatal(err)
	}
	defer Fermer(db)
	_ = db.View(func(tx *bbolt.Tx) error {
		if n := tx.Bucket(seau).Stats().KeyN; n != 500 {
			t.Errorf("%d clés", n)
		}
		return nil
	})
}
