// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package store

import (
	"path/filepath"
	"testing"
)

// #3709 — changer le role d'un compte, avec ses gardes.

func roleDe(t *testing.T, s *Store, id int64) string {
	t.Helper()
	var r string
	if err := s.db.QueryRow(`SELECT role FROM users WHERE id = ?`, id).Scan(&r); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestChangerRole(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "bbs.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	sysop, _ := s.CreateUser("gk2", "Gandalf", RoleSysop)
	alice, _ := s.CreateUser("alice", "Alice", RoleMember)
	bob, _ := s.CreateUser("bob", "Bob", RoleMember)

	// dernier sysop : refuse
	if err := s.ChangerRole(sysop, RoleMember); err == nil {
		t.Fatal("le dernier sysop ne doit pas etre retrograde")
	}
	// role inconnu : refuse
	if err := s.ChangerRole(alice, Role("root")); err == nil {
		t.Fatal("role inconnu accepte")
	}
	// promotion
	if err := s.ChangerRole(alice, RoleSysop); err != nil {
		t.Fatal(err)
	}
	if roleDe(t, s, alice) != "sysop" {
		t.Fatal("promotion non appliquee")
	}
	var n int
	s.db.QueryRow(`SELECT COUNT(*) FROM audit WHERE action = 'user.role'`).Scan(&n)
	if n != 1 {
		t.Fatalf("audit attendu 1 ligne, %d", n)
	}
	// retrogradation, un autre sysop restant
	if err := s.ChangerRole(sysop, RoleGuest); err != nil {
		t.Fatal(err)
	}
	if roleDe(t, s, sysop) != "guest" {
		t.Fatal("retrogradation non appliquee")
	}
	// compte desactive : refuse
	if err := s.DisableUser(bob); err != nil {
		t.Fatal(err)
	}
	if err := s.ChangerRole(bob, RoleSysop); err == nil {
		t.Fatal("compte desactive promu")
	}
	if roleDe(t, s, bob) != "member" {
		t.Fatal("role modifie malgre le refus")
	}
}
