// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package store

import "testing"

// #1608 — les listes de fils ecartent les salons qu'un lecteur ne voit pas DANS
// la requete, pour que la borne s'applique a ce qui est montre.

func TestRecentHorsEcarteLesSalonsExclusAvantLaBorne(t *testing.T) {
	s, sysop, _, bob, prive, ouvert := magasinSalons(t)
	if _, err := s.NewThread(ouvert, sysop, "Sur la place", "x", VisPublic); err != nil {
		t.Fatal(err)
	}
	// Plus de fils recents dans le salon exclu que la borne demandee.
	for i := 0; i < 5; i++ {
		if _, err := s.NewThread(prive, sysop, "Au bureau", "x", VisLocal); err != nil {
			t.Fatal(err)
		}
	}
	caches, err := s.SalonsCachesPour(bob, false)
	if err != nil {
		t.Fatal(err)
	}
	fils, err := s.RecentHors(3, false, caches)
	if err != nil {
		t.Fatal(err)
	}
	if len(fils) != 1 || fils[0].Title != "Sur la place" {
		t.Fatalf("fils rendus : %+v", fils)
	}
	// Sans exclusion, la liste d'administration voit tout, borne comprise.
	tous, _ := s.RecentHors(3, false, nil)
	if len(tous) != 3 {
		t.Errorf("sans exclusion : %d fils", len(tous))
	}
}

func TestFilsNonLusHorsNeCompteQueLesSalonsVus(t *testing.T) {
	s, sysop, _, bob, prive, ouvert := magasinSalons(t)
	vu, _ := s.NewThread(ouvert, sysop, "Sur la place", "x", VisPublic)
	cache, _ := s.NewThread(prive, sysop, "Au bureau", "x", VisLocal)
	nl, err := s.FilsNonLusHors(bob, map[int64]bool{prive: true})
	if err != nil {
		t.Fatal(err)
	}
	if !nl[vu] || nl[cache] {
		t.Errorf("non-lus : %v", nl)
	}
	// La forme sans exclusion reste celle d'avant.
	if nl, _ := s.FilsNonLus(bob); !nl[vu] || !nl[cache] {
		t.Errorf("non-lus sans exclusion : %v", nl)
	}
}

func TestClauseHorsSalonsVideSansExclusion(t *testing.T) {
	if q, args := clauseHorsSalons("t", nil); q != "" || args != nil {
		t.Errorf("clause %q %v", q, args)
	}
	if q, args := clauseHorsSalons("t", map[int64]bool{3: true, 1: true, 2: false}); q != " AND t.category_id NOT IN (?,?)" || len(args) != 2 || args[0] != int64(1) || args[1] != int64(3) {
		t.Errorf("clause %q %v", q, args)
	}
}
