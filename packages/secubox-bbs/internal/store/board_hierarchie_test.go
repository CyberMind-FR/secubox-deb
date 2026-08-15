// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
package store

import "testing"

func TestUnSousSalonSeRangeSousSonParent(t *testing.T) {
	out := ordonneHierarchie([]Category{
		{ID: 1, Title: "Technique"},
		{ID: 2, Title: "Cuisine"},
		{ID: 3, Title: "Réseau", ParentID: 1},
	})
	if len(out) != 3 {
		t.Fatalf("perdu en chemin : %d", len(out))
	}
	if out[0].ID != 1 || out[1].ID != 3 || out[2].ID != 2 {
		t.Errorf("ordre : %d %d %d", out[0].ID, out[1].ID, out[2].ID)
	}
	if out[1].Profondeur != 1 {
		t.Errorf("profondeur du sous-salon = %d", out[1].Profondeur)
	}
}

func TestUnEnfantDontLeParentEstCacheRemonteALaRacine(t *testing.T) {
	// Le parent prive a ete filtre en amont. Rattacher l'enfant afficherait le
	// titre du parent — donc son existence — a qui n'y a pas acces.
	out := ordonneHierarchie([]Category{
		{ID: 3, Title: "Réseau", ParentID: 99},
	})
	if len(out) != 1 || out[0].Profondeur != 0 {
		t.Errorf("orphelin mal place : %+v", out)
	}
}

func TestUnCycleNeFaitPasTournerLaFonctionSansFin(t *testing.T) {
	// « Ne devrait pas exister » n'est pas une garantie.
	out := ordonneHierarchie([]Category{
		{ID: 1, ParentID: 2},
		{ID: 2, ParentID: 1},
	})
	if len(out) == 0 {
		t.Error("un cycle a tout fait disparaitre")
	}
}
