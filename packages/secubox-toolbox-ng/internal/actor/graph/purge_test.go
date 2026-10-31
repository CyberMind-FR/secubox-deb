// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package graph

import (
	"fmt"
	"testing"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/similarity"
)

// #3320 : seule la base etait purgee ; le graphe, lui, grossissait sans fin.
func TestPurger_RetireLesActeursAnciensEtLeursCles(t *testing.T) {
	g := New(DefaultThreshold)
	vieux := g.Observe(Obs{Sig: similarity.Signature{IP: "1.1.1.1", PathSig: "a"}, Target: "x", Timestamp: 100})
	recent := g.Observe(Obs{Sig: similarity.Signature{IP: "2.2.2.2", PathSig: "b"}, Target: "y", Timestamp: 5000})
	retires := g.Purger(1000)
	if len(retires) != 1 || retires[0] != vieux.ID {
		t.Fatalf("retires = %v, attendu [%s]", retires, vieux.ID)
	}
	if _, ok := g.Get(vieux.ID); ok || g.Len() != 1 {
		t.Fatalf("l'acteur ancien doit avoir disparu (len=%d)", g.Len())
	}
	for k, ens := range g.idx {
		if ens[vieux.ID] {
			t.Fatalf("cle %s mene encore a l'acteur purge", k)
		}
		if len(ens) == 0 {
			t.Fatalf("ensemble vide laisse dans l'index : %s", k)
		}
	}
	if _, ok := g.Get(recent.ID); !ok {
		t.Fatal("l'acteur recent doit rester")
	}
	// l'adresse purgee recree un acteur neuf, sans rattachement fantome
	n := g.Observe(Obs{Sig: similarity.Signature{IP: "1.1.1.1", PathSig: "a"}, Target: "x", Timestamp: 6000})
	if n.ID == vieux.ID || n.Events != 1 {
		t.Fatalf("rattachement a un acteur purge : %s events=%d", n.ID, n.Events)
	}
}

// #3320 : la consolidation ne revisite que les acteurs modifies ; le resultat
// reste celui d'une passe complete.
func TestConsolider_IncrementaleMemeResultat(t *testing.T) {
	g := New(DefaultThreshold)
	inex := map[string]bool{}
	for i := 0; i < 50; i++ {
		g.Observe(Obs{Sig: similarity.Signature{IP: fmt.Sprintf("10.0.%d.1", i), PathSig: fmt.Sprintf("p%d", i)}, Timestamp: int64(i + 1)})
	}
	if n := g.Consolider(inex); n != 0 {
		t.Fatalf("aucune fusion attendue, %d", n)
	}
	if len(g.modifies) != 0 {
		t.Fatalf("les modifies doivent etre remis a zero apres une passe (%d)", len(g.modifies))
	}
	// deux profils separes visent ensuite les deux memes hotes inexistants
	for _, h := range []string{"qq.x", "tinkoff.x"} {
		inex[h] = true
		g.Observe(Obs{Sig: similarity.Signature{IP: "9.9.9.1", PathSig: "z1"}, Target: h, Tags: []string{EtiquetteInexistant}, Timestamp: 100})
	}
	a := g.Observe(Obs{Sig: similarity.Signature{IP: "9.9.9.2", PathSig: "z2", UAFamily: "u2"}, Target: "qq.x", Timestamp: 101})
	_ = a
	g.Observe(Obs{Sig: similarity.Signature{IP: "9.9.9.2", PathSig: "z2", UAFamily: "u2"}, Target: "tinkoff.x", Timestamp: 102})
	avant := g.Len()
	if n := g.Consolider(inex); n < 1 || g.Len() != avant-n {
		t.Fatalf("fusion par dictionnaire attendue : n=%d len %d -> %d", n, avant, g.Len())
	}
}

// Un hote qui DEVIENT inexistant apres coup doit permettre de reunir deux
// acteurs qui n'ont plus bouge depuis.
func TestConsolider_NouvelInexistantRevisiteLesActeursConcernes(t *testing.T) {
	g := New(DefaultThreshold)
	for _, h := range []string{"a.x", "b.x"} {
		g.Observe(Obs{Sig: similarity.Signature{IP: "1.0.0.1", PathSig: "p1"}, Target: h, Timestamp: 1})
		g.Observe(Obs{Sig: similarity.Signature{IP: "1.0.0.2", PathSig: "p2", UAFamily: "u"}, Target: h, Timestamp: 2})
	}
	if n := g.Consolider(map[string]bool{}); n != 0 {
		t.Fatalf("hotes legitimes : pas de fusion (%d)", n)
	}
	if n := g.Consolider(map[string]bool{"a.x": true, "b.x": true}); n != 1 {
		t.Fatalf("les hotes devenus inexistants doivent reunir les deux acteurs (%d)", n)
	}
}

// Relecture #3321 : inexVus suit l'ensemble courant ; un hote retire puis remis
// redevient « nouveau » et fait revisiter les acteurs qui l'ont vise.
func TestConsolider_InexVusSuitLEnsembleCourant(t *testing.T) {
	g := New(DefaultThreshold)
	g.Consolider(map[string]bool{"a.x": true})
	g.Consolider(map[string]bool{})
	if g.inexVus["a.x"] {
		t.Fatal("un hote qui n'est plus inexistant doit sortir de inexVus")
	}
}
