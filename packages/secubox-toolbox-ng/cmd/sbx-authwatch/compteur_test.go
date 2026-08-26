// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"testing"
	"time"
)

func TestSeuilAtteintDeclencheUneSeuleFois(t *testing.T) {
	c := NewCompteur(10*time.Minute, 4, 30*time.Minute)
	t0 := time.Unix(1_700_000_000, 0)
	for i := 0; i < 3; i++ {
		if _, bannir := c.Ajoute("1.2.3.4", 1, t0.Add(time.Duration(i)*time.Second)); bannir {
			t.Fatalf("bannissement premature au coup %d", i+1)
		}
	}
	if _, bannir := c.Ajoute("1.2.3.4", 1, t0.Add(4*time.Second)); !bannir {
		t.Fatal("le seuil de 4 aurait du declencher")
	}
	// Le repit evite la tempete : chaque nouvel echec ne doit pas re-bannir.
	for i := 0; i < 5; i++ {
		if _, bannir := c.Ajoute("1.2.3.4", 2, t0.Add(time.Duration(10+i)*time.Second)); bannir {
			t.Fatal("re-declenchement pendant le repit")
		}
	}
}

// La fenetre doit GLISSER : sinon un attaquant a cheval sur deux tranches
// fixes passe indefiniment sous le seuil.
func TestFenetreGlisse(t *testing.T) {
	c := NewCompteur(time.Minute, 3, time.Hour)
	t0 := time.Unix(1_700_000_000, 0)
	c.Ajoute("5.6.7.8", 1, t0)
	c.Ajoute("5.6.7.8", 1, t0.Add(10*time.Second))
	// Deux minutes plus tard, les deux premiers sont sortis de la fenetre.
	total, bannir := c.Ajoute("5.6.7.8", 1, t0.Add(2*time.Minute))
	if bannir {
		t.Fatal("des evenements hors fenetre ne doivent pas compter")
	}
	if total != 1 {
		t.Fatalf("total %d, attendu 1 (seul l'evenement courant reste)", total)
	}
}

func TestAdressesIndependantes(t *testing.T) {
	c := NewCompteur(10*time.Minute, 3, time.Hour)
	t0 := time.Unix(1_700_000_000, 0)
	for i := 0; i < 2; i++ {
		c.Ajoute("1.1.1.1", 1, t0)
		c.Ajoute("2.2.2.2", 1, t0)
	}
	if _, bannir := c.Ajoute("1.1.1.1", 1, t0); !bannir {
		t.Fatal("1.1.1.1 aurait du atteindre le seuil")
	}
	if _, bannir := c.Ajoute("2.2.2.2", 0, t0); bannir {
		t.Fatal("2.2.2.2 ne doit pas etre affectee par le compteur d'une autre")
	}
}

// Un signal fort atteint le seuil plus vite : la patience est proportionnee au
// doute qu'on a sur l'intention.
func TestSignalFortAtteintLeSeuilPlusVite(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	fort := NewCompteur(10*time.Minute, 4, time.Hour)
	faible := NewCompteur(10*time.Minute, 4, time.Hour)
	coupsFort, coupsFaible := 0, 0
	for i := 0; i < 10; i++ {
		coupsFort++
		if _, b := fort.Ajoute("1.2.3.4", Poids("high"), t0); b {
			break
		}
	}
	for i := 0; i < 10; i++ {
		coupsFaible++
		if _, b := faible.Ajoute("1.2.3.4", Poids("medium"), t0); b {
			break
		}
	}
	if coupsFort >= coupsFaible {
		t.Fatalf("fort a pris %d coups, faible %d — le fort devrait etre plus rapide", coupsFort, coupsFaible)
	}
}

func TestElagageLibereLesAdressesInactives(t *testing.T) {
	c := NewCompteur(time.Minute, 10, time.Minute)
	t0 := time.Unix(1_700_000_000, 0)
	for i := 0; i < 50; i++ {
		c.Ajoute(randIP(i), 1, t0)
	}
	if c.Suivies() != 50 {
		t.Fatalf("50 adresses attendues, %d suivies", c.Suivies())
	}
	c.Elague(t0.Add(2 * time.Minute))
	if c.Suivies() != 0 {
		t.Fatalf("apres elagage, %d adresses restent en memoire", c.Suivies())
	}
}

func randIP(i int) string {
	return "203.0.113." + string(rune('0'+i%10)) + string(rune('0'+(i/10)%10))
}
