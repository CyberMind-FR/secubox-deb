// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

package audio

import (
	"errors"
	"math"
	"sync"
	"testing"
	"time"
)

// LA PLEINE ÉCHELLE NÉGATIVE EST -32768, PAS -32767. Diviser par 32767
// laisserait sortir -1,00003 : assez pour déborder un affichage borné, et faux.
func TestConversionS16(t *testing.T) {
	cas := []struct {
		octets []byte
		veut   float64
	}{
		{[]byte{0x00, 0x00}, 0},
		{[]byte{0xFF, 0x7F}, 32767.0 / 32768},
		{[]byte{0x00, 0x80}, -1},
		{[]byte{0x00, 0x40}, 0.5},
	}
	dst := make([]float64, 1)
	for _, c := range cas {
		VersFlottants(c.octets, dst)
		if math.Abs(dst[0]-c.veut) > 1e-9 {
			t.Errorf("%v -> %.6f, veut %.6f", c.octets, dst[0], c.veut)
		}
		if dst[0] < -1 || dst[0] > 1 {
			t.Errorf("%v sort de [-1,1] : %.6f", c.octets, dst[0])
		}
	}
}

func TestConversionNeDebordePasLaDestination(t *testing.T) {
	dst := make([]float64, 2)
	if n := VersFlottants(make([]byte, 100), dst); n != 2 {
		t.Fatalf("%d échantillons écrits dans une destination de 2", n)
	}
}

// ── L'ANNEAU ───────────────────────────────────────────────────────────────

func TestLAnneauNeRendRienAvantDEtrePlein(t *testing.T) {
	a := NouvelAnneau(8, 4)
	var trames int
	a.Ecris(make([]float64, 7), func([]float64) { trames++ })
	if trames != 0 {
		t.Fatalf("%d trame(s) rendue(s) avant d'avoir vu une fenêtre entière", trames)
	}
	if a.Pret() {
		t.Error("Pret() vrai alors que l'anneau n'est pas rempli")
	}
}

func TestLAnneauRendDesTramesQuiSeChevauchent(t *testing.T) {
	a := NouvelAnneau(8, 4)
	var vues [][]float64
	x := make([]float64, 24)
	for i := range x {
		x[i] = float64(i)
	}
	a.Ecris(x, func(tr []float64) {
		vues = append(vues, append([]float64(nil), tr...))
	})
	if len(vues) < 3 {
		t.Fatalf("%d trames, attendu au moins 3", len(vues))
	}
	// La première trame complète finit sur l'échantillon 7.
	if vues[0][7] != 7 {
		t.Errorf("première trame : dernier échantillon %v, veut 7", vues[0][7])
	}
	// La suivante avance d'exactement un pas.
	if vues[1][7] != 11 {
		t.Errorf("deuxième trame : dernier échantillon %v, veut 11", vues[1][7])
	}
	// Et la moitié du contenu est partagée : c'est tout l'intérêt.
	if vues[1][0] != 4 {
		t.Errorf("deuxième trame : premier échantillon %v, veut 4", vues[1][0])
	}
}

func TestUnPasImpossibleEstRefuse(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("un pas plus grand que la trame doit échouer bruyamment")
		}
	}()
	NouvelAnneau(8, 16)
}

// ── LA SOURCE ABSENTE ──────────────────────────────────────────────────────
// Elle ne rend PAS de zéros. Des zéros se lisent comme du silence et
// donneraient un cockpit parfaitement crédible sur une machine sourde.

func TestLaSourceAbsenteNeRendPasDuSilence(t *testing.T) {
	a := NouvelleAbsente("pas de carte son")
	dst := make([]float64, 64)
	n, err := a.Lis(dst)
	if n != 0 {
		t.Errorf("%d échantillons rendus par une source absente", n)
	}
	if !errors.Is(err, ErrPasDEntree) {
		t.Errorf("erreur %v, veut ErrPasDEntree", err)
	}
	if d := a.Decrit(); d.Reelle {
		t.Error("une source absente se prétend réelle")
	}
}

// ── LE NAVIGATEUR ──────────────────────────────────────────────────────────

func TestLeNavigateurRendCeQuOnLuiAPousse(t *testing.T) {
	n := NouveauNavigateur("test", 48000)
	n.Pousse([]float64{1, 2, 3, 4})
	dst := make([]float64, 10)
	k, err := n.Lis(dst)
	if err != nil || k != 4 {
		t.Fatalf("lu %d, %v", k, err)
	}
	if dst[0] != 1 || dst[3] != 4 {
		t.Fatalf("contenu %v", dst[:4])
	}
}

// SUR UN FLUX TEMPS RÉEL, DU VIEUX SON N'A AUCUNE VALEUR. Si l'analyse prend
// du retard on jette les plus anciens, sinon la mémoire enfle jusqu'à ce que
// le noyau tranche à notre place.
func TestLeNavigateurJetteLePlusAncienEtLeCompte(t *testing.T) {
	n := NouveauNavigateur("test", 10)
	for i := 0; i < 5; i++ {
		bloc := make([]float64, 6)
		for j := range bloc {
			bloc[j] = float64(i*6 + j)
		}
		n.Pousse(bloc)
	}
	dst := make([]float64, 100)
	k, _ := n.Lis(dst)
	if k > 10 {
		t.Fatalf("%d échantillons gardés pour un plafond de 10", k)
	}
	if dst[0] != 20 { // 30 poussés, 10 gardés : on commence à 20
		t.Errorf("le plus RÉCENT doit être gardé : premier = %v, veut 20", dst[0])
	}
	if p := n.Perdus(); p != 20 {
		t.Errorf("%d échantillons perdus comptés, veut 20", p)
	}
}

// UNE FERMETURE DOIT RÉVEILLER LE LECTEUR, sinon la goroutine d'analyse reste
// à attendre un navigateur qui est parti — et la session fuit.
func TestLaFermetureReveilleLeLecteur(t *testing.T) {
	n := NouveauNavigateur("test", 48000)
	var wg sync.WaitGroup
	wg.Add(1)
	var err error
	go func() {
		defer wg.Done()
		_, err = n.Lis(make([]float64, 10))
	}()
	time.Sleep(20 * time.Millisecond)
	n.Ferme()
	fini := make(chan struct{})
	go func() { wg.Wait(); close(fini) }()
	select {
	case <-fini:
	case <-time.After(time.Second):
		t.Fatal("le lecteur n'a pas été réveillé : la goroutine fuit")
	}
	if !errors.Is(err, ErrPasDEntree) {
		t.Errorf("erreur %v après fermeture", err)
	}
}

func TestLeRetardEstMesureEtPasDevine(t *testing.T) {
	n := NouveauNavigateur("test", 48000)
	n.Pousse(make([]float64, Echantillonnage/10)) // 100 ms
	if d := n.Retard(); d < 95*time.Millisecond || d > 105*time.Millisecond {
		t.Fatalf("retard %v pour 100 ms en attente", d)
	}
}

// ── LA SYNTHÈSE ────────────────────────────────────────────────────────────

func TestLaSyntheseSeDeclareFabriquee(t *testing.T) {
	d := NouvelleSynthese(false).Decrit()
	if d.Reelle {
		t.Fatal("la synthèse se prétend réelle : une démonstration finirait par passer pour une mesure")
	}
	if d.Detail == "" {
		t.Error("rien n'avertit que la voix est fabriquée")
	}
}

func TestLaSyntheseAlterneParoleEtSilence(t *testing.T) {
	s := NouvelleSynthese(false)
	x := make([]float64, Echantillonnage*6) // un cycle entier
	s.Lis(x)
	energie := func(a []float64) float64 {
		var e float64
		for _, v := range a {
			e += v * v
		}
		return math.Sqrt(e / float64(len(a)))
	}
	parle := energie(x[:Echantillonnage*3])
	tait := energie(x[Echantillonnage*9/2:])
	if !(parle > tait*10) {
		t.Fatalf("parole %.5f vs silence %.5f : le cycle ne se voit pas", parle, tait)
	}
}
