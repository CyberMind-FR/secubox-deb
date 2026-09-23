// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

package mfcc

import (
	"math"
	"math/rand"
	"testing"
)

const fe = 48000.0

func TestLEchelleMelEstReversible(t *testing.T) {
	for _, hz := range []float64{0, 100, 440, 1000, 4000, 16000} {
		if r := EnHertz(EnMel(hz)); math.Abs(r-hz) > 1e-6 {
			t.Errorf("%g Hz -> mel -> %g Hz", hz, r)
		}
	}
}

// AUCUN FILTRE VIDE, et ce n'est pas de la coquetterie : un filtre sans poids
// rendrait un coefficient constant, qu'aucun classifieur ne pourrait
// distinguer d'un silence dans cette bande.
func TestAucunFiltreNEstVide(t *testing.T) {
	b := NouveauBanc(26, 1025, fe, 50, 8000)
	for f := 0; f < b.Nombre(); f++ {
		somme := 0.0
		for _, w := range b.filtres[f] {
			somme += w
		}
		if somme <= 0 {
			t.Errorf("filtre %d sans poids (début %d)", f, b.debuts[f])
		}
	}
}

// Un banc trop fin pour la résolution disponible est le cas qui produit des
// filtres vides : on le pousse exprès.
func TestUnBancTropFinNeCasseRien(t *testing.T) {
	b := NouveauBanc(40, 129, fe, 50, 8000) // 129 raies seulement
	e := b.Energies(make([]float64, 129), nil)
	if len(e) != 40 {
		t.Fatalf("%d énergies, veut 40", len(e))
	}
	for i, v := range e {
		if math.IsNaN(v) || math.IsInf(v, 0) {
			t.Fatalf("bande %d = %v", i, v)
		}
	}
}

func TestLeCentreDeGraviteSuitLEnergie(t *testing.T) {
	n := 1025
	grave := make([]float64, n)
	aigu := make([]float64, n)
	grave[20] = 1 // ~470 Hz
	aigu[400] = 1 // ~9400 Hz
	cg, ca := CentreDeGravite(grave, fe), CentreDeGravite(aigu, fe)
	if !(cg < ca) {
		t.Fatalf("centre de gravité grave %.0f Hz >= aigu %.0f Hz", cg, ca)
	}
	if math.Abs(cg-20*fe/float64(2*(n-1))) > 1 {
		t.Errorf("centre de gravité %.1f Hz pour une raie unique à %.1f", cg, 20*fe/float64(2*(n-1)))
	}
}

// La platitude est LE discriminant souffle / voyelle : elle doit nettement
// séparer un bruit blanc d'un spectre harmonique.
func TestLaPlatitudeSepareLeBruitDuSonHarmonique(t *testing.T) {
	n := 512
	rng := rand.New(rand.NewSource(7))
	bruit := make([]float64, n)
	for i := range bruit {
		v := rng.Float64()
		bruit[i] = v * v
	}
	harmonique := make([]float64, n)
	for h := 1; h*10 < n; h++ {
		harmonique[h*10] = 1 / float64(h)
	}
	pb, ph := PlatitudeSpectrale(bruit), PlatitudeSpectrale(harmonique)
	if pb < 0.2 {
		t.Errorf("bruit : platitude %.3f, attendue élevée", pb)
	}
	if ph > 0.05 {
		t.Errorf("harmonique : platitude %.3f, attendue basse", ph)
	}
	if !(ph < pb) {
		t.Fatalf("platitude harmonique %.3f >= bruit %.3f", ph, pb)
	}
}

func TestLaPenteSpectraleADeLaPenteDansLeBonSens(t *testing.T) {
	n := 513
	descendant := make([]float64, n)
	montant := make([]float64, n)
	for k := 0; k < n; k++ {
		descendant[k] = math.Pow(10, -float64(k)/float64(n)) // décroît
		montant[k] = math.Pow(10, float64(k)/float64(n))     // croît
	}
	if p := PenteSpectrale(descendant, fe); p >= 0 {
		t.Errorf("spectre descendant : pente %.2f dB/kHz, veut < 0", p)
	}
	if p := PenteSpectrale(montant, fe); p <= 0 {
		t.Errorf("spectre montant : pente %.2f dB/kHz, veut > 0", p)
	}
}

func TestLaDCTDecorreleUnSignalConstant(t *testing.T) {
	// Un vecteur constant ne porte QUE de l'énergie moyenne : tout doit se
	// retrouver dans c0, et les coefficients suivants être nuls.
	e := make([]float64, 26)
	for i := range e {
		e[i] = 3.5
	}
	c := DCT2(e, nil, 13)
	if math.Abs(c[0]-3.5*math.Sqrt(26)) > 1e-9 {
		t.Errorf("c0 = %g", c[0])
	}
	for k := 1; k < len(c); k++ {
		if math.Abs(c[k]) > 1e-9 {
			t.Errorf("c%d = %g, veut 0", k, c[k])
		}
	}
}

func TestLeSilenceNeProduitPasDInfini(t *testing.T) {
	b := NouveauBanc(26, 1025, fe, 50, 8000)
	e := b.Energies(make([]float64, 1025), nil)
	c := DCT2(e, nil, 13)
	for i, v := range append(append([]float64{}, e...), c...) {
		if math.IsNaN(v) || math.IsInf(v, 0) {
			t.Fatalf("valeur %d = %v sur le silence", i, v)
		}
	}
	if p := PlatitudeSpectrale(make([]float64, 512)); math.IsNaN(p) {
		t.Fatal("platitude NaN sur le silence")
	}
}
