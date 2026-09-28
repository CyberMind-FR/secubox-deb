// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

package pitch

import (
	"math"
	"math/rand"
	"testing"
)

// EN-DESSOUS D'UN MINIMUM, ON NE REND RIEN. Un indice calculé sur trois
// mesures ressemble à un indice — c'est exactement ce qui le rend dangereux.
func TestPasAssezDeTramesDoncPasDeChiffre(t *testing.T) {
	p := NouvellePerturbation(50)
	for i := 0; i < MinimumTrames-1; i++ {
		p.Ajoute(300+float64(i), 0.5)
	}
	if p.Assez() {
		t.Fatal("Assez() vrai en-dessous du minimum")
	}
	if p.Jitter() != 0 || p.Shimmer() != 0 || p.EtendueF0(fe) != 0 {
		t.Fatal("des chiffres sont rendus alors qu'on n'a pas de quoi")
	}
}

func TestUneVoixParfaitementRegulliereNAAucunJitter(t *testing.T) {
	p := NouvellePerturbation(50)
	for i := 0; i < 40; i++ {
		p.Ajoute(327.0, 0.42)
	}
	if j := p.Jitter(); j > 1e-9 {
		t.Errorf("jitter %.6f %% sur une période constante", j)
	}
	if s := p.Shimmer(); s > 1e-9 {
		t.Errorf("shimmer %.6f dB sur une amplitude constante", s)
	}
}

func TestUneVoixIrregulliereEnAPlusQuUneVoixStable(t *testing.T) {
	rng := rand.New(rand.NewSource(11))
	mesure := func(bruit float64) (float64, float64) {
		p := NouvellePerturbation(60)
		for i := 0; i < 60; i++ {
			p.Ajoute(327*(1+rng.NormFloat64()*bruit), 0.42*(1+rng.NormFloat64()*bruit))
		}
		return p.Jitter(), p.Shimmer()
	}
	js, ss := mesure(0.002)
	ji, si := mesure(0.05)
	if !(ji > js) {
		t.Errorf("jitter : irrégulier %.3f <= stable %.3f", ji, js)
	}
	if !(si > ss) {
		t.Errorf("shimmer : irrégulier %.3f <= stable %.3f", si, ss)
	}
}

// LE SHIMMER EN dB NE DOIT PAS DÉPENDRE DU GAIN DU MICRO : doubler le niveau
// d'enregistrement ne rend pas la voix plus irrégulière.
func TestLeShimmerEstIndependantDuGain(t *testing.T) {
	rng := rand.New(rand.NewSource(12))
	suite := make([]float64, 60)
	for i := range suite {
		suite[i] = 0.3 * (1 + rng.NormFloat64()*0.05)
	}
	mesure := func(gain float64) float64 {
		p := NouvellePerturbation(60)
		for i, a := range suite {
			p.Ajoute(327+float64(i%3), a*gain)
		}
		return p.Shimmer()
	}
	un, dix := mesure(1), mesure(10)
	if math.Abs(un-dix) > 1e-9 {
		t.Fatalf("shimmer %.6f dB à gain 1, %.6f dB à gain 10", un, dix)
	}
}

// UN SILENCE NE CRÉE PAS D'IRRÉGULARITÉ. Une trame non voisée n'entre pas dans
// la fenêtre : sinon le trou entre deux mots fabriquerait un écart de période
// gigantesque et purement fictif.
func TestUneTrameNonVoiseeNEntrePas(t *testing.T) {
	p := NouvellePerturbation(50)
	for i := 0; i < 30; i++ {
		p.Ajoute(327, 0.4)
	}
	avant := p.Jitter()
	p.Ajoute(0, 0.4) // période nulle : non voisé
	p.Ajoute(327, 0) // amplitude nulle : silence
	if apres := p.Jitter(); apres != avant {
		t.Fatalf("le jitter a bougé (%.6f -> %.6f) sur des trames non voisées", avant, apres)
	}
}

func TestEtendueF0EnDemiTons(t *testing.T) {
	p := NouvellePerturbation(60)
	// Une octave d'écart régulier : l'étendue doit se compter en demi-tons,
	// pas en hertz — c'est ainsi que la hauteur se perçoit.
	for i := 0; i < 30; i++ {
		p.Ajoute(fe/200, 0.4) // 200 Hz
		p.Ajoute(fe/400, 0.4) // 400 Hz
	}
	e := p.EtendueF0(fe)
	if e < 5 || e > 7 {
		t.Fatalf("étendue %.2f demi-tons pour une alternance d'une octave (attendu ~6)", e)
	}
}

func TestLaMedianeResisteAUnSautDOctave(t *testing.T) {
	p := NouvellePerturbation(60)
	for i := 0; i < 30; i++ {
		p.Ajoute(fe/200, 0.4)
	}
	p.Ajoute(fe/100, 0.4) // une trame à l'octave, comme une erreur de YIN
	if m := p.MedianeF0(fe); math.Abs(m-200) > 1 {
		t.Fatalf("médiane %.1f Hz tirée par une seule trame fausse", m)
	}
}

func TestLaFenetreGlisse(t *testing.T) {
	p := NouvellePerturbation(20)
	for i := 0; i < 100; i++ {
		p.Ajoute(327, 0.4)
	}
	if len(p.periodes) != 20 {
		t.Fatalf("%d trames gardées, veut 20", len(p.periodes))
	}
}
