// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

package vad

import (
	"math"
	"math/rand"
	"testing"
)

const pasTrame = 512.0 / 48000.0 // 10,7 ms

// nourris joue `secondes` d'une enveloppe donnée par `f`.
func nourris(e *Ecouteur, secondes float64, parole bool, f func(t float64) float64) {
	n := int(secondes / pasTrame)
	for i := 0; i < n; i++ {
		e.Observe(f(float64(i)*pasTrame), parole)
	}
}

// LE CAS QUI MOTIVE TOUT : de la musique dans la pièce. Elle est harmonique et
// périodique, c'est-à-dire exactement ce qu'on cherche quand on cherche une
// voix — le VAD la prend pour de la parole et YIN lui trouve une hauteur.
func TestUneMusiqueEstReconnueParSonTempo(t *testing.T) {
	e := NouvelEcouteur(pasTrame, 10)
	const bpm = 120.0
	nourris(e, 10, false, func(tt float64) float64 {
		// Battement net toutes les 0,5 s, plus un peu de souffle.
		p := math.Mod(tt, 60/bpm)
		return 0.05 + 0.25*math.Exp(-p*14)
	})
	a := e.Analyse()
	if !a.Presente {
		t.Fatalf("pulsation non détectée : %+v", a)
	}
	if math.Abs(a.BPM-bpm) > 8 {
		t.Errorf("tempo %.1f BPM, veut %.0f", a.BPM, bpm)
	}
	if a.Pulsation < SeuilPulsation {
		t.Errorf("netteté %.2f", a.Pulsation)
	}
}

// ET LE CAS SYMÉTRIQUE, qui est le plus important : une conversation NE DOIT
// PAS être prise pour de la musique. Son rythme syllabique est plus rapide et
// beaucoup moins régulier — si on la déclarait « ambiance », on écarterait
// précisément ce qu'on veut mesurer.
func TestUneConversationNEstPasPriseePourDeLaMusique(t *testing.T) {
	e := NouvelEcouteur(pasTrame, 10)
	rng := rand.New(rand.NewSource(3))
	nourris(e, 10, true, func(tt float64) float64 {
		// ~4 syllabes/s, avec de l'irrégularité — c'est ce qui distingue.
		base := 0.5 + 0.5*math.Sin(2*math.Pi*4*tt+rng.NormFloat64()*0.6)
		return 0.05 + 0.2*base*base*(0.7+0.6*rng.Float64())
	})
	if a := e.Analyse(); a.Dominante {
		t.Fatalf("une conversation déclarée ambiance dominante : %+v", a)
	}
}

func TestLeSilenceNeProduitAucuneAmbiance(t *testing.T) {
	e := NouvelEcouteur(pasTrame, 10)
	nourris(e, 10, false, func(float64) float64 { return 0 })
	if a := e.Analyse(); a.Presente || a.BPM != 0 {
		t.Fatalf("ambiance trouvée dans le silence : %+v", a)
	}
}

func TestUnBruitBlancNAPasDeTempo(t *testing.T) {
	e := NouvelEcouteur(pasTrame, 10)
	rng := rand.New(rand.NewSource(7))
	nourris(e, 10, false, func(float64) float64 { return 0.1 + rng.Float64()*0.02 })
	if a := e.Analyse(); a.Presente {
		t.Fatalf("tempo trouvé dans du bruit blanc : %+v", a)
	}
}

// UNE AMBIANCE DISCRÈTE EST UN CONTEXTE, PAS UNE GÊNE. Elle explique qu'une
// voix soit plus forte — on parle plus haut quand il y a du fond — et c'est
// une information utile. On ne doit pas écarter la fenêtre pour autant.
func TestUneAmbianceDiscreteNEcartePasLaFenetre(t *testing.T) {
	e := NouvelEcouteur(pasTrame, 12)
	const bpm = 100.0
	// Alternance : parole forte, fond musical faible.
	n := int(12 / pasTrame)
	for i := 0; i < n; i++ {
		tt := float64(i) * pasTrame
		p := math.Mod(tt, 60/bpm)
		fond := 0.01 + 0.02*math.Exp(-p*14)
		parle := math.Mod(tt, 2) < 1.4
		if parle {
			e.Observe(0.30, true)
		} else {
			e.Observe(fond, false)
		}
	}
	a := e.Analyse()
	if a.Dominante {
		t.Fatalf("une ambiance faible fait écarter la fenêtre : part %.2f", a.Part)
	}
}

// Et l'inverse : quand l'ambiance domine, ce qu'on mesurerait ne serait plus
// une personne. La fenêtre doit être écartée.
func TestUneAmbianceDominanteEcarteLaFenetre(t *testing.T) {
	e := NouvelEcouteur(pasTrame, 12)
	const bpm = 128.0
	n := int(12 / pasTrame)
	for i := 0; i < n; i++ {
		tt := float64(i) * pasTrame
		p := math.Mod(tt, 60/bpm)
		e.Observe(0.06+0.30*math.Exp(-p*14), false)
	}
	a := e.Analyse()
	if !a.Presente {
		t.Fatalf("pulsation non détectée : %+v", a)
	}
	if !a.Dominante {
		t.Fatalf("ambiance à %.2f de part non déclarée dominante", a.Part)
	}
}
