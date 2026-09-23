// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Package vad — détection d'activité vocale, en Go pur.
//
// CE QUE CE N'EST PAS. Ce n'est PAS un habillage du VAD de WebRTC. Celui-ci est
// écrit en C et demanderait CGO ; or tout le dépôt se construit en
// `CGO_ENABLED=0` et se croise vers arm64, et une bibliothèque partagée de plus
// à l'exécution serait un prix élevé pour une décision binaire. On reprend donc
// sa DÉMARCHE — découper le spectre en sous-bandes vocales, comparer chacune à
// un plancher de bruit appris — sans prétendre en reproduire les coefficients.
// Le dire est important : quelqu'un qui lit « WebRTC VAD » s'attend aux
// performances publiées de WebRTC, pas aux nôtres.
//
// POURQUOI UN PLANCHER APPRIS. Un seuil fixe ne survit pas au déplacement du
// micro : une pièce calme et une pièce avec un ventilateur n'ont pas le même
// niveau de repos, et un seuil réglé pour l'une bavarde ou reste muet dans
// l'autre. Le plancher monte lentement et descend vite : il apprend le bruit
// pendant les silences, et ne se laisse pas tirer vers le haut par la parole.
package vad

import "math"

// Les sous-bandes, en hertz. Elles couvrent ce qui porte la voix : la
// fondamentale et les deux premiers formants, là où le rapport signal/bruit
// d'une parole est le meilleur. Au-delà de 4 kHz, on ne trouve guère que des
// fricatives et du souffle de micro.
var bandes = [...][2]float64{
	{80, 250}, {250, 500}, {500, 1000},
	{1000, 2000}, {2000, 3000}, {3000, 4000},
}

// Agressivite règle l'arbitrage entre manquer de la parole et en inventer.
type Agressivite int

const (
	Bavard      Agressivite = iota // garde tout ce qui ressemble à de la voix
	Normal                         // le défaut
	Prudent                        // ne garde que ce qui est franc
	TresPrudent                    // pour un environnement bruyant
)

func (a Agressivite) marge() float64 {
	switch a {
	case Bavard:
		return 3.0
	case Prudent:
		return 9.0
	case TresPrudent:
		return 12.0
	default:
		return 6.0
	}
}

// Detecteur garde le plancher de bruit et l'état de la décision.
//
// Il n'est PAS sûr en accès concurrent : un détecteur par flux analysé.
type Detecteur struct {
	agressivite Agressivite
	plancher    []float64 // énergie de repos apprise, par bande (dB)
	amorce      int       // trames vues, pour l'amorçage
	actif       bool
	restant     int // trames de rémanence encore dues
	remanence   int
	debuts      []int
	fins        []int
}

// Nouveau prépare un détecteur pour un spectre de `raies` points.
//
// `remanence` : le nombre de trames pendant lesquelles on continue de déclarer
// la parole après sa disparition. Sans elle, on coupe les fins de mots — les
// consonnes finales sont faibles, et une décision trame par trame les jette.
func Nouveau(raies int, echantillonnage float64, a Agressivite, remanence int) *Detecteur {
	d := &Detecteur{
		agressivite: a, remanence: remanence,
		plancher: make([]float64, len(bandes)),
		debuts:   make([]int, len(bandes)),
		fins:     make([]int, len(bandes)),
	}
	pas := echantillonnage / float64(2*(raies-1))
	for i, b := range bandes {
		d.debuts[i] = int(b[0] / pas)
		d.fins[i] = int(b[1] / pas)
		if d.fins[i] >= raies {
			d.fins[i] = raies - 1
		}
		if d.debuts[i] >= d.fins[i] {
			d.debuts[i] = d.fins[i] - 1
		}
		if d.debuts[i] < 0 {
			d.debuts[i] = 0
		}
		d.plancher[i] = -90
	}
	return d
}

// Verdict : la décision et de quoi la comprendre.
type Verdict struct {
	Parole    bool
	Confiance float64   // 0..1, la marge au-dessus du plancher, normalisée
	Bandes    []float64 // énergie par bande, en dB
	Plancher  []float64 // le bruit appris, en dB — utile pour comprendre un refus
	Amorcage  bool      // vrai tant que le plancher n'est pas fiable
}

// AmorcageTrames : tant qu'on n'a pas vu ça, le plancher n'est pas de confiance.
// Une demi-seconde à cent trames par seconde.
const AmorcageTrames = 50

// Analyse rend le verdict pour une trame, à partir de son spectre de PUISSANCE.
func (d *Detecteur) Analyse(puissance []float64) Verdict {
	bandesdB := make([]float64, len(bandes))
	votes := 0
	var marge float64
	for i := range bandes {
		s := 0.0
		n := 0
		for k := d.debuts[i]; k <= d.fins[i] && k < len(puissance); k++ {
			s += puissance[k]
			n++
		}
		if n == 0 {
			n = 1
		}
		e := 10 * math.Log10(s/float64(n)+1e-20)
		bandesdB[i] = e

		if e > d.plancher[i]+d.agressivite.marge() {
			votes++
			marge += e - d.plancher[i]
		}
		// MONTÉE LENTE, DESCENTE RAPIDE. Le plancher doit suivre un bruit qui
		// s'installe, sans se laisser tirer vers le haut par une phrase : on
		// monte de 0,05 dB par trame (quelques secondes pour s'adapter) et on
		// descend de 0,5 dB (la pièce redevient calme en une demi-seconde).
		switch {
		case e > d.plancher[i]:
			d.plancher[i] += 0.05
		default:
			d.plancher[i] -= 0.5
			if d.plancher[i] < e {
				d.plancher[i] = e
			}
		}
	}
	if d.amorce < AmorcageTrames {
		d.amorce++
	}

	// LA VOIX OCCUPE PLUSIEURS BANDES À LA FOIS. Un claquement de porte ou un
	// bourdonnement secteur n'en excite qu'une ou deux ; exiger au moins trois
	// bandes écarte l'essentiel des bruits impulsifs sans rien apprendre d'eux.
	brut := votes >= 3
	switch {
	case brut:
		d.actif = true
		d.restant = d.remanence
	case d.restant > 0:
		d.restant--
	default:
		d.actif = false
	}

	conf := 0.0
	if votes > 0 {
		conf = marge / float64(votes) / 20 // 20 dB au-dessus du bruit = certitude
		if conf > 1 {
			conf = 1
		}
	}
	return Verdict{
		Parole: d.actif && d.amorce >= AmorcageTrames, Confiance: conf,
		Bandes: bandesdB, Plancher: append([]float64(nil), d.plancher...),
		Amorcage: d.amorce < AmorcageTrames,
	}
}

// Reinitialise oublie le bruit appris — à appeler quand la source d'entrée
// change, sinon le plancher de l'ancienne pièce juge la nouvelle.
func (d *Detecteur) Reinitialise() {
	for i := range d.plancher {
		d.plancher[i] = -90
	}
	d.amorce, d.actif, d.restant = 0, false, 0
}
