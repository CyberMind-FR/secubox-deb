// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package fft

import "math"

// LES FENÊTRES.
//
// Une FFT suppose le signal PÉRIODIQUE sur la durée analysée. Une trame de
// parole ne l'est jamais : le début et la fin ne se raccordent pas, et cette
// marche artificielle répand de l'énergie sur tout le spectre — de la « fuite
// spectrale ». On atténue donc les bords avant de transformer.
//
// Hann pour l'affichage et pour le pitch : lobe principal large mais lobes
// secondaires qui s'effondrent vite (-31 dB, puis -18 dB/octave), ce qui évite
// qu'une formante forte n'enterre ses voisines.

// Hann rend une fenêtre de Hann de n points, périodique (dénominateur n et non
// n-1) : c'est la forme correcte pour l'analyse spectrale, celle en n-1 étant
// faite pour le filtrage.
func Hann(n int) []float64 {
	w := make([]float64, n)
	if n == 1 {
		w[0] = 1
		return w
	}
	for i := range w {
		w[i] = 0.5 - 0.5*math.Cos(2*math.Pi*float64(i)/float64(n))
	}
	return w
}

// GainCoherent : la somme de la fenêtre rapportée à n. Une fenêtre ATTÉNUE le
// signal ; sans cette correction l'énergie affichée dépendrait de la fenêtre
// choisie plutôt que de la voix.
func GainCoherent(w []float64) float64 {
	if len(w) == 0 {
		return 1
	}
	s := 0.0
	for _, v := range w {
		s += v
	}
	return s / float64(len(w))
}
