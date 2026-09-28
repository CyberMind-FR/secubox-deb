// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package mfcc

import "math"

// DCT2 applique la transformée en cosinus discrète de type II, orthonormée.
//
// C'est elle qui « décorrèle » les énergies mel : les bandes voisines varient
// ensemble (un formant en couvre plusieurs), et un classifieur nourri de
// variables redondantes accorde trois fois le même poids à la même observation.
func DCT2(entree []float64, sortie []float64, garder int) []float64 {
	n := len(entree)
	if garder > n {
		garder = n
	}
	if cap(sortie) < garder {
		sortie = make([]float64, garder)
	}
	sortie = sortie[:garder]
	for k := 0; k < garder; k++ {
		s := 0.0
		for i := 0; i < n; i++ {
			s += entree[i] * math.Cos(math.Pi*float64(k)*(float64(i)+0.5)/float64(n))
		}
		if k == 0 {
			s *= math.Sqrt(1 / float64(n))
		} else {
			s *= math.Sqrt(2 / float64(n))
		}
		sortie[k] = s
	}
	return sortie
}

// CentreDeGravite : le barycentre fréquentiel du spectre, en hertz.
//
// C'est le « brillant » du son. Il monte quand la voix se tend — le conduit se
// raidit, l'énergie glisse vers les aigus. C'est l'un des rares indices
// acoustiques de tension sur lesquels la littérature s'accorde, et il a
// l'avantage de se lire directement, sans modèle.
func CentreDeGravite(puissance []float64, echantillonnage float64) float64 {
	n := len(puissance)
	if n < 2 {
		return 0
	}
	var num, den float64
	pas := echantillonnage / float64(2*(n-1))
	for k, p := range puissance {
		num += float64(k) * pas * p
		den += p
	}
	if den <= 0 {
		return 0
	}
	return num / den
}

// PlatitudeSpectrale : moyenne géométrique sur moyenne arithmétique, dans
// [0, 1]. Proche de 1 pour du bruit (spectre plat), proche de 0 pour un son
// harmonique. C'est ce qui sépare un souffle d'une voyelle — et donc l'un des
// ingrédients de la détection de voix.
func PlatitudeSpectrale(puissance []float64) float64 {
	n := 0
	var logSomme, somme float64
	for _, p := range puissance {
		if p <= 0 {
			p = 1e-20
		}
		logSomme += math.Log(p)
		somme += p
		n++
	}
	if n == 0 || somme <= 0 {
		return 0
	}
	geo := math.Exp(logSomme / float64(n))
	arith := somme / float64(n)
	if arith <= 0 {
		return 0
	}
	f := geo / arith
	if f > 1 {
		return 1
	}
	return f
}

// PenteSpectrale : la pente de la régression linéaire de l'énergie (en dB) sur
// la fréquence, en dB par kilohertz. Une voix forcée « redresse » son spectre ;
// une voix fatiguée s'affaisse dans les aigus.
func PenteSpectrale(puissance []float64, echantillonnage float64) float64 {
	n := len(puissance)
	if n < 2 {
		return 0
	}
	pas := echantillonnage / float64(2*(n-1)) / 1000 // en kHz
	var sx, sy, sxy, sxx float64
	for k, p := range puissance {
		if p <= 0 {
			p = 1e-20
		}
		x := float64(k) * pas
		y := 10 * math.Log10(p)
		sx += x
		sy += y
		sxy += x * y
		sxx += x * x
	}
	m := float64(n)
	den := m*sxx - sx*sx
	if den == 0 {
		return 0
	}
	return (m*sxy - sx*sy) / den
}
