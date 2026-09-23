// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Package mfcc — banc de filtres mel et coefficients cepstraux.
//
// À QUOI ÇA SERT ICI. Le spectre brut dit « il y a de l'énergie à 1 200 Hz ».
// Ce n'est pas ce qui distingue une voix tendue d'une voix posée : ce qui
// compte est la FORME de l'enveloppe, et l'oreille la perçoit sur une échelle
// comprimée vers les aigus. L'échelle mel reproduit cette compression, et le
// cepstre sépare l'enveloppe (le timbre, donc l'état du conduit vocal) de la
// structure fine (la hauteur, déjà mesurée ailleurs).
//
// On les calcule ici pour DEUX raisons seulement : nourrir un classifieur ONNX
// s'il y en a un, et fournir au classifieur heuristique la pente spectrale et
// le centre de gravité, qui sont les deux indices de tension les mieux établis.
package mfcc

import "math"

// EnMel, EnHertz : l'échelle mel, formule de O'Shaughnessy (1987).
func EnMel(hz float64) float64 { return 2595 * math.Log10(1+hz/700) }
func EnHertz(mel float64) float64 {
	return 700 * (math.Pow(10, mel/2595) - 1)
}

// Banc : un banc de filtres triangulaires en mel, appliqué à un spectre de
// puissance de `raies` points.
type Banc struct {
	raies   int
	filtres [][]float64 // poids par filtre, indexés sur la même grille de raies
	debuts  []int       // première raie non nulle de chaque filtre
}

// NouveauBanc construit `n` filtres entre `bas` et `haut` hertz.
//
// LES FILTRES SE CHEVAUCHENT À MI-HAUTEUR, ce qui n'est pas un détail : sans
// recouvrement, un formant tombant entre deux filtres disparaîtrait, et
// l'enveloppe sauterait d'une trame à l'autre sans que la voix ait bougé.
func NouveauBanc(n, raies int, echantillonnage, bas, haut float64) *Banc {
	if haut > echantillonnage/2 {
		haut = echantillonnage / 2
	}
	b := &Banc{raies: raies, filtres: make([][]float64, n), debuts: make([]int, n)}
	melBas, melHaut := EnMel(bas), EnMel(haut)
	// n+2 points : chaque filtre a besoin de son voisin de gauche et de droite
	// pour poser les deux pentes de son triangle.
	points := make([]int, n+2)
	nfft := float64(2 * (raies - 1))
	for i := range points {
		mel := melBas + (melHaut-melBas)*float64(i)/float64(n+1)
		points[i] = int(math.Round(EnHertz(mel) * nfft / echantillonnage))
		if points[i] >= raies {
			points[i] = raies - 1
		}
	}
	for f := 0; f < n; f++ {
		g, c, d := points[f], points[f+1], points[f+2]
		if d <= g {
			// Les filtres graves peuvent se retrouver tous sur la même raie
			// quand la résolution ne suffit pas. On pose un filtre d'une raie
			// plutôt qu'un filtre vide, qui rendrait un coefficient nul
			// constant — indiscernable d'un silence dans cette bande.
			d = g + 1
			if d >= raies {
				d = raies - 1
				g = d - 1
			}
			c = g
		}
		poids := make([]float64, d-g+1)
		for k := g; k <= d; k++ {
			switch {
			case k < c && c > g:
				poids[k-g] = float64(k-g) / float64(c-g)
			case k == c:
				poids[k-g] = 1
			case k > c && d > c:
				poids[k-g] = float64(d-k) / float64(d-c)
			}
		}
		b.filtres[f], b.debuts[f] = poids, g
	}
	return b
}

// Nombre de filtres.
func (b *Banc) Nombre() int { return len(b.filtres) }

// Energies applique le banc à un spectre de PUISSANCE et rend le logarithme de
// l'énergie par bande. `sortie` est réutilisée si elle a la bonne taille.
func (b *Banc) Energies(puissance []float64, sortie []float64) []float64 {
	n := len(b.filtres)
	if cap(sortie) < n {
		sortie = make([]float64, n)
	}
	sortie = sortie[:n]
	for f := 0; f < n; f++ {
		s := 0.0
		for i, w := range b.filtres[f] {
			if k := b.debuts[f] + i; k < len(puissance) {
				s += puissance[k] * w
			}
		}
		// Plancher : log(0) = -∞ se propagerait jusqu'au JSON, où l'infini
		// n'est même pas représentable.
		if s < 1e-12 {
			s = 1e-12
		}
		sortie[f] = math.Log(s)
	}
	return sortie
}
