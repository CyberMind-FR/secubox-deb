// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Package fft — transformée de Fourier rapide, en Go pur.
//
// POURQUOI PAS UNE BIBLIOTHÈQUE. Tout le dépôt se construit en `CGO_ENABLED=0`
// et se croise vers arm64 : une FFT en C imposerait une chaîne de compilation
// croisée et une bibliothèque partagée à l'exécution, pour un algorithme qui
// tient en soixante lignes et qu'on peut vérifier exactement (Parseval, Dirac,
// sinusoïde pure). Le coût d'une dépendance n'est jamais nul ; ici il n'est pas
// justifié.
package fft

import (
	"math"
	"math/bits"
)

// Plan précalcule ce qui ne dépend que de la taille : les racines de l'unité et
// la table d'inversion de bits. Une trame arrive toutes les dix millisecondes —
// recalculer ces tables à chaque fois coûterait plus cher que la transformée.
type Plan struct {
	n       int
	inverse []int
	cos     []float64 // cos(-2πk/n) pour k < n/2
	sin     []float64
	fenetre []float64
	gain    float64
	re, im  []float64 // tampons de travail de Spectre
}

// NouveauPlan prépare une FFT de n points. n DOIT être une puissance de deux :
// l'algorithme radix-2 n'a de sens que là, et accepter autre chose reviendrait
// à rendre des résultats faux en silence.
func NouveauPlan(n int) *Plan {
	if n < 2 || bits.OnesCount(uint(n)) != 1 {
		panic("fft : la taille doit être une puissance de deux ≥ 2")
	}
	p := &Plan{n: n, inverse: make([]int, n),
		cos: make([]float64, n/2), sin: make([]float64, n/2)}
	lg := bits.TrailingZeros(uint(n))
	for i := 0; i < n; i++ {
		p.inverse[i] = int(bits.Reverse(uint(i)) >> (bits.UintSize - lg))
	}
	for k := 0; k < n/2; k++ {
		a := -2 * math.Pi * float64(k) / float64(n)
		p.cos[k], p.sin[k] = math.Cos(a), math.Sin(a)
	}
	p.fenetre = Hann(n)
	p.gain = GainCoherent(p.fenetre)
	p.re = make([]float64, n)
	p.im = make([]float64, n)
	return p
}

// Taille rend le nombre de points du plan.
func (p *Plan) Taille() int { return p.n }

// Transforme calcule la FFT sur place de (re, im), tous deux de taille n.
func (p *Plan) Transforme(re, im []float64) {
	n := p.n
	for i := 0; i < n; i++ {
		if j := p.inverse[i]; j > i {
			re[i], re[j] = re[j], re[i]
			im[i], im[j] = im[j], im[i]
		}
	}
	for taille := 2; taille <= n; taille <<= 1 {
		demi := taille / 2
		pas := n / taille
		for debut := 0; debut < n; debut += taille {
			for k := 0; k < demi; k++ {
				c, s := p.cos[k*pas], p.sin[k*pas]
				i, j := debut+k, debut+k+demi
				tr := re[j]*c - im[j]*s
				ti := re[j]*s + im[j]*c
				re[j], im[j] = re[i]-tr, im[i]-ti
				re[i], im[i] = re[i]+tr, im[i]+ti
			}
		}
	}
}

// Spectre rend le module du spectre d'un signal réel, fenêtré par Hann, sur
// n/2+1 points (du continu à Nyquist). `sortie` est réutilisée si elle a la
// bonne taille — on tourne à cent trames par seconde, allouer à chaque fois
// donnerait du travail au ramasse-miettes pour rien.
func (p *Plan) Spectre(echantillons []float64, sortie []float64) []float64 {
	// LES TAMPONS SONT CEUX DU PLAN. On passe ici cent fois par seconde :
	// trente-deux kilo-octets alloués à chaque trame donneraient au
	// ramasse-miettes le travail qu'on cherche à épargner au processeur.
	// Corollaire : un Plan n'est PAS sûr en accès concurrent — un par
	// goroutine d'analyse, ce que le moteur garantit.
	n := p.n
	re, im := p.re, p.im
	for i := range re {
		re[i], im[i] = 0, 0
	}
	m := len(echantillons)
	if m > n {
		m = n
	}
	for i := 0; i < m; i++ {
		re[i] = echantillons[i] * p.fenetre[i]
	}
	p.Transforme(re, im)

	demi := n/2 + 1
	if cap(sortie) < demi {
		sortie = make([]float64, demi)
	}
	sortie = sortie[:demi]
	// Correction du gain de fenêtre, puis facteur deux sur les raies repliées :
	// un signal réel range la moitié de son énergie dans les fréquences
	// négatives, qu'on n'affiche pas. Sans ce facteur, l'amplitude lue serait
	// la moitié de l'amplitude réelle — et le continu, lui, n'est pas replié.
	norm := 1 / (float64(n) * p.gain)
	for k := 0; k < demi; k++ {
		mag := math.Hypot(re[k], im[k]) * norm
		if k != 0 && k != n/2 {
			mag *= 2
		}
		sortie[k] = mag
	}
	return sortie
}

// Decibels convertit un module en dBFS, avec un PLANCHER.
//
// Le silence numérique vaut zéro, dont le logarithme est -∞ : sans plancher,
// une trame muette produirait des NaN qui se propageraient jusqu'au JSON, où
// ils ne sont même pas représentables. On borne donc à -120 dB, en-dessous du
// plancher de bruit de n'importe quel micro.
func Decibels(mag, plancher float64) float64 {
	if mag <= 0 {
		return plancher
	}
	d := 20 * math.Log10(mag)
	if d < plancher {
		return plancher
	}
	return d
}

// Frequence rend la fréquence centrale de la raie k.
func (p *Plan) Frequence(k int, echantillonnage float64) float64 {
	return float64(k) * echantillonnage / float64(p.n)
}

// TransformeInverse : la transformée inverse, par conjugaison.
//
// IFFT(y) = conj(FFT(conj(y)))/n — une identité qui évite d'écrire une seconde
// routine papillon, donc un second endroit où se tromper.
func (p *Plan) TransformeInverse(re, im []float64) {
	for i := range im {
		im[i] = -im[i]
	}
	p.Transforme(re, im)
	inv := 1 / float64(p.n)
	for i := range re {
		re[i] *= inv
		im[i] *= -inv
	}
}
