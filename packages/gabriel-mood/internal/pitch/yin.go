// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Package pitch — hauteur de la voix par YIN, et perturbations de période.
//
// POURQUOI YIN ET PAS L'AUTOCORRÉLATION NUE. L'autocorrélation a un maximum en
// zéro qui écrase tout, et elle se laisse prendre par l'OCTAVE : sur une voix
// riche en harmoniques, le pic à 2·T0 rivalise avec celui à T0, et l'estimation
// saute une octave en arrière au milieu d'une phrase. YIN (de Cheveigné &
// Kawahara, 2002) répond exactement à ça : fonction de différence plutôt que de
// produit, normalisée en moyenne cumulée, puis SEUIL ABSOLU — on prend le
// PREMIER creux acceptable, pas le meilleur. C'est ce « premier » qui coupe
// l'erreur d'octave, parce que la période double arrive forcément après.
package pitch

import (
	"math"

	"github.com/CyberMind-FR/secubox-deb/gabriel-mood/internal/fft"
)

// Bornes de la voix humaine parlée. En-dehors, ce n'est pas une voix, et rendre
// une valeur y serait inventer : une basse à 40 Hz ou une raie à 800 Hz dans une
// conversation sont du bruit ou une erreur d'octave, pas une hauteur.
const (
	F0Min = 55.0  // plus bas qu'une voix d'homme grave
	F0Max = 500.0 // plus haut qu'une voix d'enfant aiguë
	// Seuil de YIN. 0,10 est la valeur de l'article ; on retient 0,15, plus
	// tolérant sur une voix bruitée de micro d'ambiance — au prix de quelques
	// trames voisées de plus, que le VAD écarte ensuite.
	Seuil = 0.15
)

// Estimateur détient les plans FFT et les tampons. Une trame arrive toutes les
// dix millisecondes : tout ce qui peut être alloué une fois l'est une fois.
type Estimateur struct {
	taille          int // N : longueur de la trame analysée
	fenetre         int // W = N/2 : longueur de la fenêtre de comparaison
	echantillonnage float64
	plan            *fft.Plan
	re, im          []float64
	ar, ai          []float64 // fenêtre de comparaison, transformée
	diff            []float64
	cumul           []float64
	carres          []float64
}

// NouvelEstimateur prépare l'analyse de trames de `taille` échantillons.
// `taille` doit être une puissance de deux : la moitié sert de fenêtre, l'autre
// de décalage maximal, ce qui fixe la plus basse fréquence détectable.
func NouvelEstimateur(taille int, echantillonnage float64) *Estimateur {
	e := &Estimateur{
		taille: taille, fenetre: taille / 2, echantillonnage: echantillonnage,
		plan:   fft.NouveauPlan(2 * taille),
		re:     make([]float64, 2*taille),
		im:     make([]float64, 2*taille),
		ar:     make([]float64, 2*taille),
		ai:     make([]float64, 2*taille),
		diff:   make([]float64, taille/2),
		cumul:  make([]float64, taille/2),
		carres: make([]float64, taille+1),
	}
	return e
}

// Resultat : ce qu'on a trouvé, et à quel point on y croit.
//
// `Clarte` n'est PAS une probabilité : c'est 1 − d'(τ), la profondeur du creux
// retenu. Une voix nette monte au-dessus de 0,9 ; du bruit large stagne sous
// 0,5. On la transmet telle quelle, sans la déguiser en pourcentage de
// certitude — c'est une mesure du signal, pas un avis sur le locuteur.
type Resultat struct {
	Hz      float64 // 0 si aucune période crédible
	Periode float64 // en échantillons, interpolée ; 0 si non voisé
	Clarte  float64 // 0..1
	Voise   bool
}

// Estime rend la hauteur d'une trame. `x` doit faire `taille` échantillons ;
// plus court, on refuse plutôt que de compléter par des zéros — le silence
// ajouté fausserait la fonction de différence sans qu'on le voie.
func (e *Estimateur) Estime(x []float64) Resultat {
	if len(x) < e.taille {
		return Resultat{}
	}
	e.differenceParFFT(x)

	// Moyenne cumulée normalisée : d'(0) = 1 par convention, et le
	// dénominateur croît avec τ, ce qui pénalise les grands décalages — c'est
	// la seconde barrière contre l'erreur d'octave.
	e.cumul[0] = 1
	somme := 0.0
	for tau := 1; tau < len(e.diff); tau++ {
		somme += e.diff[tau]
		if somme <= 0 {
			e.cumul[tau] = 1
			continue
		}
		e.cumul[tau] = e.diff[tau] * float64(tau) / somme
	}

	tauMin := int(e.echantillonnage/F0Max) - 1
	tauMax := int(e.echantillonnage/F0Min) + 1
	if tauMin < 2 {
		tauMin = 2
	}
	if tauMax >= len(e.cumul) {
		tauMax = len(e.cumul) - 1
	}
	if tauMin >= tauMax {
		return Resultat{}
	}

	// SEUIL ABSOLU : le PREMIER τ qui passe sous le seuil, puis on descend
	// jusqu'au fond de CE creux-là. Chercher le minimum global ramènerait
	// l'octave inférieure, dont le creux est souvent plus profond.
	best := -1
	for tau := tauMin; tau <= tauMax; tau++ {
		if e.cumul[tau] < Seuil {
			for tau+1 <= tauMax && e.cumul[tau+1] < e.cumul[tau] {
				tau++
			}
			best = tau
			break
		}
	}
	if best < 0 {
		// Aucun creux sous le seuil : on rend le meilleur candidat SANS le
		// déclarer voisé. L'appelant garde une hauteur indicative et sait
		// qu'elle ne vaut rien — c'est plus honnête que de rendre zéro, qui se
		// confondrait avec le silence.
		mini, vmin := tauMin, e.cumul[tauMin]
		for tau := tauMin; tau <= tauMax; tau++ {
			if e.cumul[tau] < vmin {
				mini, vmin = tau, e.cumul[tau]
			}
		}
		p := e.interpole(mini)
		return Resultat{Hz: e.echantillonnage / p, Periode: p,
			Clarte: 1 - vmin, Voise: false}
	}
	p := e.interpole(best)
	hz := e.echantillonnage / p
	if hz < F0Min || hz > F0Max {
		return Resultat{Clarte: 1 - e.cumul[best]}
	}
	return Resultat{Hz: hz, Periode: p, Clarte: 1 - e.cumul[best], Voise: true}
}

// differenceParFFT remplit e.diff avec d(τ) = P(0) + P(τ) − 2·r(τ).
//
// LA FORME NAÏVE COÛTE TROP CHER. d(τ) écrit tel quel demande W·τmax
// soustractions — deux millions d'opérations par trame, cent fois par seconde.
// Sur l'ARM64 de la board, c'est le budget entier du module pour une seule
// mesure. Développer le carré fait apparaître une corrélation, que la FFT donne
// en n·log n : le même résultat, deux ordres de grandeur moins cher.
//
// LE PIÈGE, ET JE SUIS TOMBÉ DEDANS : r(τ) n'est PAS l'autocorrélation de la
// trame. YIN compare une fenêtre FIXE de W points à la même fenêtre décalée —
// r(τ) = Σ_{j<W} x[j]·x[j+τ], toujours W termes. L'autocorrélation, elle, en
// somme N−τ : son nombre de termes DÉCROÎT avec le décalage, ce qui abaisse
// artificiellement d(τ) aux grands τ… et fait choisir une période trop courte.
// Le symptôme était propre et constant — dix pour cent trop haut sur toute
// l'étendue vocale, soit presque deux demi-tons. C'est donc une INTERcorrélation
// entre les W premiers points et la trame entière qu'il faut, pas une auto.
func (e *Estimateur) differenceParFFT(x []float64) {
	n2 := 2 * e.taille
	// A : la fenêtre de comparaison, W points. B : la trame entière, dans
	// laquelle on la fait glisser. Les tampons sont ceux de l'estimateur : on
	// passe ici cent fois par seconde, et trente-deux kilo-octets alloués à
	// chaque trame donneraient au ramasse-miettes tout le travail qu'on essaie
	// d'épargner au processeur.
	ar, ai := e.ar, e.ai
	for i := range ar {
		ar[i], ai[i] = 0, 0
	}
	copy(ar, x[:e.fenetre])
	copy(e.re, x[:e.taille])
	for i := e.taille; i < n2; i++ {
		e.re[i] = 0
	}
	for i := range e.im {
		e.im[i] = 0
	}
	e.plan.Transforme(ar, ai)
	e.plan.Transforme(e.re, e.im)
	// conj(A)·B, dont la transformée inverse est la corrélation glissante.
	for k := 0; k < n2; k++ {
		re := ar[k]*e.re[k] + ai[k]*e.im[k]
		im := ar[k]*e.im[k] - ai[k]*e.re[k]
		e.re[k], e.im[k] = re, im
	}
	e.plan.TransformeInverse(e.re, e.im)

	// Sommes de carrés glissantes, en une passe : P(τ) = Σ_{j=τ}^{τ+W-1} x[j]².
	e.carres[0] = 0
	for i := 0; i < e.taille; i++ {
		e.carres[i+1] = e.carres[i] + x[i]*x[i]
	}
	p0 := e.carres[e.fenetre]
	for tau := 0; tau < len(e.diff); tau++ {
		ptau := e.carres[tau+e.fenetre] - e.carres[tau]
		d := p0 + ptau - 2*e.re[tau]
		if d < 0 {
			d = 0 // arrondi flottant : une différence de carrés ne peut être négative
		}
		e.diff[tau] = d
	}
}

// interpole affine l'abscisse du creux par une parabole sur trois points.
// Sans elle, la résolution serait celle de l'échantillon : à 48 kHz et 200 Hz,
// un échantillon d'écart vaut déjà 0,8 Hz — et bien plus haut dans le spectre.
func (e *Estimateur) interpole(tau int) float64 {
	if tau <= 0 || tau >= len(e.cumul)-1 {
		return float64(tau)
	}
	g, c, d := e.cumul[tau-1], e.cumul[tau], e.cumul[tau+1]
	den := 2 * (2*c - g - d)
	if den == 0 {
		return float64(tau)
	}
	corr := (d - g) / den
	if math.Abs(corr) > 1 {
		return float64(tau)
	}
	return float64(tau) + corr
}
