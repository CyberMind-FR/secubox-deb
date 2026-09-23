// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package pitch

import "math"

// JITTER ET SHIMMER : L'IRRÉGULARITÉ DE LA VOIX.
//
// Deux cycles glottiques ne sont jamais identiques. Le jitter mesure combien la
// DURÉE varie d'un cycle au suivant, le shimmer combien l'AMPLITUDE varie. Une
// voix reposée est régulière ; la fatigue, l'effort et l'émotion la dérèglent.
//
// CE QUE NOS CHIFFRES NE SONT PAS. En clinique, jitter et shimmer se mesurent
// sur une voyelle TENUE, cycle par cycle, avec des marques glottiques posées à
// l'échantillon près — et les seuils publiés (≈1 % de jitter, ≈3 % de shimmer)
// valent DANS CE PROTOCOLE. Ici on travaille sur de la parole courante, à
// partir d'une période estimée toutes les dix millisecondes : chaque valeur
// résume une centaine de cycles au lieu d'en comparer deux. C'est un INDICE
// D'IRRÉGULARITÉ utilisable pour suivre une tendance sur une même voix, dans la
// même pièce. Le comparer à un seuil clinique, ou entre deux personnes, n'a pas
// de sens — et le module ne le fait nulle part.
type Perturbation struct {
	fenetre   int
	periodes  []float64
	amplitude []float64
}

// NouvellePerturbation garde les `fenetre` dernières trames VOISÉES. À cent
// trames par seconde, cinquante trames font une demi-seconde de voix : assez
// pour lisser, assez court pour suivre une phrase.
func NouvellePerturbation(fenetre int) *Perturbation {
	return &Perturbation{fenetre: fenetre}
}

// Ajoute une trame voisée. Les trames non voisées NE SONT PAS ajoutées, et
// c'est essentiel : un silence entre deux mots créerait un écart de période
// gigantesque et purement fictif.
func (p *Perturbation) Ajoute(periode, amplitude float64) {
	if periode <= 0 || amplitude <= 0 {
		return
	}
	p.periodes = append(p.periodes, periode)
	p.amplitude = append(p.amplitude, amplitude)
	if len(p.periodes) > p.fenetre {
		p.periodes = p.periodes[1:]
		p.amplitude = p.amplitude[1:]
	}
}

// Oublie vide la fenêtre — à appeler quand la parole s'interrompt assez
// longtemps pour que les deux côtés du trou n'aient plus rien à voir.
func (p *Perturbation) Oublie() {
	p.periodes = p.periodes[:0]
	p.amplitude = p.amplitude[:0]
}

// Assez dit si l'on a de quoi répondre. En-dessous, on ne rend RIEN plutôt
// qu'un chiffre tiré de trois mesures — un indice calculé sur presque rien
// ressemble à un indice, et c'est précisément le danger.
const MinimumTrames = 12

func (p *Perturbation) Assez() bool { return len(p.periodes) >= MinimumTrames }

// Jitter relatif, en pourcentage : moyenne des écarts absolus entre périodes
// consécutives, rapportée à la période moyenne.
func (p *Perturbation) Jitter() float64 {
	if !p.Assez() {
		return 0
	}
	var ecarts, somme float64
	for i := 1; i < len(p.periodes); i++ {
		ecarts += math.Abs(p.periodes[i] - p.periodes[i-1])
	}
	for _, v := range p.periodes {
		somme += v
	}
	moyenne := somme / float64(len(p.periodes))
	if moyenne <= 0 {
		return 0
	}
	return 100 * (ecarts / float64(len(p.periodes)-1)) / moyenne
}

// Shimmer en décibels : moyenne des |20·log10(A_{i+1}/A_i)|. La forme en dB est
// préférée à la forme relative parce qu'elle ne dépend pas du niveau
// d'enregistrement — doubler le gain du micro ne doit pas doubler le shimmer.
func (p *Perturbation) Shimmer() float64 {
	if !p.Assez() {
		return 0
	}
	var somme float64
	for i := 1; i < len(p.amplitude); i++ {
		a, b := p.amplitude[i-1], p.amplitude[i]
		if a <= 0 || b <= 0 {
			continue
		}
		somme += math.Abs(20 * math.Log10(b/a))
	}
	return somme / float64(len(p.amplitude)-1)
}

// EtendueF0 : l'écart-type de la fréquence fondamentale sur la fenêtre, en
// demi-tons. C'est la « mélodie » de la parole — une voix monocorde s'aplatit,
// une voix animée s'étend. En demi-tons parce que la perception de la hauteur
// est logarithmique : vingt hertz ne s'entendent pas pareil à 100 et à 300 Hz.
func (p *Perturbation) EtendueF0(echantillonnage float64) float64 {
	if !p.Assez() {
		return 0
	}
	demi := make([]float64, 0, len(p.periodes))
	for _, t := range p.periodes {
		if t > 0 {
			demi = append(demi, 12*math.Log2(echantillonnage/t))
		}
	}
	if len(demi) < 2 {
		return 0
	}
	var m float64
	for _, v := range demi {
		m += v
	}
	m /= float64(len(demi))
	var v2 float64
	for _, v := range demi {
		v2 += (v - m) * (v - m)
	}
	return math.Sqrt(v2 / float64(len(demi)-1))
}

// MedianeF0 en hertz, robuste aux sauts d'octave résiduels — une moyenne se
// laisserait tirer par une seule trame fausse, la médiane non.
func (p *Perturbation) MedianeF0(echantillonnage float64) float64 {
	if len(p.periodes) == 0 {
		return 0
	}
	c := append([]float64(nil), p.periodes...)
	for i := 1; i < len(c); i++ {
		for j := i; j > 0 && c[j] < c[j-1]; j-- {
			c[j], c[j-1] = c[j-1], c[j]
		}
	}
	t := c[len(c)/2]
	if t <= 0 {
		return 0
	}
	return echantillonnage / t
}
