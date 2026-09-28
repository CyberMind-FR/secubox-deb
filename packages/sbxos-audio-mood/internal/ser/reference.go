// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package ser

import "math"

// LA RÉFÉRENCE EN DIRECT : utilisable dès la première mesure, meilleure ensuite.
//
// ── CE QU'ON REMPLACE, ET POURQUOI ─────────────────────────────────────────
//
// L'étalon fonctionnait par ACCUMULATION PUIS DÉBLOCAGE : cent quatre-vingts
// observations, et alors seulement une réponse. C'était doublement mauvais.
//
// D'abord ça n'aboutissait pas. Une observation par fenêtre de voix — pas par
// seconde, par seconde OÙ L'ON PARLE — fait dix bonnes minutes d'usage réel.
// Et l'étalon vivait dans la session : un rechargement de page repartait de
// zéro. D'où les 6 %, 26 %, 27 % vus à l'écran, qui ne sont pas un compteur
// bloqué mais trois sessions différentes.
//
// Ensuite, et c'est plus grave, LE SEUIL ÉTAIT UNE MAUVAISE FAÇON D'EXPRIMER
// L'INCERTITUDE. Il n'existe pas d'instant où l'on « connaît » une voix : on la
// connaît de mieux en mieux. Un mur binaire transforme ce continuum en
// tout-ou-rien, et pendant tout le « rien » l'utilisateur ne peut pas
// distinguer un module qui travaille d'un module en panne.
//
// ── CE QU'ON FAIT À LA PLACE ───────────────────────────────────────────────
//
// Un estimateur EN LIGNE : centre et dispersion se mettent à jour à chaque
// mesure, et sont lisibles dès la première. L'incertitude n'interdit plus de
// répondre — elle ÉLARGIT LA DISPERSION.
//
// C'est le cœur de l'idée et elle est jolie : diviser par une dispersion plus
// large rapetisse tous les écarts, donc une référence mal connue produit
// d'elle-même des lectures plus TIMIDES, qui penchent vers le repos. On n'a
// pas besoin d'interdire quoi que ce soit ; l'arithmétique s'en charge, et
// elle le fait progressivement au lieu d'un déclic.
//
// ── CE QUE LE PRIOR FAIT, ET NE FAIT PAS ───────────────────────────────────
//
// À une seule mesure, on ne connaît aucune dispersion. On part donc d'ordres
// de grandeur de la parole conversationnelle — l'écart interquartile d'une
// fondamentale tourne autour de 10 à 15 % de sa médiane, par exemple.
//
// CES PRIORS NE TOUCHENT JAMAIS AU CENTRE. Le centre est toujours celui de
// CETTE voix, dès la première mesure. Les priors ne servent qu'à dire « on ne
// sait pas encore à quel point elle varie », c'est-à-dire à élargir. La règle
// « tout est relatif à la personne » tient donc entière : on n'a jamais
// comparé une hauteur à une norme, seulement une incertitude à un ordre de
// grandeur.

// N0 : la demi-vie de l'ignorance. La fiabilité vaut n/(n+N0), soit un demi à
// vingt-cinq mesures et trois quarts à soixante-quinze. Pas de seuil, une
// pente.
const N0 = 25.0

// Suivi : un trait suivi en direct — centre, dispersion, et combien on a vu.
type Suivi struct {
	N      int     `json:"n"`
	Centre float64 `json:"centre"`
	Disp   float64 `json:"disp"` // écart absolu médian, approché en ligne
	rel    float64 // dispersion relative a priori, pour l'élargissement
}

// Observe intègre une mesure.
//
// LE CENTRE SUIT UNE MÉDIANE, PAS UNE MOYENNE : un pas de taille fixe dans la
// direction du signe (Robbins-Monro) converge vers la médiane, et ne se laisse
// pas emporter par une valeur aberrante — un saut d'octave, une porte qui
// claque — comme le ferait une moyenne.
func (s *Suivi) Observe(v float64) {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return
	}
	s.N++
	if s.N == 1 {
		s.Centre = v
		s.Disp = math.Abs(v) * s.rel
		return
	}
	// Pas décroissant : on bouge beaucoup au début, de moins en moins ensuite.
	pas := s.Disp * 0.9 / math.Sqrt(float64(s.N))
	switch {
	case v > s.Centre:
		s.Centre += pas
	case v < s.Centre:
		s.Centre -= pas
	}
	// La dispersion suit de la même façon, sur l'écart absolu au centre.
	e := math.Abs(v - s.Centre)
	pasD := s.Disp * 0.9 / math.Sqrt(float64(s.N))
	switch {
	case e > s.Disp:
		s.Disp += pasD
	case e < s.Disp:
		s.Disp -= pasD
	}
	if plancher := math.Abs(s.Centre) * s.rel * 0.25; s.Disp < plancher {
		// Une dispersion qui s'effondre ferait exploser tous les écarts : la
		// moindre variation deviendrait un signal. On l'empêche de descendre
		// sous un quart de l'ordre de grandeur attendu.
		s.Disp = plancher
	}
}

// Fiabilite : 0 à 1, combien on connaît ce trait. Continue, sans palier.
func (s *Suivi) Fiabilite() float64 {
	return float64(s.N) / (float64(s.N) + N0)
}

// DispEffective : la dispersion ÉLARGIE par ce qu'on ignore encore.
//
// À n petit on double presque ; à n grand on tend vers la dispersion observée.
// C'est ici que l'incertitude devient une lecture plus calme plutôt qu'un
// refus de répondre.
func (s *Suivi) DispEffective() float64 {
	d := s.Disp
	if p := math.Abs(s.Centre) * s.rel; d < p && s.N < 12 {
		// Très tôt, la dispersion observée est presque toujours sous-estimée :
		// quelques mesures rapprochées se ressemblent. On retient l'ordre de
		// grandeur attendu tant qu'on n'a pas de quoi le contredire.
		d = p
	}
	elargissement := 1 + 1.6/math.Sqrt(float64(s.N)+1)
	return d * elargissement
}

// Ecart : la position de `v`, en dispersions effectives, bornée à ±3.
func (s *Suivi) Ecart(v float64) float64 {
	if s.N == 0 {
		return 0
	}
	d := s.DispEffective()
	if d <= 1e-12 {
		return 0
	}
	return math.Max(-3, math.Min(3, (v-s.Centre)/d))
}

// Reference : les cinq traits suivis, pour une personne.
//
// Sérialisable telle quelle : c'est ce qui permet de la RETENIR d'une session
// à l'autre. Cinq fois trois nombres — rien dont on puisse reconstituer une
// voix, et encore moins une parole.
type Reference struct {
	F0      Suivi `json:"f0"`
	Energie Suivi `json:"energie"`
	Debit   Suivi `json:"debit"`
	Jitter  Suivi `json:"jitter"`
	Centre  Suivi `json:"centre"`
}

// Ordres de grandeur de la parole conversationnelle. Ils n'interviennent QUE
// dans la dispersion, jamais dans le centre.
const (
	relF0      = 0.12 // l'interquartile d'une fondamentale : ~10-15 % de sa médiane
	relEnergie = 0.45 // le RMS varie beaucoup d'une syllabe à l'autre
	relDebit   = 0.25
	relJitter  = 0.50 // très dispersé par nature
	relCentre  = 0.25
)

// NouvelleReference prépare un suivi vierge — immédiatement utilisable.
func NouvelleReference() *Reference {
	r := &Reference{}
	r.amorce()
	return r
}

// amorce repose les dispersions relatives, y compris sur une référence relue
// du disque (les priors ne sont pas sérialisés : ce sont des constantes du
// code, pas des données de la personne).
func (r *Reference) amorce() {
	r.F0.rel, r.Energie.rel, r.Debit.rel = relF0, relEnergie, relDebit
	r.Jitter.rel, r.Centre.rel = relJitter, relCentre
}

// Reprendre installe une référence relue du disque, EN PLACE.
//
// En place, et c'est important : le classifieur tient un pointeur vers cette
// référence. Le remplacer par un autre pointeur laisserait le classifieur
// travailler sur l'ancienne — une session qui aurait l'air de reprendre sans
// rien reprendre du tout, ce qui est le pire des deux mondes.
//
// Les dispersions relatives sont reposées : ce sont des constantes du code,
// pas des données de la personne, et elles ne voyagent donc pas avec la
// référence.
func (r *Reference) Reprendre(autre Reference) {
	*r = autre
	r.amorce()
}

// Observe intègre une fenêtre de traits. Les fenêtres SANS voix ne comptent
// pas : le silence n'a pas de hauteur, et l'inclure abaisserait l'ordinaire.
func (r *Reference) Observe(t Traits) {
	if t.TramesVoisees < 10 || t.F0Median <= 0 {
		return
	}
	r.F0.Observe(t.F0Median)
	r.Energie.Observe(t.Energie)
	r.Jitter.Observe(t.Jitter)
	r.Centre.Observe(t.Centre)
	if t.Debit > 0 {
		r.Debit.Observe(t.Debit)
	}
}

// Ecarts : la position des traits courants dans l'ordinaire de cette personne.
func (r *Reference) Ecarts(t Traits) map[string]float64 {
	return map[string]float64{
		"f0":      r.F0.Ecart(t.F0Median),
		"energie": r.Energie.Ecart(t.Energie),
		"debit":   r.Debit.Ecart(t.Debit),
		"jitter":  r.Jitter.Ecart(t.Jitter),
		"centre":  r.Centre.Ecart(t.Centre),
	}
}

// Fiabilite : la moins bien connue des cinq. On se juge sur le maillon faible —
// une référence excellente sur la hauteur et nulle sur le débit ne permet pas
// de lire un débit.
func (r *Reference) Fiabilite() float64 {
	m := 1.0
	for _, s := range []Suivi{r.F0, r.Energie, r.Debit, r.Jitter, r.Centre} {
		if f := s.Fiabilite(); f < m {
			m = f
		}
	}
	return m
}

// Observations : combien de fenêtres de voix ont nourri la référence.
func (r *Reference) Observations() int { return r.F0.N }

// Vivante : y a-t-il de quoi répondre ? DÈS LA PREMIÈRE MESURE, oui — c'est
// tout l'objet de ce fichier. La question « est-ce assez ? » n'existe plus ;
// seule subsiste « à quel point ? », et c'est la fiabilité qui y répond.
func (r *Reference) Vivante() bool { return r.Observations() >= 1 }
