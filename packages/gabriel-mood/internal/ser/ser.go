// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Package ser — lecture d'indices prosodiques.
//
// ┌──────────────────────────────────────────────────────────────────────────┐
// │ CE MODULE NE LIT PAS LES ÉMOTIONS. IL LIT DES INDICES ACOUSTIQUES.        │
// └──────────────────────────────────────────────────────────────────────────┘
//
// Ce que la mesure donne vraiment : une hauteur, une énergie, un débit, une
// irrégularité, une couleur spectrale. Ce que la littérature établit
// solidement, c'est que ces grandeurs suivent l'ACTIVATION — on parle plus
// haut, plus fort et plus vite quand on est activé, quelle qu'en soit la
// cause. Ce qu'elle n'établit PAS, c'est la valence : rien dans le signal ne
// distingue de façon fiable la joie de la colère, ni l'enthousiasme de la
// panique. Deux personnes activées pour des raisons opposées sonnent pareil.
//
// S'y ajoutent trois limites qu'aucun modèle ne lève :
//
//   - TOUT EST RELATIF À LA PERSONNE. Une voix grave n'est pas une voix
//     abattue ; un débit rapide n'est pas de l'agitation. Seul l'écart à SON
//     PROPRE ordinaire veut dire quelque chose — d'où l'étalon ci-dessous, et
//     le refus de répondre tant qu'il n'est pas constitué.
//   - TOUT EST RELATIF À LA SITUATION. Lire à voix haute, expliquer, plaisanter
//     et se disputer ont des prosodies différentes sans changement d'humeur.
//   - ET LA CULTURE, LA LANGUE, L'ÂGE, UN RHUME, UN MICRO MAL PLACÉ déplacent
//     tout autant ces grandeurs que n'importe quelle émotion.
//
// Conséquences tenues dans le CODE, pas seulement dans ce commentaire :
//
//	– aucune sortie ne dépasse `PlafondConfiance` ;
//	– sans étalon ni signal suffisant, l'état rendu est « indéterminé », et ce
//	  n'est pas un cas d'erreur mais le cas NORMAL des premières minutes ;
//	– chaque lecture transporte ce qui l'a produite (`Pourquoi`) et sa réserve
//	  (`Reserve`), pour qu'elles ne puissent pas être détachées du chiffre en
//	  aval ;
//	– les libellés sont des NOMS D'INDICES, pas des diagnostics.
//
// Ce module ne doit servir ni à évaluer quelqu'un, ni à décider quoi que ce
// soit le concernant. Il est fait pour qu'une personne observe sa propre voix,
// sur sa propre machine, et rien d'autre ne sort de la board.
package ser

import (
	"math"
	"sort"
)

// Traits : ce que le traitement du signal a effectivement mesuré sur la
// fenêtre écoulée. Rien d'interprété à ce stade.
type Traits struct {
	F0Median      float64 // Hz, sur les trames voisées
	F0Etendue     float64 // demi-tons (écart-type)
	Energie       float64 // RMS, 0..1
	EnergieVar    float64 // écart-type du RMS sur la fenêtre
	Debit         float64 // syllabes estimées par minute
	Jitter        float64 // %
	Shimmer       float64 // dB
	Centre        float64 // centre de gravité spectral, Hz
	Pente         float64 // pente spectrale, dB/kHz
	Platitude     float64 // platitude spectrale 0..1 — 1 = bruit large, 0 = son harmonique
	PartVoisee    float64 // proportion de trames voisées, 0..1
	TramesVoisees int     // combien de trames ont réellement porté de la voix
}

// L'INDÉTERMINÉ N'EST PAS UNE HUMEUR, C'EST UN DÉFAUT DE MESURE.
//
// Il l'était devenu par accident : quand aucune étiquette ne se détachait
// nettement, on rendait « indéterminé » — ce qui rangeait sur la même ligne
// « je n'entends rien d'exploitable » et « cette voix est simplement dans son
// ordinaire ». Les deux n'ont rien à voir, et la seconde a un nom : le calme.
//
// Désormais, `indetermine` signifie UNIQUEMENT qu'on ne peut pas mesurer, et
// le motif dit laquelle des trois causes :
//
//	MotifBruit      — le signal est là mais c'est du bruit, pas de la voix ;
//	MotifPeuDeVoix  — trop peu de trames voisées sur la fenêtre ;
//	MotifEtalonnage — on ne connaît pas encore l'ordinaire de cette personne.
//
// Ce sont trois énoncés sur le SIGNAL. Aucun ne dit quoi que ce soit sur qui
// parle, et c'est exactement ce qu'on veut : ne rien affirmer faute de mesure
// n'est pas la même chose que constater un état neutre.
const (
	MotifBruit      = "bruit"
	MotifPeuDeVoix  = "voix-insuffisante"
	MotifEtalonnage = "etalonnage"
)

// Les états nommés. Ce sont des ÉTIQUETTES D'INDICE : « tension » désigne un
// faisceau acoustique (hauteur haute, irrégularité, spectre brillant), pas un
// état intérieur constaté.
//
// LE CALME EST LE REPOS, et ce n'est pas une convention arbitraire : l'étalon
// apprend l'ordinaire de CETTE voix, donc une voix à son ordinaire est, par
// construction, au repos de cette personne. Quand rien ne dévie, la réponse
// juste est « calme » — pas « je ne sais pas ».
const (
	Indetermine = "indetermine"
	Calme       = "calm"
	Joie        = "joy"
	Tension     = "stress"
	Colere      = "anger"
	Fatigue     = "fatigue"
	Concentre   = "focus"
)

// Etats dans l'ordre d'affichage.
var Etats = []string{Calme, Joie, Tension, Colere, Fatigue, Concentre}

// Emoji par état — repris du cockpit, gardé ici pour que l'interface et l'API
// ne puissent pas diverger.
var Emoji = map[string]string{
	Calme: "😌", Joie: "😊", Tension: "😬", Colere: "😠",
	Fatigue: "😴", Concentre: "🤔", Indetermine: "…",
}

// PlafondConfiance : aucune lecture ne peut se dire plus sûre que cela.
//
// Ce n'est pas de la modestie décorative. Aucun classifieur prosodique, modèle
// appris compris, ne distingue de façon fiable la cause d'une activation à
// partir du seul signal. Laisser sortir 0,99 laisserait croire le contraire à
// qui lit le nombre sans lire cette page — et c'est toujours ce qui arrive.
const PlafondConfiance = 0.72

// Lecture : le résultat, avec ce qu'il faut pour ne pas le surinterpréter.
type Lecture struct {
	Etat string `json:"state"`
	// Motif : POURQUOI c'est indéterminé, quand ça l'est. Vide sinon. Il
	// distingue les trois causes possibles — bruit, pas assez de voix, étalon
	// incomplet — qui appellent trois gestes différents de la part de qui lit.
	Motif     string             `json:"motif,omitempty"`
	Confiance float64            `json:"confidence"`
	Indices   map[string]float64 `json:"indices"`
	Pourquoi  []string           `json:"pourquoi"`
	Reserve   string             `json:"reserve"`
	Etalonne  bool               `json:"etalonne"`
	// Reference : sur QUOI l'écart a été mesuré — « vous » ou « le groupe ».
	// Ça ne peut pas être implicite : lire « tension » sans savoir qu'on est
	// comparé à d'AUTRES voix, ce serait croire à une mesure personnelle.
	Reference  string  `json:"reference,omitempty"`
	Suffisant  bool    `json:"signal_suffisant"`
	Activation float64 `json:"activation"` // -1..+1, le seul axe solide
}

// LectureIndeterminee : la réponse quand on ne sait pas. Elle est NORMALE, et
// c'est pour cela qu'elle est construite ici plutôt qu'improvisée sur place :
// il ne doit exister qu'une seule façon de dire « je ne sais pas ».
func LectureIndeterminee(code, motif string, etalonne bool) Lecture {
	ind := make(map[string]float64, len(Etats))
	for _, e := range Etats {
		ind[e] = 0
	}
	return Lecture{
		Etat: Indetermine, Motif: code, Confiance: 0, Indices: ind,
		Pourquoi: []string{motif}, Reserve: Reserve, Etalonne: etalonne,
	}
}

// Reserve accompagne CHAQUE lecture. Elle voyage avec le chiffre parce qu'un
// chiffre voyage toujours plus loin que sa page d'explication.
const Reserve = "Indices acoustiques, pas un état intérieur constaté. " +
	"Relatifs à votre propre voix, à cette pièce et à ce moment. " +
	"Ne pas utiliser pour évaluer ou décider au sujet de quelqu'un."

// Classifieur : ce qui transforme des traits en lecture. L'interface existe
// pour que le moteur ne sache pas si derrière il y a dix lignes d'arithmétique
// ou un réseau — et pour qu'on puisse remplacer l'un par l'autre sans toucher
// au reste.
type Classifieur interface {
	Evalue(Traits) Lecture
	Nom() string
}

// ── L'ÉTALON PERSONNEL ─────────────────────────────────────────────────────
//
// SANS LUI, TOUT CE QUI PRÉCÈDE EST FAUX. Un seuil absolu sur la hauteur ou le
// débit compare des personnes entre elles, ce qui n'a pas de sens : une voix
// grave et lente n'est pas une voix fatiguée, c'est peut-être simplement cette
// voix-là. On apprend donc l'ordinaire de CE locuteur, et on ne lit que les
// écarts à cet ordinaire.
//
// Médiane et écart interquartile plutôt que moyenne et écart-type : quelques
// trames aberrantes — un saut d'octave, une porte qui claque — déplacent une
// moyenne et laissent une médiane tranquille.
type Etalon struct {
	minimum  int
	f0       []float64
	energie  []float64
	debit    []float64
	jitter   []float64
	centre   []float64
	capacite int
}

// DEUX SEUILS, ET C'EST LA CORRECTION DU DÉFAUT LE PLUS VISIBLE.
//
// Il n'y en avait qu'un — cent quatre-vingts observations, soit trois bonnes
// minutes de PAROLE effective, et bien davantage en temps réel. Pendant tout
// ce temps le module ne disait rien du tout, et l'on ne pouvait pas savoir
// s'il travaillait ou s'il était en panne. Un module muet trois minutes est un
// module qu'on referme.
//
// L'ordinaire d'une voix ne se découvre pourtant pas d'un coup : une
// quarantaine d'observations donnent déjà une médiane et un interquartile
// utilisables, grossiers mais réels. On répond donc à partir de là, EN LE
// DISANT (`Provisoire`), et la confiance est bridée tant que l'étalon n'est
// pas complet. Annoncer « provisoire » est honnête ; se taire trois minutes
// était seulement inutilisable.
const (
	MinimumEtalonProvisoire = 45
	MinimumEtalon           = 180
)

// PlafondProvisoire : tant que l'étalon n'est pas complet, la confiance ne
// dépasse pas ceci. Un ordinaire estimé sur quarante mesures est un ordinaire
// approximatif, et l'écart qu'on y lit l'est tout autant.
const PlafondProvisoire = 0.40

// NouvelEtalon garde au plus `capacite` observations glissantes.
func NouvelEtalon(capacite int) *Etalon {
	if capacite < MinimumEtalon {
		capacite = MinimumEtalon
	}
	return &Etalon{minimum: MinimumEtalon, capacite: capacite}
}

func pousse(s []float64, v float64, max int) []float64 {
	s = append(s, v)
	if len(s) > max {
		s = s[len(s)-max:]
	}
	return s
}

// Observe enregistre une fenêtre de voix dans l'ordinaire du locuteur.
// Les fenêtres SANS voix ne sont pas observées : le silence n'a pas de hauteur,
// et l'inclure abaisserait l'ordinaire de tout le monde.
func (e *Etalon) Observe(t Traits) {
	if t.TramesVoisees < 10 || t.F0Median <= 0 {
		return
	}
	e.f0 = pousse(e.f0, t.F0Median, e.capacite)
	e.energie = pousse(e.energie, t.Energie, e.capacite)
	e.jitter = pousse(e.jitter, t.Jitter, e.capacite)
	e.centre = pousse(e.centre, t.Centre, e.capacite)
	if t.Debit > 0 {
		e.debit = pousse(e.debit, t.Debit, e.capacite)
	}
}

// Pret : l'étalon est-il COMPLET ?
func (e *Etalon) Pret() bool { return len(e.f0) >= e.minimum }

// Utilisable : a-t-on de quoi répondre, même grossièrement ?
func (e *Etalon) Utilisable() bool { return len(e.f0) >= MinimumEtalonProvisoire }

// Progression : 0..1, de quoi afficher une barre honnête pendant l'étalonnage
// plutôt que de laisser croire à une panne.
func (e *Etalon) Progression() float64 {
	p := float64(len(e.f0)) / float64(e.minimum)
	if p > 1 {
		return 1
	}
	return p
}

// ecart rend l'écart robuste d'une valeur à l'ordinaire, en « interquartiles ».
// Zéro quand on ne sait pas — jamais une valeur inventée.
func ecart(serie []float64, v float64) float64 {
	if len(serie) < 8 {
		return 0
	}
	c := append([]float64(nil), serie...)
	sort.Float64s(c)
	med := c[len(c)/2]
	q1, q3 := c[len(c)/4], c[3*len(c)/4]
	iq := q3 - q1
	if iq <= 1e-9 {
		return 0
	}
	z := (v - med) / iq
	// On borne : au-delà de trois interquartiles, la valeur est aberrante et
	// sa magnitude exacte ne veut plus rien dire. La laisser filer donnerait
	// un indice écrasant à une seule mesure douteuse.
	return math.Max(-3, math.Min(3, z))
}

// Ecarts : la position des traits courants dans l'ordinaire du locuteur.
func (e *Etalon) Ecarts(t Traits) map[string]float64 {
	return map[string]float64{
		"f0":      ecart(e.f0, t.F0Median),
		"energie": ecart(e.energie, t.Energie),
		"debit":   ecart(e.debit, t.Debit),
		"jitter":  ecart(e.jitter, t.Jitter),
		"centre":  ecart(e.centre, t.Centre),
	}
}
