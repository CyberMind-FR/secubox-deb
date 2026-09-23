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
	Reference string `json:"reference,omitempty"`
	// Fiabilite : 0 à 1, à quel point la référence est connue. REMPLACE le
	// pourcentage d'étalonnage, qui promettait un achèvement — on ne « finit »
	// jamais de connaître une voix, on la connaît de mieux en mieux.
	Fiabilite    float64 `json:"fiabilite"`
	Observations int     `json:"observations"`
	Suffisant    bool    `json:"signal_suffisant"`
	Activation   float64 `json:"activation"` // -1..+1, le seul axe solide
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

// ── L'ORDINAIRE D'UNE PERSONNE ─────────────────────────────────────────────
//
// SANS LUI, TOUT CE QUI PRÉCÈDE EST FAUX. Un seuil absolu sur la hauteur ou le
// débit compare des personnes entre elles, ce qui n'a pas de sens : une voix
// grave et lente n'est pas une voix fatiguée, c'est peut-être simplement cette
// voix-là. On apprend donc l'ordinaire de CE locuteur, et on ne lit que les
// écarts à cet ordinaire.
//
// L'IMPLÉMENTATION VIT DANS reference.go, et elle a remplacé un étalon à
// SEUIL qui accumulait cent quatre-vingts mesures avant de débloquer une
// réponse. Ce seuil n'aboutissait pas — une mesure par fenêtre DE VOIX fait
// dix minutes d'usage réel, et un rechargement de page repartait de zéro — et
// il exprimait mal l'incertitude : il n'existe aucun instant où l'on
// « connaît » une voix, on la connaît de mieux en mieux.
//
// Voir `Reference` et `Suivi`.

// ecart rend l'écart robuste d'une valeur à une série, en « interquartiles ».
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
	return math.Max(-3, math.Min(3, z))
}
