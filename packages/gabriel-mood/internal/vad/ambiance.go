// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package vad

import "math"

// L'AMBIANCE : ce qui joue dans la pièce, et ce que ça fait à la mesure.
//
// ── POURQUOI ÇA COMPTE, ET PAS QU'UN PEU ───────────────────────────────────
//
// De la musique dans la pièce ne se contente pas d'ajouter du bruit : elle
// ajoute du bruit HARMONIQUE ET PÉRIODIQUE, c'est-à-dire exactement ce qu'on
// cherche quand on cherche une voix. Le VAD la prend pour de la parole — elle
// occupe les mêmes sous-bandes — et YIN lui trouve une hauteur, parce qu'elle
// en a une. On se retrouve alors à mesurer la hauteur d'une guitare et à
// l'attribuer à quelqu'un.
//
// Le plancher de bruit appris ne suffit pas : il apprend un bourdonnement
// CONSTANT, pas une musique qui module. C'est justement la modulation qui la
// trahit.
//
// ── COMMENT ON LA REPÈRE ───────────────────────────────────────────────────
//
// Par le TEMPO. Une musique a une pulsation régulière ; une conversation a un
// rythme syllabique, plus rapide et beaucoup moins régulier. On suit donc
// l'enveloppe d'énergie sur plusieurs secondes et l'on cherche une périodicité
// dans la plage des tempos usuels (60 à 180 battements par minute). Une
// périodicité NETTE à cet endroit, c'est de la musique ou une machine ; la
// parole n'en produit pas, sa régularité est bien plus lâche.
//
// ── ET ENSUITE : ÉVACUER, OU BIEN CONTEXTUALISER ───────────────────────────
//
// Les deux, selon la force. Une ambiance discrète est signalée comme CONTEXTE
// — elle explique qu'une voix soit plus forte, on parle plus haut quand il y a
// du fond, et c'est une information utile plutôt qu'une gêne. Une ambiance
// dominante fait ÉCARTER la fenêtre : ce qu'on mesurerait alors ne serait plus
// une personne.
//
// Ce n'est pas une séparation de sources : on ne retire pas la musique du
// signal, on refuse de faire semblant de ne pas l'entendre.

// Plage des tempos qu'on cherche. En-deçà de 60, on confondrait avec la
// respiration et les pauses ; au-delà de 180, avec le rythme syllabique lui-même.
const (
	BPMMin = 60.0
	BPMMax = 180.0
)

// Ambiance : ce qu'on a compris de la pièce.
type Ambiance struct {
	BPM       float64 `json:"bpm"`       // 0 si aucune pulsation nette
	Pulsation float64 `json:"pulsation"` // 0..1, netteté de la périodicité
	Part      float64 `json:"part"`      // 0..1, poids de l'ambiance dans l'énergie
	Dominante bool    `json:"dominante"` // la fenêtre doit être écartée
	Presente  bool    `json:"presente"`  // assez nette pour être signalée
}

// SeuilPulsation : en-dessous, la périodicité n'est pas plus nette que celle
// d'une conversation ordinaire et ne prouve rien.
const SeuilPulsation = 0.34

// SeuilDominante : au-dessus, la pièce couvre la voix et ce qu'on mesurerait
// ne serait plus une personne.
//
// 0,55 sur la NOUVELLE définition — les deux moyennes comparées entre elles —
// veut dire « le fond est un peu plus fort que la voix ». C'est le bon endroit :
// en-dessous, une voix reste mesurable dans une pièce animée, et l'ambiance
// n'est qu'un CONTEXTE qui explique qu'on parle plus haut.
const SeuilDominante = 0.55

// Ecouteur suit l'enveloppe d'énergie pour y chercher une pulsation.
//
// Il travaille sur l'ÉNERGIE HORS VOIX autant que possible : l'enveloppe de la
// parole a son propre rythme, et la mélanger à celle de la musique brouillerait
// précisément ce qu'on essaie de séparer.
type Ecouteur struct {
	env      []float64 // enveloppe d'énergie, un point par trame
	marques  []bool    // cette trame portait-elle de la parole ?
	fond     []float64 // énergie des trames SANS parole
	pas      float64   // durée d'une trame, en secondes
	capacite int
}

// NouvelEcouteur : `pasSecondes` est la durée d'une trame (le pas d'analyse),
// `duree` la fenêtre d'observation. Six secondes portent six battements à
// 60 BPM — le minimum pour qu'une périodicité veuille dire quelque chose.
func NouvelEcouteur(pasSecondes, duree float64) *Ecouteur {
	n := int(duree / pasSecondes)
	if n < 32 {
		n = 32
	}
	return &Ecouteur{pas: pasSecondes, capacite: n}
}

// Observe ajoute une trame.
func (e *Ecouteur) Observe(rms float64, parole bool) {
	e.env = append(e.env, rms)
	e.marques = append(e.marques, parole)
	if len(e.env) > e.capacite {
		e.env = e.env[1:]
		e.marques = e.marques[1:]
	}
	if !parole {
		e.fond = append(e.fond, rms)
	} else {
		// On garde la place, mais sans valeur : l'énergie de la parole
		// masquerait celle du fond. Interpoler serait inventer ; on répète le
		// dernier fond connu, qui est l'hypothèse la plus sobre.
		v := 0.0
		if len(e.fond) > 0 {
			v = e.fond[len(e.fond)-1]
		}
		e.fond = append(e.fond, v)
	}
	if len(e.fond) > e.capacite {
		e.fond = e.fond[1:]
	}
}

// Analyse cherche une pulsation dans l'enveloppe de FOND.
func (e *Ecouteur) Analyse() Ambiance {
	n := len(e.fond)
	if n < 32 {
		return Ambiance{}
	}
	// Centrer : l'autocorrélation d'un signal non centré est dominée par sa
	// moyenne, et l'on trouverait une « périodicité » partout.
	moy := 0.0
	for _, v := range e.fond {
		moy += v
	}
	moy /= float64(n)
	x := make([]float64, n)
	var energie float64
	for i, v := range e.fond {
		x[i] = v - moy
		energie += x[i] * x[i]
	}
	if energie <= 1e-12 {
		return Ambiance{}
	}

	tauMin := int(60.0 / BPMMax / e.pas)
	tauMax := int(60.0 / BPMMin / e.pas)
	if tauMin < 2 {
		tauMin = 2
	}
	if tauMax >= n/2 {
		tauMax = n/2 - 1
	}
	if tauMin >= tauMax {
		return Ambiance{}
	}

	meilleur, score := 0, 0.0
	for tau := tauMin; tau <= tauMax; tau++ {
		var s, norme float64
		for i := 0; i+tau < n; i++ {
			s += x[i] * x[i+tau]
			norme += x[i] * x[i]
		}
		if norme <= 1e-12 {
			continue
		}
		// Normalisé par l'énergie de la portion comparée : sans cela, les
		// petits décalages gagnent toujours, puisqu'ils comparent plus de
		// points.
		r := s / norme
		if r > score {
			meilleur, score = tau, r
		}
	}
	if meilleur == 0 || score < SeuilPulsation {
		return Ambiance{}
	}

	bpm := 60.0 / (float64(meilleur) * e.pas)
	// ── LA PART DE L'AMBIANCE, ET J'AI DÛ LA REFAIRE ─────────────────────
	//
	// Elle rapportait l'énergie de fond à l'énergie TOTALE. C'était faux, et
	// faux dans le sens qui fait mal : pendant les pauses, `fond` vaut `env`,
	// si bien que ces trames comptaient 1:1 des deux côtés. Quelqu'un qui parle
	// un cinquième du temps — ce qui est le cas de tout le monde — voyait donc
	// sa « part d'ambiance » passer 0,55 dès que la pièce atteignait le
	// cinquième de sa voix. Résultat : le BPM EFFAÇAIT LES ÉMOTIONS, sur un
	// simple ventilateur.
	//
	// La question utile n'est pas « quelle fraction de l'énergie est de
	// l'ambiance » mais « la pièce couvre-t-elle la voix ». On compare donc les
	// deux MOYENNES, sur leurs trames respectives : la part vaut un demi quand
	// elles s'égalent, ce qui est exactement le point où la mesure cesse d'être
	// une mesure de quelqu'un.
	var sommeFond, sommeVoix float64
	var nFond, nVoix int
	for i := range e.env {
		if i < len(e.marques) && e.marques[i] {
			sommeVoix += e.env[i]
			nVoix++
		} else {
			sommeFond += e.env[i]
			nFond++
		}
	}
	part := 0.0
	if nFond > 0 {
		moyFond := sommeFond / float64(nFond)
		moyVoix := 0.0
		if nVoix > 0 {
			moyVoix = sommeVoix / float64(nVoix)
		}
		if moyFond+moyVoix > 1e-12 {
			part = moyFond / (moyFond + moyVoix)
		}
	}
	return Ambiance{
		BPM: math.Round(bpm*10) / 10, Pulsation: math.Round(score*100) / 100,
		Part: math.Round(part*100) / 100, Presente: true,
		Dominante: part > SeuilDominante,
	}
}
