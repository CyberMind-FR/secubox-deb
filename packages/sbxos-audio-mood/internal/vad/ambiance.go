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
	// Dominante : la pièce pèse plus que la voix. C'est un CONSTAT, pas un
	// ordre — la décision d'écarter la fenêtre est prise dans `ser`, avec le
	// reste des traits sous les yeux. Le commentaire disait « la fenêtre doit
	// être écartée », ce qu'aucun code ne faisait (#1333).
	Dominante bool `json:"dominante"`
	Presente  bool `json:"presente"` // assez nette pour être signalée
}

// SeuilPulsation : en-dessous, la périodicité n'est pas plus nette que celle
// d'une conversation ordinaire et ne prouve rien.
const SeuilPulsation = 0.34

// SeuilRessaut : de combien un pic doit remonter au-dessus du creux qui le
// précède. Une corrélation qui décroît sans jamais remonter n'a pas de période,
// si haute soit-elle aux petits décalages (#1705).
const SeuilRessaut = 0.12

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
}

// pulsation cherche un tempo sur les trames non masquées : le PIC
// d'autocorrélation, et non son maximum (voir plus bas).
func (e *Ecouteur) pulsation(masque []bool) (bpm, score float64, ok bool) {
	n := len(e.env)
	nSansParole := 0
	moy := 0.0
	for i := 0; i < n; i++ {
		if !masque[i] {
			moy += e.env[i]
			nSansParole++
		}
	}
	if nSansParole < 32 {
		return 0, 0, false
	}
	// Centrer : l'autocorrélation d'un signal non centré est dominée par sa
	// moyenne, et l'on trouverait une « périodicité » partout.
	moy /= float64(nSansParole)
	x := make([]float64, n)
	var energie float64
	for i := 0; i < n; i++ {
		if !masque[i] {
			x[i] = e.env[i] - moy
			energie += x[i] * x[i]
		}
	}
	if energie <= 1e-12 {
		return 0, 0, false
	}

	// ── UN TEMPO EST UN PIC, PAS UN MAXIMUM (#1705) ──────────────────────
	//
	// On retenait le décalage de corrélation MAXIMALE dans la plage. Or un
	// signal lisse — une ventilation, un fond qui ondule lentement, ou le fond
	// « tenu » pendant qu'on parle — est toujours le plus corrélé au plus petit
	// décalage : τ = 31 trames, soit 181,5 BPM, à chaque fenêtre, avec une
	// « netteté » de 0,8. Le tempo affiché ne bougeait donc jamais hors
	// musique, et une ambiance imaginaire entrait dans le verdict.
	//
	// Une périodicité, c'est une corrélation qui RETOMBE puis REMONTE à la
	// période. On exige donc un pic local qui ressorte de son creux ; parmi les
	// pics nets, le plus petit décalage dont la hauteur approche celle du
	// meilleur (les multiples de la période — le tempo moitié — sont aussi des
	// pics) ; et une interpolation parabolique, sans quoi le haut de la plage
	// avance par marches de six BPM.
	tauMin := int(60.0 / BPMMax / e.pas)
	tauMax := int(60.0 / BPMMin / e.pas)
	if tauMin < 2 {
		tauMin = 2
	}
	if tauMax >= n/2 {
		tauMax = n/2 - 1
	}
	if tauMin >= tauMax {
		return 0, 0, false
	}
	// r[τ] pour τ = 1 … tauMax+1 : les voisins servent au pic et au creux.
	r := make([]float64, tauMax+2)
	for tau := 1; tau <= tauMax+1 && tau < n; tau++ {
		var s, e1, e2 float64
		paires := 0
		for i := 0; i+tau < n; i++ {
			if masque[i] || masque[i+tau] {
				continue
			}
			s += x[i] * x[i+tau]
			e1 += x[i] * x[i]
			e2 += x[i+tau] * x[i+tau]
			paires++
		}
		if paires < minPaires {
			continue // pas assez de fond à ce décalage : on ne sait pas
		}
		// Normalisé par les énergies des DEUX segments comparés : sans cela,
		// les petits décalages gagnent, puisqu'ils comparent plus de points.
		if e1 > 1e-12 && e2 > 1e-12 {
			r[tau] = s / math.Sqrt(e1*e2)
		}
	}
	type pic struct {
		tau     int
		hauteur float64
	}
	var pics []pic
	creux := r[1]
	for tau := 2; tau <= tauMax; tau++ {
		if r[tau] < creux {
			creux = r[tau]
		}
		if tau < tauMin || !(r[tau] > r[tau-1] && r[tau] >= r[tau+1]) {
			continue
		}
		if r[tau] >= SeuilPulsation && r[tau]-creux >= SeuilRessaut {
			pics = append(pics, pic{tau, r[tau]})
		}
	}
	if len(pics) == 0 {
		return 0, 0, false
	}
	meilleur := pics[0]
	for _, p := range pics {
		if p.hauteur > meilleur.hauteur {
			meilleur = p
		}
	}
	for _, p := range pics {
		if p.hauteur >= 0.9*meilleur.hauteur {
			meilleur = p
			break
		}
	}
	score = meilleur.hauteur
	tauFin := float64(meilleur.tau)
	if a, b, c := r[meilleur.tau-1], r[meilleur.tau], r[meilleur.tau+1]; a-2*b+c < 0 {
		tauFin += 0.5 * (a - c) / (a - 2*b + c)
	}

	bpm = 60.0 / (tauFin * e.pas)
	return bpm, score, true
}

// pauseMin : une pause plus courte (≈ 250 ms) est un creux ENTRE SYLLABES,
// pas un silence de la pièce. Le VAD découpe une phrase : ces creux ne sont pas
// marqués « parole », et leur énergie — celle de la voix — imposait au fond le
// rythme syllabique. Un intervalle entre deux coups de grosse caisse, que le VAD
// prend parfois pour de la parole, dure davantage et reste (#1705).
const pauseMin = 24

// masqueParole : vrai pour une trame de parole ou d'une pause trop courte.
func (e *Ecouteur) masqueParole() []bool {
	n := len(e.marques)
	m := make([]bool, n)
	for i := 0; i < n; {
		if e.marques[i] {
			m[i] = true
			i++
			continue
		}
		j := i
		for j < n && !e.marques[j] {
			j++
		}
		// Pause [i, j) : courte ET encadrée de parole → creux de syllabe.
		if j-i < pauseMin && i > 0 && j < n {
			for k := i; k < j; k++ {
				m[k] = true
			}
		}
		i = j
	}
	return m
}

// minPaires : en-dessous, un décalage n'a pas assez de paires de trames sans
// parole pour dire quoi que ce soit (≈ 0,7 s d'écoute).
const minPaires = 64

// Analyse cherche une pulsation dans l'enveloppe de la pièce.
//
// DEUX LECTURES, DANS CET ORDRE (#1705).
//
//  1. L'ENVELOPPE COMPLÈTE. Sur la vraie chaîne, le VAD prend chaque coup de
//     grosse caisse pour de la parole : ne lire que les trames « sans parole »
//     revenait à ne garder que la traîne de chaque coup, et le pic tombait à
//     côté (108 BPM pour 128, avec une netteté de 0,9). Une voix réelle, elle,
//     n'a pas de période nette dans la plage : sur l'enveloppe entière, seule
//     la musique fait un pic.
//  2. À DÉFAUT, LES SEULES PAUSES. Quand la parole est un bloc d'énergie qui
//     écrase la musique, l'enveloppe complète n'a plus de pic ; entre les
//     phrases, la pulsation reste lisible. Les paires de trames sont alors
//     toutes deux hors parole — rien n'est plus « tenu » ni inventé — et les
//     pauses trop courtes, creux entre syllabes, sont écartées.
func (e *Ecouteur) Analyse() Ambiance {
	n := len(e.env)
	if n < 32 {
		return Ambiance{}
	}
	bpm, score, ok := e.pulsation(make([]bool, n))
	if !ok {
		bpm, score, ok = e.pulsation(e.masqueParole())
	}
	if !ok {
		return Ambiance{}
	}

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
