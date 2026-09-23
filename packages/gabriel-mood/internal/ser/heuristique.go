// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package ser

import (
	"fmt"
	"math"
	"sort"
)

// Heuristique : le classifieur par défaut, et il est VOLONTAIREMENT simple.
//
// POURQUOI PAS UN MODÈLE APPRIS PAR DÉFAUT. Un réseau entraîné sur un corpus
// d'acteurs — c'est ce dont on dispose publiquement — apprend à reconnaître de
// l'émotion JOUÉE, articulée pour être reconnue. Il rend des probabilités
// élevées et bien séparées sur de la parole spontanée où elles n'ont aucun
// fondement, et sa confiance est d'autant plus trompeuse qu'elle est précise.
// Une règle qu'on peut lire, qui dit sur quoi elle s'appuie et plafonne sa
// propre confiance, est ici plus honnête qu'un modèle qu'on ne peut pas
// interroger. Le chemin ONNX reste ouvert (cf. onnx.go) pour qui a un modèle
// dont il connaît le corpus.
//
// COMMENT ELLE PROCÈDE. Deux axes, et le second est faible — on le dit.
//
//	ACTIVATION (solide) : hauteur, énergie, débit et brillance montent
//	ensemble quand on est activé. C'est la régularité la mieux établie de la
//	prosodie, et c'est à peu près la seule.
//
//	TENUE (faible) : régularité de la voix (jitter, shimmer), étendue
//	mélodique. Une voix activée ET irrégulière ET brillante évoque la tension
//	plutôt que la joie ; une voix peu activée ET irrégulière évoque la
//	fatigue plutôt que le calme. « Évoque » est le mot juste : ces liens sont
//	statistiques, faibles, et dépendants de la personne.
//
// Ce qui en sort n'est pas une probabilité au sens d'un modèle : c'est un
// partage d'affinité entre six étiquettes, normalisé pour sommer à un parce
// que l'affichage le demande. On ne prétend pas mesurer une vraisemblance.
type Heuristique struct {
	etalon *Etalon
}

// NouvelleHeuristique lie le classifieur à l'étalon du locuteur. Sans étalon,
// il refuse de répondre — c'est le point le plus important de ce fichier.
func NouvelleHeuristique(e *Etalon) *Heuristique { return &Heuristique{etalon: e} }

func (h *Heuristique) Nom() string { return "heuristique-prosodique-v1" }

// MinTramesVoisees : en-dessous, la fenêtre ne contient pas assez de voix pour
// qu'une moyenne veuille dire quoi que ce soit.
const MinTramesVoisees = 25

// Evalue rend la lecture des traits courants.
func (h *Heuristique) Evalue(t Traits) Lecture {
	etalonne := h.etalon != nil && h.etalon.Pret()
	if t.TramesVoisees < MinTramesVoisees {
		return LectureIndeterminee(
			fmt.Sprintf("pas assez de voix sur la fenêtre (%d trames voisées, il en faut %d)",
				t.TramesVoisees, MinTramesVoisees), etalonne)
	}
	if !etalonne {
		p := 0.0
		if h.etalon != nil {
			p = h.etalon.Progression()
		}
		return LectureIndeterminee(
			fmt.Sprintf("étalonnage en cours (%.0f %%) : sans votre ordinaire, "+
				"un écart ne veut rien dire", p*100), false)
	}

	e := h.etalon.Ecarts(t)
	var pourquoi []string
	dire := func(f string, a ...any) { pourquoi = append(pourquoi, fmt.Sprintf(f, a...)) }

	// ── AXE 1 : ACTIVATION ────────────────────────────────────────────────
	// Moyenne pondérée des écarts qui montent ensemble. Les poids disent
	// simplement lesquels sont les plus robustes : l'énergie et la hauteur
	// avant le débit, qui dépend beaucoup de ce qu'on est en train de dire.
	activation := 0.35*e["f0"] + 0.35*e["energie"] + 0.20*e["debit"] + 0.10*e["centre"]
	activation = math.Max(-3, math.Min(3, activation)) / 3 // -1..+1
	switch {
	case activation > 0.30:
		dire("voix plus haute et plus forte que votre ordinaire (activation %+.2f)", activation)
	case activation < -0.30:
		dire("voix plus basse et plus posée que votre ordinaire (activation %+.2f)", activation)
	default:
		dire("voix proche de votre ordinaire (activation %+.2f)", activation)
	}

	// ── AXE 2 : TENUE ─────────────────────────────────────────────────────
	// Irrégularité, en interquartiles pour le jitter et en valeur brute
	// bornée pour le shimmer (dont on n'a pas d'étalon — il dépend moins de la
	// personne que du placement du micro, qu'on suppose constant).
	irregularite := 0.6*e["jitter"] + 0.4*math.Max(-3, math.Min(3, (t.Shimmer-0.5)/0.5))
	irregularite = math.Max(-3, math.Min(3, irregularite)) / 3
	if irregularite > 0.30 {
		dire("voix plus irrégulière que d'habitude (jitter %.2f %%, shimmer %.2f dB)",
			t.Jitter, t.Shimmer)
	}
	// Étendue mélodique : une voix monocorde et une voix ample ne se lisent
	// pas pareil à activation égale. Deux demi-tons est une parole plate,
	// six une parole animée.
	melodie := math.Max(-1, math.Min(1, (t.F0Etendue-4)/3))
	if melodie < -0.4 {
		dire("intonation plate (%.1f demi-tons)", t.F0Etendue)
	} else if melodie > 0.4 {
		dire("intonation ample (%.1f demi-tons)", t.F0Etendue)
	}

	// ── AFFINITÉS ─────────────────────────────────────────────────────────
	// Chaque étiquette est une position dans le plan (activation, tenue). On
	// mesure une proximité, pas une vraisemblance.
	score := map[string]float64{
		// calme : peu activé, régulier, mélodie moyenne
		Calme: aff(activation, -0.25, 0.55) * aff(irregularite, -0.4, 0.8),
		// joie : activé, ample, plutôt régulier
		Joie: aff(activation, 0.55, 0.55) * aff(irregularite, -0.2, 0.9) * aff(melodie, 0.6, 0.8),
		// tension : activé ET irrégulier ET brillant, mélodie resserrée
		Tension: aff(activation, 0.45, 0.6) * aff(irregularite, 0.6, 0.8) * aff(melodie, -0.2, 1.0),
		// colère : très activé, très fort, brillant et dur
		Colere: aff(activation, 0.85, 0.5) * aff(e["energie"]/3, 0.7, 0.6) * aff(irregularite, 0.5, 1.0),
		// fatigue : peu activé, irrégulier, mélodie plate, spectre qui s'affaisse
		Fatigue: aff(activation, -0.55, 0.5) * aff(irregularite, 0.4, 0.9) * aff(melodie, -0.6, 0.9),
		// concentration : peu activé, très régulier, débit modéré, plat
		Concentre: aff(activation, -0.15, 0.5) * aff(irregularite, -0.5, 0.7) *
			aff(melodie, -0.4, 0.9) * aff(e["debit"]/3, -0.1, 0.8),
	}
	if t.Pente < -12 && score[Fatigue] > 0 {
		// Un spectre qui s'affaisse fortement dans les aigus accompagne la
		// voix relâchée. Indice faible : on l'ajoute, on ne décide pas avec.
		score[Fatigue] *= 1.2
		dire("spectre affaissé dans les aigus (%.1f dB/kHz)", t.Pente)
	}

	indices := normalise(score)

	// ── L'ÉTAT RETENU, ET SA CONFIANCE ────────────────────────────────────
	tete, second := deuxPremiers(indices)
	// La confiance tient à l'ÉCART entre les deux premiers, pas à la valeur du
	// premier : six étiquettes à 0,17 chacune font un premier à 0,18 qui ne
	// veut rien dire. Un écart franc, lui, dit qu'une lecture se détache.
	conf := (indices[tete] - indices[second]) * 2
	// Et elle est rabotée par la qualité du signal : une fenêtre à moitié
	// muette ne peut pas fonder une lecture assurée.
	conf *= math.Min(1, t.PartVoisee/0.5)
	conf = math.Max(0, math.Min(PlafondConfiance, conf))

	if conf < 0.15 {
		l := LectureIndeterminee("aucune lecture ne se détache nettement des autres", true)
		l.Indices, l.Activation = indices, activation
		l.Suffisant = true
		l.Pourquoi = append(l.Pourquoi, pourquoi...)
		return l
	}
	return Lecture{
		Etat: tete, Confiance: arrondi(conf, 3), Indices: indices,
		Pourquoi: pourquoi, Reserve: Reserve, Etalonne: true,
		Suffisant: true, Activation: arrondi(activation, 3),
	}
}

// aff : affinité gaussienne d'une valeur à une position attendue. Largeur
// généreuse — on cherche des tendances, pas des frontières.
func aff(v, centre, largeur float64) float64 {
	d := (v - centre) / largeur
	return math.Exp(-0.5 * d * d)
}

// normalise ramène les affinités à une somme de un. C'est une commodité
// d'affichage, PAS une loi de probabilité : la somme vaut un parce qu'une
// jauge a besoin qu'elle vaille un.
func normalise(m map[string]float64) map[string]float64 {
	somme := 0.0
	for _, v := range m {
		somme += v
	}
	out := make(map[string]float64, len(m))
	if somme <= 0 {
		part := 1.0 / float64(len(m))
		for k := range m {
			out[k] = arrondi(part, 3)
		}
		return out
	}
	for k, v := range m {
		out[k] = arrondi(v/somme, 3)
	}
	return out
}

func deuxPremiers(m map[string]float64) (string, string) {
	type kv struct {
		k string
		v float64
	}
	l := make([]kv, 0, len(m))
	for k, v := range m {
		l = append(l, kv{k, v})
	}
	// Tri stable par valeur puis par nom : à égalité, l'état retenu ne doit pas
	// dépendre de l'ordre de parcours d'une map, qui est aléatoire en Go.
	sort.Slice(l, func(i, j int) bool {
		if l[i].v != l[j].v {
			return l[i].v > l[j].v
		}
		return l[i].k < l[j].k
	})
	if len(l) < 2 {
		return l[0].k, l[0].k
	}
	return l[0].k, l[1].k
}

func arrondi(v float64, d int) float64 {
	p := math.Pow(10, float64(d))
	return math.Round(v*p) / p
}
