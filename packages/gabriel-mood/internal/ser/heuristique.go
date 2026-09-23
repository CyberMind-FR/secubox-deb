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
	ref     *Reference
	partage *EtalonPartage
}

// NouvelleHeuristique lie le classifieur à l'étalon du locuteur. Sans étalon,
// il refuse de répondre — c'est le point le plus important de ce fichier.
func NouvelleHeuristique(r *Reference) *Heuristique { return &Heuristique{ref: r} }

// AvecEtalonPartage branche l'ordinaire du groupe comme référence de SECOURS.
// Il ne sert QUE tant que l'ordinaire personnel n'est pas utilisable, et la
// lecture le dit (`Reference: "groupe"`).
func (h *Heuristique) AvecEtalonPartage(p *EtalonPartage) *Heuristique {
	h.partage = p
	return h
}

// PlafondGroupe : comparé à d'AUTRES voix, on se croit encore moins que sur un
// étalon personnel provisoire. Ce qu'on mesure alors est en partie une
// différence entre personnes, pas seulement un écart à soi-même.
const PlafondGroupe = 0.30

func (h *Heuristique) Nom() string { return "heuristique-prosodique-v1" }

// MinTramesVoisees : en-dessous, la fenêtre ne contient pas assez de voix pour
// qu'une moyenne veuille dire quoi que ce soit.
const MinTramesVoisees = 25

// SeuilBruit : au-delà de cette platitude spectrale moyenne, ce qu'on entend
// est un bruit large et non une voix. Une voyelle est harmonique — son spectre
// a des pics — et se situe bien en-dessous de 0,4.
const SeuilBruit = 0.55

// SeuilAmbiance : au-delà, ce qui joue dans la pièce pèse plus que la voix.
// Même valeur que le seuil de dominance du détecteur de tempo — c'est la même
// décision, prise au même endroit conceptuel.
const SeuilAmbiance = 0.55

// PartVoiseeMin : en-dessous, la fenêtre est surtout du silence ou du bruit.
const PartVoiseeMin = 0.12

// Evalue rend la lecture des traits courants.
func (h *Heuristique) Evalue(t Traits) Lecture {
	// PLUS DE SEUIL : une référence est vivante dès sa première mesure, et sa
	// FIABILITÉ dit à quel point on peut s'y fier. Ce qui était un mur est
	// devenu une pente — et le module répond pendant la montée.
	vivante := h.ref != nil && h.ref.Vivante()
	fiab := 0.0
	if h.ref != nil {
		fiab = h.ref.Fiabilite()
	}

	// ── D'ABORD : PEUT-ON MESURER ? ──────────────────────────────────────
	// Ces trois refus portent sur le SIGNAL, jamais sur la personne. Les
	// confondre avec « humeur neutre » était le défaut de la version
	// précédente : elle rangeait sur la même ligne « je n'entends rien
	// d'exploitable » et « cette voix est dans son ordinaire ».
	if t.TramesVoisees < MinTramesVoisees || t.PartVoisee < PartVoiseeMin {
		return LectureIndeterminee(MotifPeuDeVoix,
			fmt.Sprintf("pas assez de voix sur la fenêtre (%d trames voisées, %.0f %% de la durée)",
				t.TramesVoisees, t.PartVoisee*100), vivante)
	}
	if t.AmbiancePart > SeuilAmbiance {
		return LectureIndeterminee(MotifAmbiance,
			fmt.Sprintf("ce qui joue dans la pièce domine (%.0f %% de l'énergie%s) : "+
				"ce qu'on mesurerait ne serait plus une personne",
				t.AmbiancePart*100,
				map[bool]string{true: fmt.Sprintf(", tempo %.0f BPM", t.AmbianceBPM)}[t.AmbianceBPM > 0]),
			vivante)
	}
	if t.Platitude > SeuilBruit {
		return LectureIndeterminee(MotifBruit,
			fmt.Sprintf("spectre plat (%.2f) : c'est du bruit, pas une voix — "+
				"approchez le micro ou coupez ce qui souffle", t.Platitude), vivante)
	}
	reference := "vous"
	var e map[string]float64
	switch {
	case vivante:
		e = h.ref.Ecarts(t)
		// MÉLANGE AVEC LE GROUPE TANT QU'ON SE CONNAÎT MAL. Ce n'est pas un
		// remplacement mais une PONDÉRATION : au début la référence du groupe
		// pèse lourd, et sa part fond à mesure que la vôtre se précise. Aucun
		// basculement brusque, aucun instant où la lecture change de nature
		// sans prévenir.
		if g := h.partage.Ecarts(t); g != nil && fiab < 0.75 {
			for k, v := range e {
				e[k] = fiab*v + (1-fiab)*g[k]
			}
			reference = "mixte"
		}
	case h.partage.Utilisable():
		e = h.partage.Ecarts(t)
		reference = "groupe"
	default:
		// Premier instant d'une première session, personne d'autre en ligne :
		// il n'y a littéralement aucune mesure. Ce n'est plus un étalonnage
		// qui dure, c'est une fenêtre qui n'a encore rien porté.
		return LectureIndeterminee(MotifEtalonnage,
			"première mesure en cours : aucune voix encore observée", false)
	}
	var pourquoi []string
	dire := func(f string, a ...any) { pourquoi = append(pourquoi, fmt.Sprintf(f, a...)) }

	// ── AXE 1 : ACTIVATION ────────────────────────────────────────────────
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
	if t.AmbianceBPM > 0 {
		// CONTEXTE, PAS GÊNE. On parle plus haut quand il y a du fond : le
		// dire évite de lire comme de l'activation ce qui n'est qu'une pièce
		// bruyante.
		dire("ambiance à %.0f BPM dans la pièce (%.0f %% de l'énergie) — "+
			"on parle plus haut quand il y a du fond", t.AmbianceBPM, t.AmbiancePart*100)
	}

	// ── AXE 2 : TENUE ─────────────────────────────────────────────────────
	irregularite := 0.6*e["jitter"] + 0.4*math.Max(-3, math.Min(3, (t.Shimmer-0.5)/0.5))
	irregularite = math.Max(-3, math.Min(3, irregularite)) / 3
	if irregularite > 0.30 {
		dire("voix plus irrégulière que d'habitude (jitter %.2f %%, shimmer %.2f dB)",
			t.Jitter, t.Shimmer)
	}
	melodie := math.Max(-1, math.Min(1, (t.F0Etendue-4)/3))
	if melodie < -0.4 {
		dire("intonation plate (%.1f demi-tons)", t.F0Etendue)
	} else if melodie > 0.4 {
		dire("intonation ample (%.1f demi-tons)", t.F0Etendue)
	}

	// ── AFFINITÉS ─────────────────────────────────────────────────────────
	//
	// LE CALME EST CENTRÉ SUR L'ORIGINE, et c'est le cœur de la révision.
	// L'étalon apprend l'ordinaire de CETTE voix : une voix à son ordinaire
	// est donc, par construction, au repos de cette personne. Le calme n'est
	// pas une étiquette parmi six, c'est le point de départ dont les autres
	// sont des écarts — et il doit gagner nettement quand rien ne dévie.
	//
	// LES LARGEURS ONT ÉTÉ RESSERRÉES. Trop généreuses, six gaussiennes
	// larges rendaient partout des valeurs voisines : le premier indice
	// dépassait à peine le second, et tout finissait « indéterminé » faute
	// d'écart. Ce n'était pas de la prudence, c'était une distribution qui ne
	// distinguait rien.
	score := map[string]float64{
		Calme: aff(activation, -0.05, 0.36) * aff(irregularite, -0.35, 0.62) *
			aff(melodie, 0.0, 1.1),
		Joie: aff(activation, 0.60, 0.40) * aff(irregularite, -0.25, 0.70) *
			aff(melodie, 0.65, 0.62),
		Tension: aff(activation, 0.42, 0.40) * aff(irregularite, 0.62, 0.55) *
			aff(melodie, -0.25, 0.75),
		Colere: aff(activation, 0.92, 0.36) * aff(e["energie"]/3, 0.75, 0.45) *
			aff(irregularite, 0.55, 0.75),
		Fatigue: aff(activation, -0.62, 0.36) * aff(irregularite, 0.45, 0.65) *
			aff(melodie, -0.62, 0.65),
		Concentre: aff(activation, -0.22, 0.30) * aff(irregularite, -0.55, 0.48) *
			aff(melodie, -0.45, 0.60) * aff(e["debit"]/3, -0.05, 0.62),
	}
	if t.Pente < -12 && score[Fatigue] > 0 {
		score[Fatigue] *= 1.2
		dire("spectre affaissé dans les aigus (%.1f dB/kHz)", t.Pente)
	}

	// CONTRASTE. Élever à une puissance > 1 avant de normaliser écarte les
	// valeurs proches sans changer leur ORDRE : c'est un réglage d'affichage
	// honnête (on ne renverse rien), et il rend lisible un classement qui
	// existait déjà mais se lisait comme une égalité.
	indices := normaliseContraste(score, 1.35)

	tete, second := deuxPremiers(indices)

	// ── LA CONFIANCE ──────────────────────────────────────────────────────
	//
	// Elle combine ce qui se détache (l'écart au suivant) et la valeur du
	// premier : une lecture à 0,55 qui dépasse la suivante de 0,2 est plus
	// solide qu'une lecture à 0,22 avec le même écart.
	//
	// LE FACTEUR EST CALÉ POUR QUE LE PLAFOND RESTE RARE. Une première version
	// saturait à 0,72 sur TOUS les cas nets — le chiffre ne distinguait alors
	// plus rien, et un nombre qui vaut toujours pareil ferait mieux de ne pas
	// s'afficher. On veut une échelle qui serve : autour de 0,25 quand deux
	// lectures se disputent, autour de 0,5 sur un cas franc, le plafond
	// seulement pour l'évidence.
	conf := 0.62 * (0.55*(indices[tete]-indices[second])*2 + 0.45*indices[tete])
	conf *= math.Min(1, t.PartVoisee/0.45)
	// LA FIABILITÉ MULTIPLIE LA CONFIANCE, elle ne la bloque pas. Une référence
	// à peine ébauchée donne une lecture timide, pas un silence — et la
	// dispersion élargie l'a déjà rendue prudente en amont, si bien que les
	// deux effets vont dans le même sens sans qu'on ait rien à arbitrer.
	plafond := PlafondConfiance
	switch reference {
	case "groupe":
		plafond = PlafondGroupe
		dire("comparé à l'ordinaire du GROUPE : votre voix n'a pas encore été observée")
	case "mixte":
		conf *= 0.45 + 0.55*fiab
		dire("référence à %.0f %% la vôtre, le reste emprunté au groupe", fiab*100)
	default:
		conf *= 0.45 + 0.55*fiab
		if fiab < 0.5 {
			dire("référence encore jeune (%d mesures) : lecture indicative", h.ref.Observations())
		}
	}
	conf = math.Max(0, math.Min(plafond, conf))

	// ON NE RETOMBE PLUS DANS « INDÉTERMINÉ » FAUTE D'ÉCART. Le signal est
	// mesurable : il y a donc une réponse, et c'est la confiance qui dit
	// combien elle se détache. Se taire ici revenait à traiter une voix
	// ordinaire comme un défaut de mesure.
	return Lecture{
		Etat: tete, Confiance: arrondi(conf, 3), Indices: indices,
		Pourquoi: pourquoi, Reserve: Reserve, Etalonne: fiab >= 0.75,
		Fiabilite: arrondi(fiab, 3), Observations: h.ref.Observations(),
		Reference: reference, Suffisant: true, Activation: arrondi(activation, 3),
	}
}

// FondIncompressible : la part d'incertitude qu'on mélange à toute
// distribution.
//
// ELLE REND 100 % STRUCTURELLEMENT IMPOSSIBLE, et c'est le point. Sans elle,
// un cas franc sortait à 1,00 — les cinq autres étiquettes exactement à zéro —
// ce qui affirme qu'aucune autre lecture n'est concevable. Aucun classifieur
// prosodique ne peut dire cela, et sûrement pas six gaussiennes. Le plafond de
// confiance protégeait le chiffre de confiance ; il ne protégeait pas les
// indices eux-mêmes, qui sont pourtant ce qu'on lit en premier.
//
// Six pour cent répartis uniformément : assez pour qu'aucune barre ne se vide
// tout à fait, trop peu pour brouiller un classement net.
const FondIncompressible = 0.06

// normaliseContraste : comme normalise, mais en accentuant les écarts, puis en
// mélangeant le fond incompressible.
//
// L'ORDRE EST STRICTEMENT PRÉSERVÉ — élever des valeurs positives à une même
// puissance est monotone, et ajouter une constante à toutes ne renverse rien.
// On ne fabrique aucune préférence : on rend visible celle qui existait, et on
// s'interdit de la présenter comme exclusive.
func normaliseContraste(m map[string]float64, puissance float64) map[string]float64 {
	accentue := make(map[string]float64, len(m))
	for k, v := range m {
		if v < 0 {
			v = 0
		}
		accentue[k] = math.Pow(v, puissance)
	}
	net := normalise(accentue)
	part := FondIncompressible / float64(len(net))
	out := make(map[string]float64, len(net))
	for k, v := range net {
		out[k] = arrondi((1-FondIncompressible)*v+part, 3)
	}
	return out
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
