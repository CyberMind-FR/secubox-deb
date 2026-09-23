// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Package vad — détection d'activité vocale, en Go pur.
//
// CE QUE CE N'EST PAS. Ce n'est PAS un habillage du VAD de WebRTC. Celui-ci est
// écrit en C et demanderait CGO ; or tout le dépôt se construit en
// `CGO_ENABLED=0` et se croise vers arm64, et une bibliothèque partagée de plus
// à l'exécution serait un prix élevé pour une décision binaire. On reprend donc
// sa DÉMARCHE — découper le spectre en sous-bandes vocales, comparer chacune à
// un plancher de bruit appris — sans prétendre en reproduire les coefficients.
// Le dire est important : quelqu'un qui lit « WebRTC VAD » s'attend aux
// performances publiées de WebRTC, pas aux nôtres.
//
// POURQUOI UN PLANCHER APPRIS. Un seuil fixe ne survit pas au déplacement du
// micro : une pièce calme et une pièce avec un ventilateur n'ont pas le même
// niveau de repos, et un seuil réglé pour l'une bavarde ou reste muet dans
// l'autre. Le plancher monte lentement et descend vite : il apprend le bruit
// pendant les silences, et ne se laisse pas tirer vers le haut par la parole.
package vad

import (
	"math"
	"sort"
)

// Les sous-bandes, en hertz. Elles couvrent ce qui porte la voix : la
// fondamentale et les deux premiers formants, là où le rapport signal/bruit
// d'une parole est le meilleur. Au-delà de 4 kHz, on ne trouve guère que des
// fricatives et du souffle de micro.
var bandes = [...][2]float64{
	{80, 250}, {250, 500}, {500, 1000},
	{1000, 2000}, {2000, 3000}, {3000, 4000},
}

// Agressivite règle l'arbitrage entre manquer de la parole et en inventer.
type Agressivite int

const (
	Bavard      Agressivite = iota // garde tout ce qui ressemble à de la voix
	Normal                         // le défaut
	Prudent                        // ne garde que ce qui est franc
	TresPrudent                    // pour un environnement bruyant
)

func (a Agressivite) marge() float64 {
	switch a {
	case Bavard:
		return 3.0
	case Prudent:
		return 9.0
	case TresPrudent:
		return 12.0
	default:
		return 6.0
	}
}

// ── L'ESTIMATION DU PLANCHER, ET POURQUOI CE N'EST PAS UN LISSAGE (#1333) ──
//
// La version précédente montait le plancher de 0,05 dB chaque fois que
// l'énergie le dépassait. Le commentaire promettait qu'il « apprend le bruit
// pendant les silences, et ne se laisse pas tirer vers le haut par la
// parole » — mais le code montait AUSSI sur les trames parlées. À cent trames
// par seconde et quarante pour cent de parole, la parole seule tirait le
// plancher de deux décibels par seconde. Avec une musique au niveau de la
// voix, le plancher atteignait ce niveau en une dizaine de secondes, la voix
// ne le dépassait plus de la marge exigée, et la détection tombait de 88 % à
// 30 % : la lecture passait en « pas assez de voix » pendant que la personne
// parlait.
//
// LE GEL PENDANT LA PAROLE NE MARCHE PAS, ET JE L'AI ESSAYÉ. Le plancher sert
// à décider ce QU'EST la parole ; le faire dépendre de cette décision ferme
// une boucle. Mesuré : le plancher tombait à son minimum et n'en remontait
// jamais, parce que toute musique le dépassant était classée « parole », ce
// qui gelait l'apprentissage. Rappel parfait — et CENT POUR CENT de fausses
// détections, y compris en pièce calme. Le module aurait analysé la musique
// comme une personne, ce qui est bien pire qu'un indéterminé.
//
// LA SORTIE EST DE NE PAS DEMANDER SON AVIS À LA DÉCISION. La parole est
// INTERMITTENTE : sur quelques secondes il y a forcément des creux, et le
// MINIMUM de l'énergie sur une fenêtre plus longue qu'une phrase EST le bruit
// de la pièce. C'est la « minimum statistics » de Martin dans sa forme la plus
// simple — on découpe la fenêtre en sous-blocs, on garde le minimum de chacun,
// et le plancher est le minimum des derniers sous-blocs. Aucune circularité,
// et une seule comparaison par trame et par bande.
const (
	// FenetrePlancher : la fenêtre d'observation, en TRAMES — le détecteur
	// ignore la durée d'une trame. À dix millisecondes (ce que pose le
	// moteur), cela fait trois secondes : plus long qu'une phrase, assez court
	// pour suivre une pièce qui change.
	FenetrePlancher = 300

	// RecalcPlancher : on ne refait le quantile qu'une trame sur cinquante. Il
	// n'y a rien à gagner à le recalculer cent fois par seconde — le bruit
	// d'une pièce ne change pas à cette vitesse — et tout à perdre sur le
	// budget processeur d'une board ARM.
	RecalcPlancher = 50

	// QuantilePlancher : la fraction de la fenêtre considérée comme du bruit.
	// Vingt pour cent laisse jusqu'à QUATRE CINQUIÈMES de parole dans la
	// fenêtre sans que le plancher s'en trouve tiré — bien au-delà de ce que
	// produit une conversation, qui laisse toujours des blancs.
	QuantilePlancher = 0.20

	// MargePlancher : de quoi passer au-dessus des remous qui subsistent sous
	// le quantile. RÉGLÉE PAR LA MESURE, sur un banc où chaque sous-bande
	// fluctue indépendamment — le bruit d'une pièce n'excite pas les six
	// bandes en même temps, et c'est justement ce que suppose la règle des
	// trois bandes. Rappel / fausses détections, fluctuation du bruit en
	// abscisse :
	//
	//         ±2 dB      ±4 dB      ±6 dB
	//   0,0   100/7,7    100/7,7    100/54,7
	//   1,0   100/7,7    100/7,7    100/17,4   ← retenue
	//   2,0     0/0,0     98/7,4    100/7,8
	//
	// Deux décibels tiennent mieux les fausses détections dans le bruit fort,
	// mais perdent ENTIÈREMENT une voix à cinq décibels au-dessus d'une pièce
	// très stable. Un décibel ne perd rien nulle part et reste, partout, très
	// en-dessous de l'ancien estimateur (7,7 à 26,6 % à ±2/±4, 96 % à ±6).
	MargePlancher = 1.0

	// PlafondEcart : de combien, au plus, le plancher peut s'élever au-dessus
	// du creux de la fenêtre. Il ne sert QUE dans un cas, mais un cas réel :
	// quand la parole occupe plus des quatre cinquièmes de la fenêtre — un
	// monologue, une lecture à voix haute — le quantile tombe dans la parole
	// et le plancher s'envole de cinquante décibels. Mesuré, à 80 et 90 % de
	// parole dans une pièce à -70 dB : -19 dB sans plafond, -59,8 dB avec.
	// Douze décibels sont bien au-delà de l'écart quantile-minimum d'un bruit
	// ordinaire (quelques décibels), si bien que le plafond ne mord JAMAIS en
	// régime normal — vérifié : les fausses détections ne bougent pas d'un
	// dixième, de six à vingt-quatre décibels de plafond.
	PlafondEcart = 12.0
)

// amorcePlancher remet une bande à son état de départ : plancher très bas,
// aucun sous-bloc fermé. Partagée par `Nouveau` et `Reinitialise`, qui
// doivent poser exactement le même état — deux amorçages écrits deux fois
// finissent toujours par différer.
func (d *Detecteur) amorcePlancher(i int) {
	d.plancher[i] = -90
	if d.histo[i] == nil {
		d.histo[i] = make([]float64, FenetrePlancher)
	}
	for k := range d.histo[i] {
		d.histo[i][k] = 0
	}
	d.rang, d.vus, d.depuisCalc, d.pret = 0, 0, 0, false
}

// avancePlancher enregistre la trame et, une trame sur RecalcPlancher, refait
// le quantile.
func (d *Detecteur) avancePlancher(bandesdB []float64) {
	for i := range bandes {
		d.histo[i][d.rang] = bandesdB[i]
	}
	d.rang = (d.rang + 1) % FenetrePlancher
	if d.vus < FenetrePlancher {
		d.vus++
	}
	d.depuisCalc++
	if d.depuisCalc < RecalcPlancher {
		return
	}
	d.depuisCalc = 0
	k := int(float64(d.vus) * QuantilePlancher)
	if k >= d.vus {
		k = d.vus - 1
	}
	for i := range bandes {
		d.tri = append(d.tri[:0], d.histo[i][:d.vus]...)
		sort.Float64s(d.tri)
		// LE QUANTILE, BORNÉ PAR SON PROPRE MINIMUM. Quand la parole occupe
		// plus des quatre cinquièmes de la fenêtre — un monologue, une lecture
		// à voix haute — le quantile tombe DANS la parole et le plancher
		// s'envole avec elle. Le cas se reconnaît sans ambiguïté : la
		// distribution est bimodale, et le quantile se retrouve alors des
		// dizaines de décibels au-dessus du creux. On refuse simplement de
		// s'éloigner autant du plus bas observé.
		p := d.tri[k] + MargePlancher
		if plafond := d.tri[0] + PlafondEcart; p > plafond {
			p = plafond
		}
		d.plancher[i] = p
	}
	// LE PLANCHER EXISTE : la décision peut commencer. C'EST LUI QUI DÉFINIT
	// L'AMORÇAGE, et pas un compteur séparé. Les deux ont divergé une fois —
	// le compteur libérait la décision à cinquante trames quand le plancher
	// n'était calculé qu'à cent, et l'intervalle déclarait « parole » sur tout,
	// y compris le silence. Deux horloges pour un même départ finissent
	// toujours par se désaccorder.
	d.pret = true
}

// Detecteur garde le plancher de bruit et l'état de la décision.
//
// Il n'est PAS sûr en accès concurrent : un détecteur par flux analysé.
type Detecteur struct {
	agressivite Agressivite
	plancher    []float64   // énergie de repos apprise, par bande (dB)
	histo       [][]float64 // les FenetrePlancher dernières énergies, par bande
	rang        int         // position courante dans l'anneau
	vus         int         // trames écrites dans l'anneau (plafonné)
	depuisCalc  int         // trames depuis le dernier calcul du quantile
	pret        bool        // le plancher a été calculé au moins une fois
	tri         []float64   // tampon de tri, alloué une fois
	amorce      int         // trames vues, pour l'amorçage
	actif       bool
	restant     int // trames de rémanence encore dues
	remanence   int
	debuts      []int
	fins        []int
}

// Nouveau prépare un détecteur pour un spectre de `raies` points.
//
// `remanence` : le nombre de trames pendant lesquelles on continue de déclarer
// la parole après sa disparition. Sans elle, on coupe les fins de mots — les
// consonnes finales sont faibles, et une décision trame par trame les jette.
func Nouveau(raies int, echantillonnage float64, a Agressivite, remanence int) *Detecteur {
	d := &Detecteur{
		agressivite: a, remanence: remanence,
		plancher: make([]float64, len(bandes)),
		histo:    make([][]float64, len(bandes)),
		tri:      make([]float64, 0, FenetrePlancher),
		debuts:   make([]int, len(bandes)),
		fins:     make([]int, len(bandes)),
	}
	pas := echantillonnage / float64(2*(raies-1))
	for i, b := range bandes {
		d.debuts[i] = int(b[0] / pas)
		d.fins[i] = int(b[1] / pas)
		if d.fins[i] >= raies {
			d.fins[i] = raies - 1
		}
		if d.debuts[i] >= d.fins[i] {
			d.debuts[i] = d.fins[i] - 1
		}
		if d.debuts[i] < 0 {
			d.debuts[i] = 0
		}
		d.amorcePlancher(i)
	}
	return d
}

// Verdict : la décision et de quoi la comprendre.
type Verdict struct {
	Parole    bool
	Confiance float64   // 0..1, la marge au-dessus du plancher, normalisée
	Bandes    []float64 // énergie par bande, en dB
	Plancher  []float64 // le bruit appris, en dB — utile pour comprendre un refus
	Amorcage  bool      // vrai tant que le plancher n'est pas fiable
}

// AmorcageTrames : tant qu'on n'a pas vu ça, le plancher n'est pas de confiance.
// Une demi-seconde à cent trames par seconde.
const AmorcageTrames = 50

// Analyse rend le verdict pour une trame, à partir de son spectre de PUISSANCE.
func (d *Detecteur) Analyse(puissance []float64) Verdict {
	bandesdB := make([]float64, len(bandes))
	votes := 0
	var marge float64
	for i := range bandes {
		s := 0.0
		n := 0
		for k := d.debuts[i]; k <= d.fins[i] && k < len(puissance); k++ {
			s += puissance[k]
			n++
		}
		if n == 0 {
			n = 1
		}
		e := 10 * math.Log10(s/float64(n)+1e-20)
		bandesdB[i] = e

		if e > d.plancher[i]+d.agressivite.marge() {
			votes++
			marge += e - d.plancher[i]
		}
	}
	d.avancePlancher(bandesdB)
	if d.amorce < AmorcageTrames {
		d.amorce++
	}

	// LA VOIX OCCUPE PLUSIEURS BANDES À LA FOIS. Un claquement de porte ou un
	// bourdonnement secteur n'en excite qu'une ou deux ; exiger au moins trois
	// bandes écarte l'essentiel des bruits impulsifs sans rien apprendre d'eux.
	brut := votes >= 3
	switch {
	case brut:
		d.actif = true
		d.restant = d.remanence
	case d.restant > 0:
		d.restant--
	default:
		d.actif = false
	}

	conf := 0.0
	if votes > 0 {
		conf = marge / float64(votes) / 20 // 20 dB au-dessus du bruit = certitude
		if conf > 1 {
			conf = 1
		}
	}
	return Verdict{
		Parole: d.actif && d.pret, Confiance: conf,
		Bandes: bandesdB, Plancher: append([]float64(nil), d.plancher...),
		Amorcage: !d.pret,
	}
}

// Reinitialise oublie le bruit appris — à appeler quand la source d'entrée
// change, sinon le plancher de l'ancienne pièce juge la nouvelle.
func (d *Detecteur) Reinitialise() {
	for i := range d.plancher {
		d.amorcePlancher(i)
	}
	d.amorce, d.actif, d.restant = 0, false, 0
}
