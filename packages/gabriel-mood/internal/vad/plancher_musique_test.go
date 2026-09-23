// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package vad

import (
	"math"
	"testing"
)

// LE TEST QUI AURAIT ÉVITÉ #1333.
//
// Le défaut n'était visible qu'AVEC LE TEMPS : à cinq secondes tout allait
// bien, à trente la détection s'était effondrée. Un test qui n'observe qu'une
// poignée de trames ne l'aurait jamais vu — c'est pourquoi celui-ci fait
// tourner trente secondes simulées et compare le DÉBUT à la FIN.
//
// ET IL MESURE LES DEUX CÔTÉS. Mon premier correctif donnait un rappel
// parfait : le plancher, gelé pendant la parole, tombait à son minimum et n'en
// remontait plus, si bien que TOUT était déclaré parole. Un test de rappel seul
// l'aurait validé. Les fausses détections sont ici la moitié qui compte.

const (
	tramesParSeconde = 100
	secondes         = 30
)

// scene simule une pièce : un bruit de fond constant, et une voix qui parle
// par rafales d'une demi-seconde, une seconde sur deux.
func scene(t *testing.T, fondDB, voixDB float64) (rappel, fausses float64, plancher float64) {
	t.Helper()
	const raies, ech = 512, 48000.0
	plat := func(dB float64) []float64 {
		p := make([]float64, raies)
		for i := range p {
			p[i] = math.Pow(10, dB/10)
		}
		return p
	}
	d := Nouveau(raies, ech, Normal, 12)
	fond := plat(fondDB)
	voix := make([]float64, raies)
	for i := range voix {
		// Les énergies s'additionnent : une voix DANS une pièce bruyante, ce
		// n'est pas une voix à la place du bruit.
		voix[i] = fond[i] + math.Pow(10, voixDB/10)
	}
	var vus, parles, faux, silences int
	var dernierPlancher float64
	for s := 0; s < secondes; s++ {
		for f := 0; f < tramesParSeconde; f++ {
			parle := (f/50)%2 == 0 && s%2 == 0
			in := fond
			if parle {
				in = voix
			}
			v := d.Analyse(in)
			switch {
			case parle:
				parles++
				if v.Parole {
					vus++
				}
			default:
				silences++
				if v.Parole {
					faux++
				}
			}
			dernierPlancher = v.Plancher[2]
		}
	}
	return float64(vus) / float64(parles), float64(faux) / float64(silences), dernierPlancher
}

// TestLaMusiqueNeCouvrePasUneVoixQuiLaDomine : le cœur de #1333.
//
// Avec une musique VINGT décibels sous la voix — le cas courant, une radio
// dans la pièce — la détection tombait à 30 % au bout d'une demi-minute parce
// que le plancher montait jusqu'au niveau de la musique. Elle doit rester au
// niveau de la pièce calme.
func TestLaMusiqueNeCouvrePasUneVoixQuiLaDomine(t *testing.T) {
	calmeRappel, calmeFaux, _ := scene(t, -80, -35)
	musRappel, musFaux, plancher := scene(t, -55, -35)

	if musRappel < 0.90 {
		t.Errorf("voix détectée seulement %.1f %% avec une musique 20 dB plus bas "+
			"(pièce calme : %.1f %%) — le plancher a suivi la musique",
			musRappel*100, calmeRappel*100)
	}
	if musFaux > 0.15 {
		t.Errorf("%.1f %% de fausses détections sur le silence : le plancher est trop bas",
			musFaux*100)
	}
	// Le plancher DOIT suivre la musique — c'est son travail. Ce qu'il ne doit
	// pas faire, c'est monter plus haut qu'elle.
	if plancher < -60 || plancher > -45 {
		t.Errorf("plancher à %.1f dB pour une musique à -55 dB : il devrait la "+
			"suivre de près, sans la dépasser", plancher)
	}
	if calmeFaux > 0.15 {
		t.Errorf("%.1f %% de fausses détections en pièce calme", calmeFaux*100)
	}
}

// TestLaDetectionNeSeDegradePasAvecLeTemps : le symptôme tel qu'il a été
// rapporté — « vers 10-15 secondes, on part dans les indéterminés ».
func TestLaDetectionNeSeDegradePasAvecLeTemps(t *testing.T) {
	const raies, ech = 512, 48000.0
	plat := func(dB float64) []float64 {
		p := make([]float64, raies)
		for i := range p {
			p[i] = math.Pow(10, dB/10)
		}
		return p
	}
	d := Nouveau(raies, ech, Normal, 12)
	fond := plat(-55)
	voix := make([]float64, raies)
	for i := range voix {
		voix[i] = fond[i] + math.Pow(10, -35/10.0)
	}
	mesure := func(deSeconde, aSeconde int) float64 {
		vus, parles := 0, 0
		for s := deSeconde; s < aSeconde; s++ {
			for f := 0; f < tramesParSeconde; f++ {
				parle := (f/50)%2 == 0 && s%2 == 0
				in := fond
				if parle {
					in = voix
				}
				v := d.Analyse(in)
				if parle {
					parles++
					if v.Parole {
						vus++
					}
				}
			}
		}
		if parles == 0 {
			return 0
		}
		return float64(vus) / float64(parles)
	}
	debut := mesure(0, 10)
	fin := mesure(10, 40)
	if fin < debut-0.10 {
		t.Errorf("la détection se dégrade : %.1f %% sur les dix premières secondes, "+
			"%.1f %% ensuite — c'est exactement le symptôme de #1333",
			debut*100, fin*100)
	}
}

// TestLeMinimumNeSeLaissePasTirerParLaParole : la propriété qui rend
// l'estimateur juste, isolée.
func TestLeMinimumNeSeLaissePasTirerParLaParole(t *testing.T) {
	const raies, ech = 512, 48000.0
	d := Nouveau(raies, ech, Normal, 12)
	fort := make([]float64, raies)
	faible := make([]float64, raies)
	for i := range fort {
		fort[i] = math.Pow(10, -20/10.0)
		faible[i] = math.Pow(10, -70/10.0)
	}
	// Quatre-vingt-dix pour cent de parole très forte, dix pour cent de
	// silence : le plancher doit trouver le silence, pas la moyenne.
	var v Verdict
	for s := 0; s < 20; s++ {
		for f := 0; f < tramesParSeconde; f++ {
			in := fort
			if f >= 90 {
				in = faible
			}
			v = d.Analyse(in)
		}
	}
	if v.Plancher[2] > -55 {
		t.Errorf("plancher à %.1f dB alors que la pièce est à -70 dB : "+
			"la parole l'a tiré vers le haut", v.Plancher[2])
	}
}
