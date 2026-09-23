// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package audio

// Anneau : le tampon circulaire qui découpe un flux continu en trames qui se
// CHEVAUCHENT.
//
// POURQUOI DU CHEVAUCHEMENT. Une trame de 2048 échantillons dure 43 ms. Sans
// recouvrement, on ne mesurerait la voix que toutes les 43 ms, et une fenêtre
// de Hann — qui écrase ses propres bords — perdrait la moitié de ce qui s'y
// passe. Avec un pas de 512, chaque instant est vu par quatre trames : la
// mesure devient continue, et la latence tombe à la durée d'un pas.
type Anneau struct {
	donnees []float64
	taille  int // longueur d'une trame
	pas     int // avance entre deux trames
	ecrits  int // échantillons accumulés depuis la dernière trame rendue
	rempli  bool
	tete    int
}

// NouvelAnneau prépare le découpage. `pas` doit diviser `taille` — sinon
// l'alignement dérive silencieusement et l'horodatage des trames devient faux.
func NouvelAnneau(taille, pas int) *Anneau {
	if pas <= 0 || pas > taille {
		panic("anneau : le pas doit tenir dans la trame")
	}
	return &Anneau{donnees: make([]float64, taille), taille: taille, pas: pas}
}

// Ecris ajoute des échantillons et appelle `surTrame` pour chaque trame
// complète. La trame passée est un TAMPON RÉUTILISÉ : qui veut la garder la
// copie. C'est dit ici parce que c'est le genre de partage qui se paie très
// cher et très tard.
func (a *Anneau) Ecris(x []float64, surTrame func(trame []float64)) {
	for _, v := range x {
		a.donnees[a.tete] = v
		a.tete = (a.tete + 1) % a.taille
		if a.tete == 0 {
			a.rempli = true
		}
		a.ecrits++
		if a.ecrits >= a.pas && a.rempli {
			a.ecrits = 0
			surTrame(a.trame())
		}
	}
}

// trame rend la fenêtre courante remise à plat, du plus ancien au plus récent.
func (a *Anneau) trame() []float64 {
	out := make([]float64, a.taille)
	copy(out, a.donnees[a.tete:])
	copy(out[a.taille-a.tete:], a.donnees[:a.tete])
	return out
}

// Pret : a-t-on vu au moins une trame entière ? Avant cela, ce qu'on
// rendrait serait moitié signal moitié zéros — et ces zéros compteraient
// comme du silence dans toutes les mesures.
func (a *Anneau) Pret() bool { return a.rempli }
