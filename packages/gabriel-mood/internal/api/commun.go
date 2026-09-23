// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package api

import (
	"math"
	"net/http"

	"github.com/CyberMind-FR/secubox-deb/gabriel-mood/internal/ser"
)

// L'HUMEUR D'ENSEMBLE : ce que plusieurs voix donnent, sans qu'aucune se voie.
//
// Chacun a sa page et sa lecture, qui ne sort pas de sa session. Ce fichier
// ajoute la seule chose qu'on puisse publier sans trahir personne : une
// moyenne, quand il y a assez de monde pour qu'une moyenne cache ceux qui la
// composent.
//
// ── POURQUOI UN SEUIL, ET POURQUOI TROIS ───────────────────────────────────
//
// Une moyenne n'anonymise pas par magie.
//
//	À UN participant, la « moyenne » EST sa lecture. Publier revient à
//	publier la personne.
//
//	À DEUX, si vous êtes l'un des deux — et vous connaissez votre propre
//	valeur — vous retranchez et vous obtenez EXACTEMENT celle de l'autre.
//	C'est une soustraction, pas une attaque savante.
//
//	À TROIS, il reste deux inconnues pour une équation : on ne peut plus
//	isoler quelqu'un sans complicité.
//
// Trois est le plancher habituel de ce genre de publication, et c'est celui
// qu'on retient. En-dessous, on ne publie RIEN — pas une version dégradée, pas
// une approximation : rien, et on dit pourquoi.
const SeuilAnonymat = 3

// PasArrondi : les valeurs publiées sont arrondies au vingtième.
//
// Contre la SOUSTRACTION DANS LE TEMPS. Même au-dessus du seuil, observer la
// moyenne juste avant et juste après qu'une personne se connecte donne la
// différence, donc sa lecture. L'arrondi grossier rend cette différence
// illisible tant que le groupe n'est pas minuscule — et sous le seuil, il n'y
// a de toute façon plus rien à observer.
const PasArrondi = 0.05

// Commun : la réponse de GET /api/mood/commun.
type Commun struct {
	Participants int                `json:"participants"`
	Suffisant    bool               `json:"suffisant"`
	Seuil        int                `json:"seuil"`
	Indices      map[string]float64 `json:"indices,omitempty"`
	Activation   float64            `json:"activation,omitempty"`
	Tete         string             `json:"tete,omitempty"`
	// L'ÉTAT DE LA BASE COMMUNE : combien d'ordinaires la composent, et
	// sert-elle de repère aux nouveaux venus. C'est la contrepartie du
	// partage — qui contribue a le droit de savoir à quoi.
	BaseCommune int    `json:"base_commune"`
	BaseActive  bool   `json:"base_active"`
	Detail      string `json:"detail"`
	Reserve     string `json:"reserve"`
}

func arrondiGrossier(v float64) float64 {
	return math.Round(v/PasArrondi) * PasArrondi
}

// GET /api/mood/commun
func (s *Serveur) commun(w http.ResponseWriter, r *http.Request) {
	// ON NE COMPTE QUE LES LECTURES QUI EN SONT. Une session en bruit ou en
	// étalonnage n'a pas d'indices ; l'inclure ferait deux dégâts — tirer la
	// moyenne vers rien, et révéler qu'un participant est dans le bruit, ce
	// qui est déjà une information sur lui.
	var lectures []ser.Lecture
	for _, id := range s.Sessions.Liste() {
		sess, ok := s.Sessions.Par(id)
		if !ok {
			continue
		}
		l := sess.Analyseur.Lecture()
		if l.Etat == ser.Indetermine || l.Indices == nil {
			continue
		}
		lectures = append(lectures, l)
	}

	rep := Commun{
		Participants: len(lectures), Seuil: SeuilAnonymat,
		BaseCommune: s.Sessions.Partage.Contributeurs(),
		BaseActive:  s.Sessions.Partage.Utilisable(),
		Reserve:     ser.Reserve,
	}
	if len(lectures) < SeuilAnonymat {
		rep.Detail = "pas assez de participants pour publier sans trahir personne : " +
			"à un, la moyenne EST la personne ; à deux, qui connaît la sienne " +
			"obtient l'autre par soustraction. Il en faut au moins trois."
		ecris(w, http.StatusOK, rep)
		return
	}

	somme := make(map[string]float64, len(ser.Etats))
	var act float64
	for _, l := range lectures {
		for _, k := range ser.Etats {
			somme[k] += l.Indices[k]
		}
		act += l.Activation
	}
	n := float64(len(lectures))
	rep.Indices = make(map[string]float64, len(ser.Etats))
	tete, meilleur := "", -1.0
	for _, k := range ser.Etats {
		v := arrondiGrossier(somme[k] / n)
		rep.Indices[k] = v
		if v > meilleur {
			tete, meilleur = k, v
		}
	}
	rep.Activation = arrondiGrossier(act / n)
	rep.Tete = tete
	rep.Suffisant = true
	rep.Detail = "moyenne de " + itoa(len(lectures)) + " voix, arrondie au vingtième. " +
		"Aucune lecture individuelle n'est publiée, ici ni ailleurs."
	ecris(w, http.StatusOK, rep)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 && i > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
