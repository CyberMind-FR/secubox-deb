// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package linker

import (
	"regexp"
	"strings"
	"unicode"
)

// LE TITRE QUI N'EN EST PAS UN (#1323)
//
// Certains flux publient leur propre code de mise en page. Le Dauphiné sort,
// depuis des semaines, des titres de la forme « Vidéo. $content.TitleNoTags » :
// le chapeau est bien là, mais le titre lui-même est resté un GABARIT que le
// moteur du site n'a pas substitué. Soixante-dix-neuf articles sur deux
// sources, et autant de sujets qui s'annoncent par du jargon de gabarit.
//
// ON NE PEUT PAS RÉPARER CE QU'ON N'A PAS, MAIS ON L'A. Le résumé du même
// article porte la vraie première phrase — c'est lui qu'il faut faire remonter
// à la place du gabarit. Le chapeau, lui, se garde : « Vidéo », « Savoie »,
// « Notre enquête » disent quelque chose de vrai sur la dépêche.
//
// LA PRUDENCE QUI COMPTE : un `$` ne fait pas un gabarit. « TikTok to pay $400m »,
// « A$AP Rocky », « LAPSUS$ » sont de VRAIS titres, et il y en a des dizaines
// en base. Un premier filtre sur le seul `$` en attrapait cent pour les
// soixante-dix-neuf vrais cas. On exige donc la forme complète d'une référence
// de gabarit : des accolades, ou un POINT entre deux identifiants.
var gabaritRe = regexp.MustCompile(
	`\$\{[^}]*\}` + // ${ x }
		`|\{\{[^}]*\}\}` + // {{ x }}
		`|<%[=\-]?[^%]*%>` + // <%= x %>
		`|\$[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+`) // $objet.Propriete

// Un titre n'est pas un article : au-delà, on coupe au mot.
const maxTitre = 160

// PorteUnGabarit dit si un titre contient une référence non substituée.
func PorteUnGabarit(titre string) bool { return gabaritRe.MatchString(titre) }

// TitreLisible rend un titre affichable, en s'appuyant sur le corps quand le
// titre d'origine n'est qu'un gabarit. Sans gabarit, il rend le titre INCHANGÉ :
// c'est une réparation, pas une réécriture.
func TitreLisible(titre, corps string) string {
	if !PorteUnGabarit(titre) {
		return titre
	}
	chapeau := strings.TrimSpace(strings.Join(
		strings.Fields(gabaritRe.ReplaceAllString(titre, " ")), " "))
	phrase := premierePhrase(corps)
	switch {
	case phrase == "" && chapeau == "":
		// Ni chapeau ni corps : on garde le titre d'origine. Un gabarit affiché
		// reste préférable à une dépêche sans titre, qu'on ne saurait plus
		// désigner ni retrouver.
		return titre
	case phrase == "":
		return chapeau
	case chapeau == "":
		return tronqueAuMot(phrase, maxTitre)
	}
	// Le chapeau porte déjà sa ponctuation (« Vidéo. », « Savoie. ») ; on ne
	// lui en ajoute pas une seconde.
	if !finitParPonctuation(chapeau) {
		chapeau += "."
	}
	return tronqueAuMot(chapeau+" "+phrase, maxTitre)
}

func finitParPonctuation(s string) bool {
	if s == "" {
		return false
	}
	r := []rune(s)[len([]rune(s))-1]
	return r == '.' || r == ':' || r == '!' || r == '?' || r == '–' || r == '—'
}

// premierePhrase rend la première phrase d'un texte.
//
// LA DIFFICULTÉ EST L'ABRÉVIATION. « M. Dupont », « 20 sept. 2026 » portent un
// point qui ne termine rien. On ne coupe donc qu'à partir d'une longueur où une
// phrase est plausible : plus court, le point appartient presque toujours à une
// abréviation. C'est une heuristique, assumée — elle rend au pire une phrase un
// peu longue, jamais un titre tronqué à « M. ».
const minPhrase = 40

func premierePhrase(s string) string {
	s = strings.TrimSpace(strings.Join(strings.Fields(s), " "))
	if s == "" {
		return ""
	}
	rs := []rune(s)
	for i := 0; i < len(rs); i++ {
		if rs[i] != '.' && rs[i] != '!' && rs[i] != '?' {
			continue
		}
		if i+1 < len(rs) && !unicode.IsSpace(rs[i+1]) {
			continue // « 3.5 », « ledauphine.com » : pas une fin de phrase
		}
		if i+1 >= minPhrase {
			return strings.TrimSpace(string(rs[:i+1]))
		}
	}
	return s
}

// tronqueAuMot coupe sans casser un mot, et le dit par une ellipse.
func tronqueAuMot(s string, max int) string {
	rs := []rune(s)
	if len(rs) <= max {
		return s
	}
	coupe := string(rs[:max])
	if i := strings.LastIndexByte(coupe, ' '); i > max/2 {
		coupe = coupe[:i]
	}
	return strings.TrimRight(coupe, " ,;:.") + "…"
}
