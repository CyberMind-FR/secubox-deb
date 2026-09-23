// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package web

// UN LIEN VERS UNE VIDÉO DE LA BOX DEVIENT UN LECTEUR (#1328).
//
// ── CE QU'ON VOYAIT ────────────────────────────────────────────────────────
//
// Coller `https://peertube.gk2.secubox.in/w/xxxx` dans un message donnait une
// PASTILLE : le mot « peertube » et l'adresse en toutes lettres. Pour regarder,
// il fallait cliquer, sortir du fil, et revenir.
//
// ── POURQUOI ÇA NE MARCHAIT PAS, ALORS QUE TOUT ÉTAIT LÀ ───────────────────
//
// Rien ne manquait, en réalité :
//
//   * `objetMediaPeertube` construisait déjà le lecteur — il servait pour les
//     fils passerelle, en TÊTE de fil (`objetMediaURL` dans fil.html) ;
//   * la CSP autorisait déjà `frame-src https://peertube.gk2.secubox.in` ;
//   * `--peertube-origine` était déjà passé à l'unité.
//
// Ce qui manquait, c'était le chemin entre les deux : le rendu d'un MESSAGE ne
// consultait jamais cette machinerie. Il voyait une ancre vers un de nos
// services et la confiait à `fichesSecuBox`, dont c'est le travail — poser une
// pastille sur un lien de service. Une vidéo n'est pas un lien de service.
//
// ── OÙ CETTE PASSE SE PLACE, ET POURQUOI LÀ ────────────────────────────────
//
// Juste après `mediasIntegres` (qui transforme les pièces jointes en lecteurs)
// et juste avant `fichesSecuBox`. L'ordre porte la règle : ce qui peut se
// REGARDER devient un lecteur ; ce qui reste est un lien de service, et prend
// sa pastille. Mettre cette passe après aurait demandé de défaire une pastille
// déjà posée, ce qui est toujours plus fragile que de ne pas la poser.

import (
	"regexp"
	"strings"
)

// MaxLecteursParMessage : au-delà, on laisse les pastilles.
//
// Un message qui cite douze vidéos n'en veut pas douze lecteurs : la page
// deviendrait illisible, et douze cadres PeerTube en vol coûtent cher au
// navigateur comme à l'instance. Trois suffisent à couvrir l'usage réel — on
// partage une vidéo, parfois deux — et le reste reste cliquable.
const MaxLecteursParMessage = 3

// ancreMediaRe capture une ancre déjà produite par `liens()` ou
// `adressesNues()`. On travaille sur l'ANCRE et pas sur le texte brut : à ce
// stade tout est échappé, et reconnaître l'adresse nue rejouerait le travail
// des deux passes précédentes.
var ancreMediaRe = regexp.MustCompile(`<a href="(https://[^"]+)"[^>]*>[^<]*</a>`)

// lecteursDeLiens remplace les liens vidéo par leur lecteur.
func lecteursDeLiens(s string) string {
	if !strings.Contains(s, "<a href=") {
		return s
	}
	poses := 0
	// DÉDOUBLONNAGE PAR VIDÉO. Le même lien collé deux fois — une fois nu, une
	// fois en lien Markdown — arrive ici en deux ancres. Personne ne veut deux
	// fois le même lecteur ; la seconde redevient une pastille, ce qui garde
	// l'information sans encombrer.
	vues := map[string]bool{}
	return ancreMediaRe.ReplaceAllStringFunc(s, func(tout string) string {
		m := ancreMediaRe.FindStringSubmatch(tout)
		if m == nil {
			return tout
		}
		adresse := m[1]
		lecteur, ok := embedMediaURL(adresse)
		if !ok {
			return tout
		}
		cle := peertubeEmbedURL(adresse)
		// AU-DELA DU PLAFOND, OU EN DOUBLON : une pastille, pas un lien nu.
		// `fichesSecuBox` a saute cette ancre exprès pour nous laisser la
		// main ; si l'on rendait l'ancre telle quelle, ces liens-la seraient
		// les seuls du fil a ne pas porter leur etiquette de service.
		if poses >= MaxLecteursParMessage || vues[cle] {
			return ficheDe(adresse, adresse)
		}
		vues[cle] = true
		poses++
		return lecteur
	})
}
