// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// SecuBox-Deb :: toolbox-ng :: sbxwaf — noms de paramètres et de cookies lus comme PHP (#3273)
//
// LIRE COMME PHP, PAS COMME GO. Une signature qui compare le nom brut d'un
// paramètre se contourne par la différence : PHP enregistre `.from`, ` _from`,
// `_from[]` ou `_from[x]` sous le nom `_from`, et `_[Host-x` sous `__Host-x`.
// Les règles de #3273 (Roundcube, Nextcloud, PHP générique) comparent donc le
// nom NORMALISÉ par `nomPHP`, jamais le nom brut.
//
// Référence : https://raw.githubusercontent.com/php/php-src/PHP-8.2/main/php_variables.c
// récupéré le 2026-10-29, sha256 c0f13d88b964f4801e1baebf91fc4137880621e6976a38e77e40b5935ed29314
// (numéros de ligne de ce fichier : php_register_variable_ex l. 107-,
// php_default_treat_data l. 480-). php_url_decode et php_raw_url_decode viennent
// d'ext/standard/url.c (même branche).
//
// ÉCART AVEC LE BRIEF DE LA TÂCHE 1, tranché par la source : sans « ] » après
// le premier « [ », PHP remplace aussi les « ' ' », « . » et « [ » de la suite
// par « _ » (l. 236-240) ; le brief disait « recopiée telle quelle ». Donc
// `a[b.c` donne `a_b_c`, pas `a_b.c`.

package main

import "strings"

// occurrencesParNomMax : occurrences gardées par nom retenu, la PREMIÈRE et la
// DERNIÈRE (passe finale M2). PHP garde la dernière valeur d'un nom en double
// (php_register_variable_ex, php_variables.c:107-262, zend_symtable_update) ;
// la première reste gardée pour les noms en tableau (`_from[]`). Un plafond
// global (64 jusqu'ici) se contournait : 64 paramètres de remplissage faisaient
// sortir _from, donc rc-001.
const occurrencesParNomMax = 2

// parametresRetenusMax : plafond de paramètres conservés par requête, déduit
// du plafond par nom : la mémoire reste bornée par noms retenus × 2.
var parametresRetenusMax = occurrencesParNomMax * len(nomsRetenusPHP)

// nomsRetenusPHP : les seuls noms (déjà normalisés) dont on conserve la valeur.
var nomsRetenusPHP = map[string]bool{
	"_from": true, "_uid": true, "_flag": true, "_q": true, "_filter": true,
	"_headers": true, "_scope": true, "_mbox": true, "_search": true,
	"_subject": true, "_replyto": true, "_followupto": true, "_charset": true,
	"_task": true, "_action": true,
}

// nomPHP rend le nom de base que PHP enregistre (php_register_variable_ex,
// php_variables.c:107-262). ok=false quand PHP ignore la variable.
func nomPHP(brut string) (nom string, ok bool) {
	// Chaîne C : arrêt au premier octet nul (l. 131-137, strlen/memcpy).
	if i := strings.IndexByte(brut, 0); i >= 0 {
		brut = brut[:i]
	}
	// l. 132-134 : seuls les espaces « ' ' » de tête sont sautés.
	i := 0
	for i < len(brut) && brut[i] == ' ' {
		i++
	}
	brut = brut[i:]

	// l. 145-155 : « ' ' » et « . » deviennent « _ » ; le premier « [ » arrête.
	// La recherche se fait dans brut lui-même : aucune copie tant que rien ne
	// change (relecture I1), une seule copie sinon (souligner).
	crochet := strings.IndexByte(brut, '[')
	// l. 156-162 : base vide (y compris « [ » initial, R-W2) : variable ignorée.
	if len(brut) == 0 || crochet == 0 {
		return "", false
	}
	if crochet < 0 {
		return souligner(brut, false), true
	}
	// l. 226-232 : « ] » plus loin (le seul caractère blanc sauté n'est pas « ] »).
	if strings.IndexByte(brut[crochet+1:], ']') >= 0 {
		return souligner(brut[:crochet], false), true
	}
	// l. 233-249 : pas un index ; le « [ » devient « _ » et, dans la suite,
	// « ' ' », « . » et « [ » aussi (l. 236-240). Avant le premier « [ », il
	// n'y a pas d'autre « [ » : une seule passe suffit.
	return souligner(brut, true), true
}

// souligner remplace par « _ » les « ' ' » et « . » (et les « [ » si crochet),
// OCTET PAR OCTET comme PHP : un octet non UTF-8 reste tel quel. Rien à
// changer : s est rendu sans allocation ; sinon une seule copie.
func souligner(s string, crochet bool) string {
	vise := func(c byte) bool { return c == ' ' || c == '.' || (crochet && c == '[') }
	i := 0
	for i < len(s) && !vise(s[i]) {
		i++
	}
	if i == len(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	b.WriteString(s[:i])
	for ; i < len(s); i++ {
		if vise(s[i]) {
			b.WriteByte('_')
		} else {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// urldecodePHP : php_url_decode (ext/standard/url.c) : « + » → espace, %XX → octet,
// « % » suivi d'autre chose que deux chiffres hexadécimaux laissé tel quel.
func urldecodePHP(s string) string {
	if !strings.ContainsAny(s, "+%") {
		return s
	}
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '+':
			out = append(out, ' ')
		case c == '%' && i+2 < len(s):
			h, ok1 := hexVal(s[i+1])
			l, ok2 := hexVal(s[i+2])
			if ok1 && ok2 {
				out = append(out, h<<4|l)
				i += 2
			} else {
				out = append(out, c)
			}
		default:
			out = append(out, c)
		}
	}
	return string(out)
}

// ParametrePHP : un paramètre retenu, nom normalisé et valeur décodée.
type ParametrePHP struct{ Nom, Valeur string }

// ParametresPHP : résultat de lireParametresPHP.
type ParametresPHP struct {
	Retenus   []ParametrePHP // noms de nomsRetenusPHP seulement, première et dernière occurrence de chacun (retenirPHP)
	Variables int            // segments non vides séparés par « & » (max_input_vars, C4)
	Tronque   bool           // corps coupé par la fenêtre de capture (posé par completerCorps, R-W8 M2)
}

// lireParametresPHP lit une chaîne de requête ou un corps urlencoded comme
// php_default_treat_data (php_variables.c:555-605) : php_strtok_r saute les
// segments vides ; le nom est coupé au premier « = » AVANT d'être décodé ;
// segment sans « = » : valeur vide ; valeur décodée seulement si le nom est retenu.
func lireParametresPHP(brut string) ParametresPHP {
	var p ParametresPHP
	// Boucle sur strings.Cut, sans tranche intermédiaire (relecture I1 :
	// strings.Split allouait ~16 Mo pour 1 Mio de « & »).
	for reste, encore := brut, true; encore; {
		var seg string
		seg, reste, encore = strings.Cut(reste, "&")
		// Chaîne C : un octet nul termine le segment.
		if i := strings.IndexByte(seg, 0); i >= 0 {
			seg = seg[:i]
		}
		if seg == "" {
			continue
		}
		p.Variables++
		nom, val := seg, ""
		if i := strings.IndexByte(seg, '='); i >= 0 {
			nom, val = seg[:i], seg[i+1:]
		}
		n, ok := nomPHP(urldecodePHP(nom))
		if !ok || !nomsRetenusPHP[n] {
			continue
		}
		p.Retenus = retenirPHP(p.Retenus, n, urldecodePHP(val))
	}
	return p
}

// retenirPHP ajoute (nom, valeur) aux paramètres retenus en gardant, pour
// chaque nom, sa première et sa dernière occurrence, quelle que soit leur
// position (passe finale M2) : au-delà de occurrencesParNomMax, la dernière
// gardée est remplacée. L'ordre relatif des valeurs d'un nom est conservé
// (première, puis dernière). Au plus parametresRetenusMax entrées.
func retenirPHP(retenus []ParametrePHP, nom, valeur string) []ParametrePHP {
	vus, dernier := 0, -1
	for i := range retenus {
		if retenus[i].Nom == nom {
			vus++
			dernier = i
		}
	}
	if vus < occurrencesParNomMax {
		return append(retenus, ParametrePHP{Nom: nom, Valeur: valeur})
	}
	retenus[dernier].Valeur = valeur
	return retenus
}

// Valeurs rend toutes les occurrences du nom normalisé, dans l'ordre (nil si aucune).
func (p ParametresPHP) Valeurs(nom string) []string {
	var r []string
	for _, e := range p.Retenus {
		if e.Nom == nom {
			r = append(r, e.Valeur)
		}
	}
	return r
}

// parcourirCookiesPHP : php_default_treat_data, PARSE_COOKIE (php_variables.c:555-605).
// Chaque ligne (chaîne C, coupée au premier octet nul) est coupée sur « ; » (strtok :
// segments vides sautés), blancs de tête (isspace) sautés (l. 570-573), nom jusqu'au
// premier « = » (ligne entière sinon), nom NON décodé (PHP >= 8.0, l. 600), puis nomPHP.
// Nom vide : ignoré (l. 574-576). f reçoit le nom brut et le nom normalisé ; les
// noms que PHP ignore ne sont pas rapportés. Rien n'est stocké.
func parcourirCookiesPHP(lignes []string, f func(brut, nom string)) {
	for _, ligne := range lignes {
		if i := strings.IndexByte(ligne, 0); i >= 0 {
			ligne = ligne[:i]
		}
		for reste, encore := ligne, true; encore; {
			var seg string
			seg, reste, encore = strings.Cut(reste, ";")
			seg = strings.TrimLeft(seg, " \t\n\v\f\r")
			if seg == "" {
				continue
			}
			brut := seg
			if i := strings.IndexByte(seg, '='); i >= 0 {
				brut = seg[:i]
			}
			if brut == "" {
				continue
			}
			if nom, ok := nomPHP(brut); ok {
				f(brut, nom)
			}
		}
	}
}
