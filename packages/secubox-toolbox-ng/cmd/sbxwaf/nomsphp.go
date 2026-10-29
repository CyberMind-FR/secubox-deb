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

// parametresRetenusMax : plafond de paramètres conservés par requête.
// Seuil provisoire, non sourcé (2026-10-29).
const parametresRetenusMax = 64

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
	b := []byte(brut)
	crochet := -1
	for p := 0; p < len(b); p++ {
		if b[p] == ' ' || b[p] == '.' {
			b[p] = '_'
		} else if b[p] == '[' {
			crochet = p
			break
		}
	}
	// l. 156-162 : base vide (y compris « [ » initial, R-W2) : variable ignorée.
	base := len(b)
	if crochet >= 0 {
		base = crochet
	}
	if base == 0 {
		return "", false
	}
	if crochet < 0 {
		return string(b), true
	}
	// l. 226-232 : « ] » plus loin (le seul caractère blanc sauté n'est pas « ] »).
	if strings.IndexByte(string(b[crochet+1:]), ']') >= 0 {
		return string(b[:base]), true
	}
	// l. 233-249 : pas un index ; le « [ » devient « _ » et, dans la suite,
	// « ' ' », « . » et « [ » aussi (l. 236-240).
	b[crochet] = '_'
	for p := crochet + 1; p < len(b); p++ {
		if b[p] == ' ' || b[p] == '.' || b[p] == '[' {
			b[p] = '_'
		}
	}
	return string(b), true
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
	Retenus   []ParametrePHP // seulement les noms de nomsRetenusPHP, au plus parametresRetenusMax, dans l'ordre
	Variables int            // segments non vides séparés par « & » (max_input_vars, C4)
}

// lireParametresPHP lit une chaîne de requête ou un corps urlencoded comme
// php_default_treat_data (php_variables.c:555-605) : php_strtok_r saute les
// segments vides ; le nom est coupé au premier « = » AVANT d'être décodé ;
// segment sans « = » : valeur vide ; valeur décodée seulement si le nom est retenu.
func lireParametresPHP(brut string) ParametresPHP {
	var p ParametresPHP
	for _, seg := range strings.Split(brut, "&") {
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
		if !ok || !nomsRetenusPHP[n] || len(p.Retenus) >= parametresRetenusMax {
			continue
		}
		p.Retenus = append(p.Retenus, ParametrePHP{Nom: n, Valeur: urldecodePHP(val)})
	}
	return p
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
		for _, seg := range strings.Split(ligne, ";") {
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
