// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// SecuBox-Deb :: toolbox-ng :: sbxwaf — signatures PHP génériques (#3273, R-PHP1 à R-PHP4)
//
// Ces contrôles repèrent les sondes de failles de PHP lui-même, quelle que
// soit l'application derrière :
//   - R-PHP1 (CVE-2023-0662) : plus de 1 020 parties multipart. Aucun code ici :
//     c'est le contrôle parties_nombre de #3257, avec parties_min 1021 ;
//   - R-PHP2 (CVE-2023-3823) : DOCTYPE ou ENTITY dans le prologue XML d'une
//     requête DAV ou XML (xml_dtd_prologue) ;
//   - R-PHP3 (CVE-2024-2756) : faux cookie __Host- ou __Secure- obtenu par la
//     normalisation des noms de PHP (cookie_prefixe_normalise) ;
//   - R-PHP4 (CVE-2024-8925) : frontière multipart de plus de 70 caractères
//     (frontiere_longueur ; le statut malforme est posé par analyserMultipart).
//
// MODE DETECT SEULEMENT, comme tout #3273. Le journal ne porte que des
// booléens et des compteurs : jamais une valeur de cookie ni un octet du DTD.

package main

import (
	"bytes"
	"strings"
)

// prologueXMLMax borne le prologue XML capturé, sans jeton (R-W2, point 10).
// Seuil provisoire, non sourcé (2026-10-29), spécification § 3.7.
const prologueXMLMax = 4096

// frontiereRFC2046 : une frontière « must be no longer than 70 characters »
// (RFC 2046 §5.1.1).
const frontiereRFC2046 = 70

// methodesDAV : méthodes WebDAV, CalDAV et CardDAV dont le corps est du XML
// (spécification § 3.7).
var methodesDAV = map[string]bool{
	"PROPFIND": true, "PROPPATCH": true, "REPORT": true, "SEARCH": true,
	"LOCK": true, "MKCOL": true, "MKCALENDAR": true,
}

// estXMLPHP dit si le corps de la requête est du XML à examiner : méthode DAV
// (comparée en majuscules), ou Content-Type coupé comme estMultipartPHP
// (minuscules, premier `;`, `,` ou espace) égal à application/xml ou text/xml.
func estXMLPHP(methode, contentType string) bool {
	if methodesDAV[strings.ToUpper(methode)] {
		return true
	}
	ct := minusculesASCII(contentType)
	if i := strings.IndexAny(ct, ";, "); i >= 0 {
		ct = ct[:i]
	}
	return ct == "application/xml" || ct == "text/xml"
}

// debutBalise dit si c peut commencer le nom d'un élément XML : lettre, `_` ou `:`.
func debutBalise(c byte) bool {
	return c == '_' || c == ':' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// prefixeSansCasse : strncasecmp(b, p, len(p)) == 0 en ASCII (p en minuscules).
func prefixeSansCasse(b []byte, p string) bool {
	if len(b) < len(p) {
		return false
	}
	for i := 0; i < len(p); i++ {
		c := b[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		if c != p[i] {
			return false
		}
	}
	return true
}

// prologueAvecDTD dit si le prologue du document contient <!DOCTYPE ou <!ENTITY
// (sans casse). Le prologue va du début de debut jusqu'au premier `<` suivi
// d'une lettre, de `_` ou de `:` (l'élément racine) ; les commentaires et les
// instructions de traitement sont sautés en entier, pour qu'un `<a` caché dans
// un commentaire ne referme pas le prologue trop tôt. Un BOM UTF-16 (FF FE ou
// FE FF) fait ne garder qu'un octet sur deux, l'octet non nul. Ne lit que
// debut (au plus prologueXMLMax octets, fournis par la capture).
func prologueAvecDTD(debut []byte) bool {
	if len(debut) >= 2 && ((debut[0] == 0xFF && debut[1] == 0xFE) || (debut[0] == 0xFE && debut[1] == 0xFF)) {
		// Little-endian : l'octet bas est le premier de chaque paire ; big-endian : le second.
		decal := 2
		if debut[0] == 0xFE {
			decal = 3
		}
		simple := make([]byte, 0, len(debut)/2)
		for i := decal; i < len(debut); i += 2 {
			simple = append(simple, debut[i])
		}
		debut = simple
	}
	for i := 0; i < len(debut); i++ {
		if debut[i] != '<' || i+1 >= len(debut) {
			continue
		}
		reste := debut[i:]
		switch c := reste[1]; {
		case debutBalise(c):
			return false // élément racine : fin du prologue
		case prefixeSansCasse(reste, "<!doctype"), prefixeSansCasse(reste, "<!entity"):
			return true
		case prefixeSansCasse(reste, "<!--"):
			fin := bytes.Index(reste[4:], []byte("-->"))
			if fin < 0 {
				return false
			}
			i += 4 + fin + 2
		case c == '?':
			fin := bytes.Index(reste[2:], []byte("?>"))
			if fin < 0 {
				return false
			}
			i += 2 + fin + 1
		}
	}
	return false
}

// cookieFauxPrefixe dit si un cookie des lignes `Cookie` a un nom normalisé par
// PHP qui commence par __Host- ou __Secure- alors que son nom brut n'y
// commence pas (CVE-2024-2756) : `_[Host-x=y` devient `__Host-x`. Parcours
// linéaire (parcourirCookiesPHP), rien n'est stocké ni journalisé.
func cookieFauxPrefixe(lignes []string) bool {
	faux := false
	parcourirCookiesPHP(lignes, func(brut, nom string) {
		if faux {
			return
		}
		if prefixeCookie(nom) && !prefixeCookie(brut) {
			faux = true
		}
	})
	return faux
}

// prefixeCookie : le nom commence par __Host- ou __Secure-.
func prefixeCookie(nom string) bool {
	return strings.HasPrefix(nom, "__Host-") || strings.HasPrefix(nom, "__Secure-")
}
