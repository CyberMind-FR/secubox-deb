// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// SecuBox-Deb :: toolbox-ng :: sbxwaf — étiquettes d'outil d'attaque (#3273)
//
// Une étiquette reconnaît l'empreinte d'un outil, pas une attaque. Elle
// AGGRAVE une ligne qui existe déjà : le trait « outil:<étiquette> » part vers
// actord avec la ligne, et le champ tool prend l'étiquette s'il est vide. Elle
// ne relève jamais la gravité et ne crée jamais de signal à elle seule.
// Seule exception : la sonde PHP-CGI « -d allow_url_include » (contrôle
// sonde_php_cgi), qui vaut un signal medium sur un vhost PHP.
//
// Rien ne se calcule avant le relais : analyserRequetePHP les calcule, sous
// son recover, et seulement si une ligne de détection est à écrire (ou si la
// signature sonde_php_cgi est chargée). Le journal ne porte que l'étiquette :
// jamais la frontière, le chemin brut ni une valeur de paramètre.

package main

import (
	"net/http"
	"strings"
)

const (
	etiquettePoC49113 = "poc-cve-2025-49113"   // frontière contenant a_rule_for_WAF_to_block_fool_exploitation
	etiquetteSondeCGI = "sonde-php-cgi"        // sondePHPCGI(rawQuery)
	etiquetteOwnCloud = "sonde-owncloud"       // /apps/graphapi/, paramètre ou en-tête OC-Signature / OC-Credential
	etiquetteFPM11043 = "sonde-cve-2019-11043" // chemin brut contenant %0a ou %0d
)

// boundaryPoC49113 : la frontière de la preuve de concept publique de
// CVE-2025-49113 (spécification § 3.1).
const boundaryPoC49113 = "a_rule_for_waf_to_block_fool_exploitation"

// sondePHPCGI : la chaîne de requête décodée comme PHP (urldecodePHP) porte
// « allow_url_include » (sans casse) précédé d'un jeton -d ou \xADd (soft
// hyphen, CVE-2024-4577), en début de chaîne ou après un blanc ou « & ».
// PHP-CGI prend une requête sans « = » pour sa ligne de commande (CVE-2012-1823).
func sondePHPCGI(rawQuery string) bool {
	if rawQuery == "" {
		return false
	}
	d := minusculesASCII(urldecodePHP(rawQuery)) // ASCII seul : ToLower réécrirait l'octet 0xAD
	const nom = "allow_url_include"
	depuis := 0
	for {
		i := strings.Index(d[depuis:], nom)
		if i < 0 {
			return false
		}
		i += depuis
		depuis = i + 1
		// Blancs entre le jeton et le nom, puis le jeton lui-même.
		av := strings.TrimRight(d[:i], " \t")
		var debut int
		switch {
		case strings.HasSuffix(av, "-d"):
			debut = len(av) - 2
		case strings.HasSuffix(av, "\xadd"):
			debut = len(av) - 2
			// « %C2%AD » : l'octet 0xAD précédé de 0xC2 (UTF-8).
			if debut > 0 && av[debut-1] == 0xc2 {
				debut--
			}
		default:
			continue
		}
		if debut == 0 || av[debut-1] == ' ' || av[debut-1] == '\t' || av[debut-1] == '&' {
			return true
		}
	}
}

// requeteNomme : un paramètre de la requête brute porte ce nom (déjà en
// minuscules), après urldecodePHP et sans casse. Aucune allocation de table.
func requeteNomme(rawQuery string, noms ...string) bool {
	for rawQuery != "" {
		var seg string
		seg, rawQuery, _ = strings.Cut(rawQuery, "&")
		nom, _, _ := strings.Cut(seg, "=")
		nom = minusculesASCII(urldecodePHP(nom))
		for _, n := range noms {
			if nom == n {
				return true
			}
		}
	}
	return false
}

// etiquettesOutilPHP rend les étiquettes d'une requête, dans l'ordre poc, cgi,
// owncloud, 11043 ; nil si aucune. rawPath : le chemin brut (EscapedPath), seul
// à porter un %0a que le décodage aurait déjà consommé. Elle lit des en-têtes,
// le chemin et la chaîne de requête : jamais le corps.
func etiquettesOutilPHP(r *http.Request, rawPath string) []string {
	var out []string
	if b, ok := boundaryPHP(r.Header.Get("Content-Type")); ok &&
		strings.Contains(strings.ToLower(b), boundaryPoC49113) {
		out = append(out, etiquettePoC49113)
	}
	if sondePHPCGI(r.URL.RawQuery) {
		out = append(out, etiquetteSondeCGI)
	}
	chemin := strings.ToLower(r.URL.Path)
	if strings.Contains(chemin, "/apps/graphapi/") ||
		requeteNomme(r.URL.RawQuery, "oc-signature", "oc-credential") ||
		r.Header.Get("OC-Signature") != "" || r.Header.Get("OC-Credential") != "" {
		out = append(out, etiquetteOwnCloud)
	}
	brut := strings.ToLower(rawPath)
	if strings.Contains(brut, "%0a") || strings.Contains(brut, "%0d") ||
		strings.ContainsAny(r.URL.Path, "\r\n") {
		out = append(out, etiquetteFPM11043)
	}
	return out
}
