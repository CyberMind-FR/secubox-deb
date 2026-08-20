// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import "regexp"

// Empreinte d'outils (#1070, phase C) — NOMMER l'outil quand on en est SÛR.
//
// On utilise le maximum d'outils connus, mais on ne colle un nom que si le
// signal est net : un UA qui annonce l'outil (nuclei, sqlmap, wpscan…) est un
// signal certain (ces outils se déclarent par défaut). Un simple chemin
// caractéristique, lui, est corroborant mais pas décisif → on renvoie la
// FAMILLE, pas le nom, avec certain=false. Jamais de faux nom : l'incertitude
// reste explicite. La corroboration par SÉQUENCE (plusieurs sondes) viendra du
// corrélateur (phase D) ; ici on juge une requête.

type toolSig struct {
	name    string
	famille string
	ua      *regexp.Regexp // annonce dans l'UA → certain
	chemin  *regexp.Regexp // motif de chemin caractéristique → corroborant
}

func reI(s string) *regexp.Regexp { return regexp.MustCompile("(?i)" + s) }

// outilsConnus : le maximum d'outils connus. L'UA est la clé du nommage certain ;
// le chemin sert de corroboration (famille probable).
var outilsConnus = []toolSig{
	{"nuclei", "scanner-templates", reI(`nuclei`), reI(`nuclei-templates`)},
	{"sqlmap", "sqli-scanner", reI(`sqlmap`), nil},
	{"nikto", "scanner-web", reI(`nikto`), nil},
	{"wpscan", "cms-scanner", reI(`wpscan`), reI(`/wp-json/wp/v2/users`)},
	{"gobuster", "fuzzer-repertoire", reI(`gobuster`), nil},
	{"feroxbuster", "fuzzer-repertoire", reI(`feroxbuster`), nil},
	{"ffuf", "fuzzer", reI(`\bffuf\b`), nil},
	{"dirbuster", "fuzzer-repertoire", reI(`dirbuster`), nil},
	{"dirsearch", "fuzzer-repertoire", reI(`dirsearch`), nil},
	{"wfuzz", "fuzzer", reI(`wfuzz`), nil},
	{"masscan", "scanner-ports", reI(`masscan`), nil},
	{"nmap", "scanner-ports", reI(`nmap( scripting engine)?`), nil},
	{"zgrab", "scanner-bannieres", reI(`zgrab`), nil},
	{"httpx", "sondeur", reI(`\bhttpx\b`), nil},
	{"katana", "crawler", reI(`katana`), nil},
	{"burp", "proxy-scanner", reI(`burp( ?suite)?`), nil},
	{"acunetix", "scanner-web", reI(`acunetix`), nil},
	{"nessus", "scanner-vuln", reI(`nessus`), nil},
	{"openvas", "scanner-vuln", reI(`openvas`), nil},
	{"zap", "proxy-scanner", reI(`\bzap\b|owasp zap`), nil},
}

// identifierOutil nomme l'outil derrière une requête.
//
//   - UA reconnu  → (nom, famille, true)  : nommage certain.
//   - chemin seul → (nom, famille, false) : probable, on expose la famille.
//   - rien        → ("", "", false).
func identifierOutil(ua, path string) (nom, famille string, certain bool) {
	for _, o := range outilsConnus {
		if o.ua != nil && o.ua.MatchString(ua) {
			return o.name, o.famille, true
		}
	}
	for _, o := range outilsConnus {
		if o.chemin != nil && o.chemin.MatchString(path) {
			return o.name, o.famille, false
		}
	}
	return "", "", false
}

// étiquetteOutil renvoie ce qu'on inscrit dans le champ `tool` du journal :
// le nom si certain, sinon « famille? » (probable), sinon vide.
func étiquetteOutil(ua, path string) string {
	nom, fam, certain := identifierOutil(ua, path)
	switch {
	case certain:
		return nom
	case nom != "":
		return fam + "?" // probable : on nomme la famille, pas l'outil
	default:
		return ""
	}
}
