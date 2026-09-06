// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Package features extrait les caractéristiques stables d'un événement brut
// (RFC-0013 §1 sous-module `features`). Ces formes — chemin normalisé, famille
// d'outillage — servent de pivots de corrélation SANS exposer la valeur brute.
//
// La logique reprend celle déjà éprouvée dans sbxwaf (profiler.normaliserChemin,
// toolprint.identifierOutil, visitstats.classifyUA), ré-implémentée ici parce que
// ces symboles vivent dans `package main` (non importable) ; l'objectif est la
// PARITÉ de comportement, pas une deuxième heuristique divergente.
package features

import (
	"regexp"
	"strings"
)

// MaxPathShape borne la longueur du chemin normalisé (aligné sur envelope).
const MaxPathShape = 256

var (
	reUUID  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	reHex   = regexp.MustCompile(`^[0-9a-f]{16,}$`)
	reDigit = regexp.MustCompile(`^\d+$`)
	// jeton opaque : long, mélange lettres/chiffres (session, token base62/64).
	reTok = regexp.MustCompile(`^[A-Za-z0-9_-]{24,}$`)
)

// PathShape normalise un chemin d'URL en une FORME stable : les segments
// variables (id numérique, UUID, hash hex, jeton opaque) deviennent des
// placeholders, pour que deux requêtes « /files/42 » et « /files/1337 » partagent
// la même grammaire de chemin. La query string est ignorée ; la casse est
// abaissée ; le résultat est borné en longueur.
func PathShape(raw string) string {
	if i := strings.IndexAny(raw, "?#"); i >= 0 {
		raw = raw[:i]
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "/"
	}
	if !strings.HasPrefix(raw, "/") {
		raw = "/" + raw
	}
	raw = strings.ToLower(raw)
	segs := strings.Split(raw, "/")
	for i, s := range segs {
		if s == "" {
			continue
		}
		switch {
		case reUUID.MatchString(s):
			segs[i] = ":uuid"
		case reDigit.MatchString(s):
			segs[i] = ":id"
		case reHex.MatchString(s):
			segs[i] = ":hex"
		case reTok.MatchString(s):
			segs[i] = ":tok"
		default:
			if len(s) > 40 { // segment libre anormalement long : on borne
				segs[i] = s[:40] + "…"
			}
		}
	}
	out := strings.Join(segs, "/")
	if len(out) > MaxPathShape {
		out = out[:MaxPathShape]
	}
	return out
}

// familles d'outillage reconnues, testées par sous-chaîne sur l'UA abaissé.
// L'ordre compte : l'outil offensif prime sur le navigateur/bibliothèque.
var famRules = []struct {
	needle string
	family string
}{
	{"nuclei", "nuclei"}, {"sqlmap", "sqlmap"}, {"nikto", "nikto"},
	{"masscan", "masscan"}, {"nmap", "nmap"}, {"zgrab", "zgrab"},
	{"gobuster", "gobuster"}, {"ffuf", "ffuf"}, {"dirbuster", "dirbuster"},
	{"wpscan", "wpscan"}, {"hydra", "hydra"}, {"feroxbuster", "feroxbuster"},
	{"censys", "scanner-net"}, {"shodan", "scanner-net"}, {"internet-measurement", "scanner-net"},
	{"curl", "curl"}, {"wget", "wget"},
	{"python-requests", "python"}, {"python-urllib", "python"}, {"python/", "python"}, {"aiohttp", "python"},
	{"go-http-client", "go"}, {"okhttp", "java"}, {"java/", "java"},
	{"libwww-perl", "perl"}, {"ruby", "ruby"}, {"axios", "node"}, {"node-fetch", "node"},
	{"googlebot", "crawler"}, {"bingbot", "crawler"}, {"yandexbot", "crawler"},
	{"ahrefsbot", "crawler"}, {"semrushbot", "crawler"}, {"bot", "crawler"}, {"spider", "crawler"},
	{"edg/", "edge"}, {"chrome/", "chrome"}, {"firefox/", "firefox"},
	{"safari/", "safari"}, {"opera", "opera"},
}

// UAFamily réduit un User-Agent à une FAMILLE stable (outil offensif, biblio
// cliente, navigateur, crawler). "" pour un UA absent, "other" pour un UA non
// reconnu. Corréler la famille — pas la chaîne exacte — résiste aux UA aléatoires.
func UAFamily(ua string) string {
	ua = strings.ToLower(strings.TrimSpace(ua))
	if ua == "" {
		return ""
	}
	for _, r := range famRules {
		if strings.Contains(ua, r.needle) {
			return r.family
		}
	}
	// Un UA de navigateur complet contient « mozilla » sans marqueur connu.
	if strings.Contains(ua, "mozilla") {
		return "browser-generic"
	}
	return "other"
}
