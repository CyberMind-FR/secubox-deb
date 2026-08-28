// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"net"
	"strings"
)

// Détection d'anomalie d'hôte (#1070, phase A).
//
// sbxwaf compare déjà le Host à la table de routes ; un hôte absent recevait un
// simple 421, NI banni NI journalisé. C'est le plus gros angle mort : un vrai
// navigateur n'envoie jamais un Host qu'on ne sert pas. On classe donc ces
// hôtes comme signal scanner.
//
// Signaux FORTS (ban premier coup) : Host vide, IP brute, nom généré (DGA) —
// aucun usage légitime. Signal FAIBLE (gradué) : un nom plausible mais non
// routé, qui PEUT être un lien périmé légitime.

// HostClass décrit le verdict de classification d'un Host non routé.
type HostClass struct {
	Name   string // "empty" | "ip_literal" | "dga" | "unrouted"
	Sev    string // "high" | "medium"
	Strong bool   // true → ban premier coup ; false → gradué
}

// classifyHost catégorise un Host que le WAF ne sert pas. `host` est déjà
// dépouillé de son port et mis en minuscules par l'appelant.
func classifyHost(host string) HostClass {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" {
		return HostClass{Name: "empty", Sev: "high", Strong: true}
	}
	// IP littérale (v4 ou v6, éventuellement entre crochets) : personne ne vise
	// un vhost nommé par son IP — c'est du balayage.
	probe := h
	if strings.HasPrefix(probe, "[") {
		if i := strings.IndexByte(probe, ']'); i > 0 {
			probe = probe[1:i]
		}
	}
	if net.ParseIP(probe) != nil {
		return HostClass{Name: "ip_literal", Sev: "high", Strong: true}
	}
	if estDGA(h) {
		return HostClass{Name: "dga", Sev: "high", Strong: true}
	}
	return HostClass{Name: "unrouted", Sev: "medium", Strong: false}
}

// estPremierePartie dit si `host` relève d'un de NOS suffixes de première partie
// (les mêmes que le bandeau : gk2.secubox.in, secubox.in, …). Un hôte sous notre
// propre domaine qui n'est pas routé n'est JAMAIS un scanner : c'est un alias ou
// un lien que l'on n'a pas (encore) câblé — l'appli Nextcloud iOS pointant sur
// `nextcloud.gk2.secubox.in`, un vieux marque-page. Le bannir coupe un vrai
// utilisateur, et en CGNAT mobile tous ceux qui partagent son IP (#1266). On le
// signale, on ne le bannit pas. Correspondance sur frontière de label : égal au
// suffixe, ou s'y terminant par « .suffixe » — jamais un simple contains.
func estPremierePartie(host string, suffixes []string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	if i := strings.IndexByte(h, ':'); i >= 0 {
		h = h[:i] // au cas où un port subsiste
	}
	for _, s := range suffixes {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" {
			continue
		}
		if h == s || strings.HasSuffix(h, "."+s) {
			return true
		}
	}
	return false
}

// estDGA juge l'étiquette la plus à gauche (le sous-domaine variable) d'un nom :
// un nom généré par algorithme est long, pauvre en voyelles, souvent riche en
// chiffres et en caractères distincts. Heuristique volontairement prudente
// (seuils hauts) pour limiter les faux positifs sur des sous-domaines légitimes
// générés — le seuil est un point ouvert du design #1070.
func estDGA(host string) bool {
	label := host
	if i := strings.IndexByte(host, '.'); i > 0 {
		label = host[:i]
	}
	n := len(label)
	if n < 10 {
		return false // trop court pour juger sans bruit
	}
	var voyelles, chiffres, tirets int
	distincts := map[rune]bool{}
	for _, c := range label {
		switch {
		case strings.ContainsRune("aeiouy", c):
			voyelles++
		case c >= '0' && c <= '9':
			chiffres++
		case c == '-':
			tirets++
		}
		distincts[c] = true
	}
	// Un vrai nom à rallonge composé de mots séparés par des tirets
	// (« mon-service-interne-2 ») n'est pas un DGA : les tirets abaissent le score.
	if tirets >= 2 {
		return false
	}
	fn := float64(n)
	ratioVoy := float64(voyelles) / fn
	ratioChiffres := float64(chiffres) / fn
	diversite := float64(len(distincts)) / fn
	switch {
	case ratioVoy < 0.20 && n >= 12: // quasi imprononçable
		return true
	case ratioChiffres > 0.35 && n >= 10: // saupoudré de chiffres
		return true
	case ratioVoy < 0.28 && diversite > 0.72 && n >= 15: // long, dense, sans voyelles
		return true
	default:
		return false
	}
}
