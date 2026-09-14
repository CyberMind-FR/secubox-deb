// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

// EMPREINTE COMPORTEMENTALE — déduire l'outil de ce qu'il FAIT (#1290).
//
// POURQUOI L'USER-AGENT NE SUFFIT PAS. `toolprint.go` nomme un outil quand il
// s'annonce : nuclei, sqlmap et wpscan se déclarent par défaut, et c'est un
// signal certain tant que personne ne s'en cache. Mais c'est une ligne à
// changer — `-H "User-Agent: Mozilla/5.0"` — et l'outil devient anonyme sans
// rien perdre de sa méthode.
//
// CE QU'UN OUTIL NE PEUT PAS FALSIFIER AUSSI FACILEMENT, c'est la FORME de ses
// requêtes : quels en-têtes il envoie, dans quel ordre, lesquels il omet. Cette
// forme vient de sa bibliothèque HTTP, pas de sa configuration. Changer l'UA
// coûte un argument ; changer la forme coûte de réécrire son client.
//
// Trois choses manquent à un client automatique et ne manquent jamais à un
// navigateur, parce qu'un navigateur les envoie sans qu'on le lui demande :
// `Accept-Language`, un `Accept` détaillé, et une négociation de compression.
// Leur absence ne PROUVE rien isolément — un client légitime minimaliste
// existe — mais leur absence CONJUGUÉE à une sonde dans l'espace non routé ne
// laisse plus beaucoup de lectures innocentes.
//
// CE MODULE NE CONDAMNE PAS. Il produit des étiquettes et une empreinte
// stable ; le rapprochement entre acteurs se fait ailleurs, et la sanction
// ailleurs encore.

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"sort"
	"strings"
)

// enTetesNavigateur — ce qu'un vrai navigateur envoie sans y penser.
var enTetesNavigateur = []string{
	"Accept-Language",
	"Accept-Encoding",
	"Sec-Fetch-Mode",
	"Sec-Fetch-Site",
	"Upgrade-Insecure-Requests",
}

// signatureEnTetes rend une empreinte STABLE de la forme de la requête :
// la liste ordonnée des noms d'en-têtes, plus la version HTTP.
//
// ORDRE PRÉSERVÉ, ET C'EST LE POINT. Go range les en-têtes dans une map, donc
// l'ordre d'arrivée est perdu — sauf qu'il est conservé dans `r.Header`'s
// `Host`/ordre de clés ? Non : il ne l'est pas. On travaille donc sur
// l'ENSEMBLE trié, qui reste discriminant (quels en-têtes, pas dans quel
// ordre) et, lui, parfaitement reproductible. Nommer cette limite vaut mieux
// que prétendre à un JA4H qu'on ne calcule pas.
func signatureEnTetes(r *http.Request) string {
	noms := make([]string, 0, len(r.Header))
	for n := range r.Header {
		// Les en-têtes de transport ajoutés par nos propres relais diraient
		// notre infrastructure, pas le client : ils fausseraient l'empreinte.
		ln := strings.ToLower(n)
		if strings.HasPrefix(ln, "x-forwarded") || ln == "x-real-ip" ||
			strings.HasPrefix(ln, "x-secubox") {
			continue
		}
		noms = append(noms, ln)
	}
	sort.Strings(noms)
	h := sha256.New()
	h.Write([]byte(r.Proto))
	h.Write([]byte{0x1f})
	h.Write([]byte(strings.Join(noms, ",")))
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// traitsComportementaux étiquette ce que la requête révèle de son émetteur.
// Chaque étiquette est un FAIT observable, jamais une conclusion.
func traitsComportementaux(r *http.Request) []string {
	var t []string

	manquants := 0
	for _, n := range enTetesNavigateur {
		if r.Header.Get(n) == "" {
			manquants++
		}
	}
	switch {
	case manquants == len(enTetesNavigateur):
		t = append(t, "entetes:aucun-trait-navigateur")
	case manquants >= 3:
		t = append(t, "entetes:pauvres")
	}

	if r.Header.Get("Accept") == "" {
		t = append(t, "entetes:sans-accept")
	} else if r.Header.Get("Accept") == "*/*" {
		// `*/*` seul est la valeur par défaut de presque toutes les
		// bibliothèques HTTP — et de presque aucun navigateur.
		t = append(t, "entetes:accept-generique")
	}
	if r.Header.Get("Accept-Encoding") == "" {
		t = append(t, "entetes:sans-compression")
	}
	if r.Proto == "HTTP/1.0" {
		t = append(t, "http:1.0")
	}
	if strings.EqualFold(r.Header.Get("Connection"), "close") {
		// Une connexion jetée après une requête : le client ne compte pas
		// revenir, ce qui est le propre d'un balayage.
		t = append(t, "http:connexion-jetable")
	}
	if r.Header.Get("Referer") == "" && r.URL.Path != "/" {
		// Un chemin profond atteint sans référent n'a pas été suivi depuis une
		// page : il a été DEVINÉ.
		t = append(t, "nav:chemin-devine")
	}
	if r.Header.Get("Cookie") == "" {
		t = append(t, "nav:sans-cookie")
	}
	return t
}

// familleDeduite propose une famille d'outil à partir des seuls traits, sans
// regarder l'User-Agent. La valeur rendue porte TOUJOURS un « ? » : c'est une
// déduction, et le format le dit.
//
// On ne nomme jamais un outil précis ici. Deux bibliothèques différentes
// produisent des formes proches, et un faux nom coûte plus cher qu'une famille
// honnête — c'est la même règle que dans toolprint.go.
func familleDeduite(traits []string, famille familleSonde) string {
	ens := make(map[string]bool, len(traits))
	for _, x := range traits {
		ens[x] = true
	}
	automate := ens["entetes:aucun-trait-navigateur"] || ens["entetes:pauvres"]
	if !automate {
		return ""
	}
	switch {
	case famille == sondeSecret || famille == sondeGit:
		return "moissonneur-secrets?"
	case famille == sondeCMS:
		return "scanner-cms?"
	case famille == sondeAdmin || famille == sondeInfo:
		return "sondeur-console?"
	case ens["entetes:accept-generique"] && ens["nav:chemin-devine"]:
		return "fuzzer-repertoire?"
	default:
		return "client-automatise?"
	}
}
