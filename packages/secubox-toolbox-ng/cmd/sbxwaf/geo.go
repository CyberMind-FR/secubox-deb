// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Géolocalisation du pays source (#1240).
//
// POURQUOI. Le graphe d'acteurs portait `countries: 0` sur TOUS ses acteurs : le
// WAF n'émettait jamais le pays. Deux conséquences, l'une visible et l'autre pas :
//
//   - une CAMPAGNE se définit chez actord par « plusieurs IP OU plusieurs pays ».
//     Sans pays, la moitié de la définition ne pouvait jamais se déclencher ;
//   - une CARTE du renseignement n'a rien à afficher sans géolocalisation — et
//     une carte qui invente ses points serait pire que pas de carte du tout.
//
// LECTURE LOCALE, JAMAIS UN APPEL RÉSEAU. La base GeoLite2 est un fichier sur la
// box (`/usr/share/GeoIP/GeoLite2-Country.mmdb`). Interroger un service tiers
// pour chaque requête entrante ferait fuiter vers un tiers la liste de nos
// visiteurs — l'inverse exact de ce que cette box défend — et ajouterait une
// latence réseau sur le chemin critique du WAF.
//
// PAYS SEULEMENT, PAS DE VILLE. Le barème n'accorde qu'un point au pays : il
// sert à écarter, jamais à conclure. Une géolocalisation plus fine coûterait une
// base bien plus lourde pour une donnée personnelle qu'on n'utiliserait pas.
package main

import (
	"log"
	"net"
	"sync"

	"github.com/oschwald/maxminddb-golang"
)

// Geo résout le pays d'une adresse depuis une base MaxMind locale.
type Geo struct {
	r  *maxminddb.Reader
	mu sync.RWMutex
}

// NewGeo ouvre la base. Chemin vide ou base illisible = géolocalisation
// désactivée : le WAF continue sans le pays plutôt que de refuser de démarrer.
// Perdre un axe de corrélation ne justifie pas de perdre le pare-feu applicatif.
func NewGeo(chemin string) *Geo {
	if chemin == "" {
		return nil
	}
	r, err := maxminddb.Open(chemin)
	if err != nil {
		log.Printf("sbxwaf: géolocalisation désactivée (%v) — "+
			"les acteurs n'auront pas de pays", err)
		return nil
	}
	log.Printf("sbxwaf: géolocalisation depuis %s (pays seulement, lecture locale)", chemin)
	return &Geo{r: r}
}

// paysEnregistrement ne retient que le code ISO-2. On ne désérialise pas le
// reste de l'enregistrement (noms traduits, continent, Union européenne) :
// c'est du travail par requête pour une donnée dont on ne fait rien.
type paysEnregistrement struct {
	Pays struct {
		Code string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

// Pays rend le code ISO-3166 alpha-2 de l'adresse, ou "" si inconnue, privée,
// ou si la base est absente. Sûr avec un récepteur nil.
func (g *Geo) Pays(adresse string) string {
	if g == nil {
		return ""
	}
	ip := net.ParseIP(adresse)
	if ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() {
		// Une adresse du LAN n'a pas de pays, et lui en inventer un placerait
		// nos propres machines sur la carte des attaquants.
		return ""
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.r == nil {
		return ""
	}
	var e paysEnregistrement
	if err := g.r.Lookup(ip, &e); err != nil {
		return ""
	}
	if len(e.Pays.Code) != 2 {
		// Le contrat d'enveloppe refuse tout ce qui n'est pas ISO-2 : autant ne
		// rien émettre qu'émettre une valeur qui sera rejetée à l'ingestion.
		return ""
	}
	return e.Pays.Code
}

// Close libère la base.
func (g *Geo) Close() {
	if g == nil || g.r == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	_ = g.r.Close()
	g.r = nil
}
