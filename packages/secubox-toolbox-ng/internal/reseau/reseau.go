// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Annuaire de réseaux : ASN, organisation et classe d'une adresse (#3919).
//
// LECTURE LOCALE, JAMAIS UN APPEL RÉSEAU (même raison que la géolocalisation
// du WAF) : la base GeoLite2-ASN est un fichier de la box. Les catalogues de
// classes sont fusionnés dans l'ordre, le dernier gagnant ASN par ASN
// (livré, puis surcharge de l'opérateur).
package reseau

import (
	"log"
	"net"
	"sync"
	"unicode/utf8"

	"github.com/oschwald/maxminddb-golang"
)

// Info décrit le réseau d'une adresse.
type Info struct {
	ASN    uint32
	Org    string
	Classe string
}

// Annuaire résout une adresse en Info. Sûr avec un récepteur nil.
type Annuaire struct {
	mu         sync.RWMutex
	r          *maxminddb.Reader
	classes    map[uint32]string
	chemin     string
	catalogues []string
}

// Ouvrir charge la base et les catalogues. Base absente ou illisible,
// catalogue absent : annuaire dégradé mais utilisable (tout « inconnu »),
// jamais nil ni panique.
func Ouvrir(cheminMMDB string, catalogues ...string) *Annuaire {
	a := &Annuaire{chemin: cheminMMDB, catalogues: catalogues, classes: map[uint32]string{}}
	a.r = ouvrirBase(cheminMMDB)
	a.classes = chargerCatalogues(catalogues)
	return a
}

func ouvrirBase(chemin string) *maxminddb.Reader {
	if chemin == "" {
		return nil
	}
	r, err := maxminddb.Open(chemin)
	if err != nil {
		log.Printf("reseau: base ASN indisponible (%v) — classes inconnues", err)
		return nil
	}
	return r
}

func chargerCatalogues(chemins []string) map[uint32]string {
	res := map[uint32]string{}
	for _, c := range chemins {
		if c == "" {
			continue
		}
		m, err := lireFichierCatalogue(c)
		if err != nil {
			log.Printf("reseau: catalogue %s ignoré (%v)", c, err)
			continue
		}
		for asn, cl := range m {
			res[asn] = cl
		}
	}
	return res
}

type enregistrementASN struct {
	ASN uint32 `maxminddb:"autonomous_system_number"`
	Org string `maxminddb:"autonomous_system_organization"`
}

// Classer rend ASN, organisation et classe. Adresse invalide, privée ou
// non routable : Info{Classe: "inconnu"}.
func (a *Annuaire) Classer(ip string) Info {
	vide := Info{Classe: ClasseInconnu}
	if a == nil {
		return vide
	}
	p := net.ParseIP(ip)
	if p == nil || !p.IsGlobalUnicast() || p.IsPrivate() {
		return vide
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.r == nil {
		return vide
	}
	var e enregistrementASN
	if err := a.r.Lookup(p, &e); err != nil || e.ASN == 0 {
		return vide
	}
	classe := a.classes[e.ASN]
	if classe == "" {
		classe = ClasseInconnu
	}
	return Info{ASN: e.ASN, Org: e.Org, Classe: classe}
}

// Recharger rouvre la base et relit les catalogues. Si la nouvelle base est
// illisible, l'ancienne est gardée (une mise à jour tronquée ne doit pas
// aveugler le WAF).
func (a *Annuaire) Recharger() {
	if a == nil {
		return
	}
	classes := chargerCatalogues(a.catalogues)
	var nouvelle *maxminddb.Reader
	if a.chemin != "" {
		nouvelle = ouvrirBase(a.chemin)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.classes = classes
	if nouvelle != nil {
		if a.r != nil {
			_ = a.r.Close()
		}
		a.r = nouvelle
	}
}

// Close libère la base.
func (a *Annuaire) Close() {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.r != nil {
		_ = a.r.Close()
		a.r = nil
	}
}

// MasquerCompte ne garde que les 3 premiers caractères d'un compte, suivis de
// « … » ; 3 caractères ou moins : « … » seul (rien à révéler).
func MasquerCompte(c string) string {
	if utf8.RuneCountInString(c) <= 3 {
		return "…"
	}
	r := []rune(c)
	return string(r[:3]) + "…"
}
