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

// baseASN est ce que l'annuaire exige d'une base : *maxminddb.Reader la
// satisfait, un test y met une fausse base.
type baseASN interface {
	Lookup(ip net.IP, result any) error
	Close() error
}

// ouvrirBase ouvre une base ; variable de paquet pour que les tests l'injectent.
var ouvrirBase = func(chemin string) (baseASN, error) {
	r, err := maxminddb.Open(chemin)
	if err != nil {
		return nil, err
	}
	return r, nil
}

// Annuaire résout une adresse en Info. Sûr avec un récepteur nil.
type Annuaire struct {
	mu         sync.RWMutex
	r          baseASN
	classes    map[uint32]string
	chemin     string
	catalogues []string
}

// Ouvrir charge la base et les catalogues. Base absente ou illisible,
// catalogue absent : annuaire dégradé mais utilisable (tout « inconnu »),
// jamais nil ni panique.
func Ouvrir(cheminMMDB string, catalogues ...string) *Annuaire {
	a := &Annuaire{chemin: cheminMMDB, catalogues: catalogues, classes: map[uint32]string{}}
	a.r = ouvrirBaseOuNil(cheminMMDB)
	a.classes = chargerCatalogues(catalogues)
	return a
}

func ouvrirBaseOuNil(chemin string) baseASN {
	if chemin == "" {
		return nil
	}
	r, err := ouvrirBase(chemin)
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
	var nouvelle baseASN
	if a.chemin != "" {
		nouvelle = ouvrirBaseOuNil(a.chemin)
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
