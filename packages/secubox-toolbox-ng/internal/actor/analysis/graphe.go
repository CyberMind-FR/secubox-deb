// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package analysis

import (
	"net"
	"sort"
)

// Graphe d'un acteur : ACTEUR → IP / APPAREIL, CIBLE, CAPTEUR, ASN, PAYS, AUTRE ACTEUR. Il répond à « qui touche-t-il, vu par qui, hébergé où, avec qui
// partage-t-il un mode opératoire ». Plafonné : un acteur à 3 000 adresses (ACT-0001) ne produit pas un graphe de 3 000 nœuds.
const (
	maxIPsGraphe    = 50
	maxCiblesGraphe = 30
	maxPairsGraphe  = 10
)

type Noeud struct {
	ID      string `json:"id"`
	Type    string `json:"type"` // acteur | ip | appareil | cible | capteur | asn | pays | autre_acteur
	Libelle string `json:"libelle"`
	Poids   int    `json:"poids,omitempty"`
}

type Lien struct {
	De       string `json:"de"`
	Vers     string `json:"vers"`
	Relation string `json:"relation"`
}

type Graphe struct {
	Noeuds  []Noeud `json:"noeuds"`
	Liens   []Lien  `json:"liens"`
	Tronque bool    `json:"tronque"`
	Acteur  string  `json:"actor_id"`
}

type EntreeGraphe struct {
	ActeurID string
	IPs      []string
	ASNs     []string
	Pays     []string
	Cibles   []string
	Pairs    []string // acteurs au même mode opératoire (même jeu de cibles)
	Events   []Event
}

func ConstruireGraphe(in EntreeGraphe) Graphe {
	g := Graphe{Acteur: in.ActeurID}
	vus := map[string]bool{}
	ajoute := func(n Noeud, relation string) {
		if !vus[n.ID] {
			vus[n.ID] = true
			g.Noeuds = append(g.Noeuds, n)
		}
		if relation != "" && n.ID != in.ActeurID {
			g.Liens = append(g.Liens, Lien{De: in.ActeurID, Vers: n.ID, Relation: relation})
		}
	}
	ajoute(Noeud{ID: in.ActeurID, Type: "acteur", Libelle: in.ActeurID}, "")
	prem := func(l []string, max int) []string {
		l = dedup(l)
		if len(l) > max {
			g.Tronque = true
			return l[:max]
		}
		return l
	}
	for _, ip := range prem(in.IPs, maxIPsGraphe) {
		typ := "ip"
		if a := net.ParseIP(ip); a != nil && (a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast()) {
			typ = "appareil" // une adresse du réseau local est un appareil, pas une infrastructure distante
		}
		ajoute(Noeud{ID: "ip:" + ip, Type: typ, Libelle: ip}, "utilise")
	}
	for _, c := range prem(in.Cibles, maxCiblesGraphe) {
		ajoute(Noeud{ID: "cible:" + c, Type: "cible", Libelle: c}, "vise")
	}
	compte := map[string]int{}
	for _, e := range in.Events {
		compte[e.Sensor]++
	}
	capteurs := make([]string, 0, len(compte))
	for k := range compte {
		capteurs = append(capteurs, k)
	}
	sort.Strings(capteurs)
	for _, c := range capteurs {
		ajoute(Noeud{ID: "capteur:" + c, Type: "capteur", Libelle: c, Poids: compte[c]}, "vu par")
	}
	for _, a := range prem(in.ASNs, 20) {
		ajoute(Noeud{ID: "asn:" + a, Type: "asn", Libelle: a}, "hébergé par")
	}
	for _, p := range prem(in.Pays, 20) {
		ajoute(Noeud{ID: "pays:" + p, Type: "pays", Libelle: p}, "situé en")
	}
	for _, p := range prem(in.Pairs, maxPairsGraphe) {
		ajoute(Noeud{ID: p, Type: "autre_acteur", Libelle: p}, "même mode opératoire")
	}
	return g
}

func dedup(l []string) []string {
	m := map[string]bool{}
	var out []string
	for _, s := range l {
		if s != "" && !m[s] {
			m[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}
