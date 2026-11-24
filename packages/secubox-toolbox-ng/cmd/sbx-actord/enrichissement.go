// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"sort"
	"strings"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/envelope"
	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/reseau"
)

// Campagnes lisibles (#3919) : famille, cibles, classes de réseau, pays et
// part des sources éphémères, pour qu'une carte de campagne se lise sans
// ouvrir la liste de ses acteurs.
//
// POURQUOI PAR SOURCE ET À L'INGESTION. Le graphe ne garde, par acteur, que
// des ensembles (adresses, pays, cibles) : ni le nombre d'événements par
// adresse, ni l'ASN d'une adresse, ni la catégorie. Les recalculer à la
// demande voudrait relire le magasin (376 Mo sur gk2) à chaque requête. On
// tient donc, à l'ingestion, une petite fiche PAR ADRESSE SOURCE ; la
// campagne agrège les fiches de ses adresses, en temps linéaire et sans
// E/S. Clé par adresse plutôt que par acteur : la consolidation (fusion de
// deux acteurs) n'a ainsi rien à recopier.

// ciblesParSourceMax borne les cibles retenues par adresse : un réciteur de
// dictionnaire viserait sinon des centaines de noms par adresse.
const ciblesParSourceMax = 16

// ficheSource : ce qu'actord retient d'une adresse source.
type ficheSource struct {
	evts     int
	asn      uint32
	resolu   bool // ASN déjà cherché dans l'annuaire (enveloppe sans ASN)
	pays     string
	dernier  int64
	familles map[string]int
	cibles   map[string]int
}

// PaysPart : un pays et sa part (en %) des sources d'une campagne.
type PaysPart struct {
	Code string `json:"code"`
	Part int    `json:"part"`
}

// noterSource met à jour la fiche de l'adresse d'un événement. Appelée sous s.mu.
func (s *Server) noterSource(e *envelope.Envelope) {
	if e.SrcIP == "" {
		return
	}
	if s.sources == nil {
		s.sources = map[string]*ficheSource{}
	}
	f := s.sources[e.SrcIP]
	if f == nil {
		f = &ficheSource{familles: map[string]int{}, cibles: map[string]int{}}
		s.sources[e.SrcIP] = f
	}
	f.evts++
	if e.Timestamp > f.dernier {
		f.dernier = e.Timestamp
	}
	if e.ASN != 0 {
		f.asn, f.resolu = e.ASN, true
	} else if !f.resolu {
		// Enveloppe antérieure à l'ASN (ou capteur qui ne le porte pas) :
		// une seule recherche par adresse, dans l'annuaire local d'actord.
		f.asn, f.resolu = s.annuaire.Classer(e.SrcIP).ASN, true
	}
	if e.GeoCountry != "" {
		f.pays = e.GeoCountry
	}
	f.familles[familleEvenement(e)]++
	if e.DstService != "" {
		if _, ok := f.cibles[e.DstService]; ok || len(f.cibles) < ciblesParSourceMax {
			f.cibles[e.DstService]++
		}
	}
}

// familleEvenement : la famille de la catégorie de l'événement. La catégorie
// est la règle d'authwatch (RuleID) ou la première étiquette du WAF ; on
// prend la première qui se range dans une famille.
func familleEvenement(e *envelope.Envelope) string {
	if e.RuleID != "" {
		if f := reseau.Famille(e.RuleID); f != reseau.FamilleAutre {
			return f
		}
	}
	for _, t := range e.BehaviorTags {
		if f := reseau.Famille(t); f != reseau.FamilleAutre {
			return f
		}
	}
	return reseau.FamilleAutre
}

// oublierSources retire les fiches non vues depuis `avant`. Appelée sous s.mu.
func (s *Server) oublierSources(avant int64) {
	for ip, f := range s.sources {
		if f.dernier < avant {
			delete(s.sources, ip)
		}
	}
}

// part rend k/n en pourcentage entier, arrondi au plus proche (moitié vers le
// haut) : 50/60 → 83.
func part(k, n int) int {
	if n == 0 {
		return 0
	}
	return (k*100 + n/2) / n
}

// cleCompte : une cible qui est un compte (adresse de messagerie) plutôt
// qu'un hôte ou un service. Seule celle-là est masquée.
func cleCompte(c string) bool { return strings.Contains(c, "@") }

// enrichir calcule les champs lisibles d'une campagne depuis les fiches de
// ses adresses. Appelée sous s.mu.
func (s *Server) enrichir(g *campagne, ips map[string]bool) {
	n := len(ips)
	classes := map[string]int{}
	pays := map[string]int{}
	familles := map[string]int{}
	cibles := map[string]int{}
	classeDe := map[uint32]string{} // un verrou d'annuaire par ASN, pas par adresse
	une, le3 := 0, 0
	for ip := range ips {
		f := s.sources[ip]
		if f == nil {
			classes[reseau.ClasseInconnu]++
			continue
		}
		cl, ok := classeDe[f.asn]
		if !ok {
			cl = s.annuaire.ClasseASN(f.asn)
			classeDe[f.asn] = cl
		}
		classes[cl]++
		if f.pays != "" {
			pays[f.pays]++
		}
		if f.evts == 1 {
			une++
		}
		if f.evts >= 1 && f.evts <= 3 {
			le3++
		}
		for k, v := range f.familles {
			familles[k] += v
		}
		for k, v := range f.cibles {
			cibles[k] += v
		}
	}

	g.Classes = make(map[string]int, len(classes))
	for k, v := range classes {
		g.Classes[k] = part(v, n)
	}
	g.PaysTop = []PaysPart{}
	for _, k := range premiers(pays, 3) {
		g.PaysTop = append(g.PaysTop, PaysPart{Code: k, Part: part(pays[k], n)})
	}
	g.CiblesNoms = []string{}
	for _, k := range premiers(cibles, 3) {
		if cleCompte(k) {
			k = reseau.MasquerCompte(k)
		}
		g.CiblesNoms = append(g.CiblesNoms, k)
	}
	// La famille est la plus fréquente parmi les événements rangés ; « autre »
	// seulement quand aucun ne l'est.
	g.Famille = reseau.FamilleAutre
	delete(familles, reseau.FamilleAutre)
	if p := premiers(familles, 1); len(p) == 1 {
		g.Famille = p[0]
	}
	g.Une, g.Le3 = part(une, n), part(le3, n)
	g.Rotation = g.Le3 >= 80 && n >= 50
}

// premiers rend les max clés de plus forte valeur, égalités par ordre
// alphabétique (reproductible d'une requête à l'autre).
func premiers(m map[string]int, max int) []string {
	cles := make([]string, 0, len(m))
	for k, v := range m {
		if v > 0 {
			cles = append(cles, k)
		}
	}
	sort.Slice(cles, func(i, j int) bool {
		if m[cles[i]] != m[cles[j]] {
			return m[cles[i]] > m[cles[j]]
		}
		return cles[i] < cles[j]
	})
	if len(cles) > max {
		cles = cles[:max]
	}
	return cles
}
