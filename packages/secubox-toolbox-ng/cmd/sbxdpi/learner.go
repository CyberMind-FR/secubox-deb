// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// SecuBox-Deb :: toolbox-ng :: sbxdpi :: learner assisté (DPI sémantique L5)
//
// APPRENTISSAGE ASSISTÉ, pas une boîte noire. Le pipeline du brief est
// OBSERVE → CORRELATE → SUGGEST → REVIEW → ACCEPT → RULE ; ce module couvre
// OBSERVE→CORRELATE→SUGGEST : il regroupe les destinations NON classifiées par
// domaine racine (eTLD+1 approché) et propose une règle domain_suffix prête à
// être relue et acceptée par un humain. Aucune suggestion n'est jamais promue
// automatiquement — la promotion (ACCEPT→RULE) est un acte humain côté WebUI.
package main

import (
	"sort"
	"strconv"
	"strings"
)

// twoLevelTLDs : quelques suffixes publics à deux niveaux, pour ne pas couper
// « bbc.co.uk » en « co.uk ». Liste courte volontairement — une SUGGESTION est
// relue ; pas besoin de la Public Suffix List complète ici.
var twoLevelTLDs = map[string]bool{
	"co.uk": true, "org.uk": true, "gov.uk": true, "ac.uk": true,
	"com.au": true, "net.au": true, "org.au": true,
	"co.jp": true, "co.nz": true, "com.br": true, "com.cn": true, "com.tr": true,
}

// registrable renvoie le domaine enregistrable approché (eTLD+1). Un hôte à un
// seul label ou vide renvoie tel quel.
func registrable(host string) string {
	host = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(host, ".")))
	labels := strings.Split(host, ".")
	n := len(labels)
	if n <= 2 {
		return host
	}
	last2 := labels[n-2] + "." + labels[n-1]
	if twoLevelTLDs[last2] && n >= 3 {
		return labels[n-3] + "." + last2
	}
	return last2
}

// suggestion : une proposition de règle issue des inconnus. Toujours accompagnée
// d'un pourquoi (reason) et d'exemples ; jamais présentée comme une vérité.
type suggestion struct {
	Domain       string         `json:"domain"`
	Subdomains   int            `json:"subdomains"`
	Flows        uint64         `json:"flows"`
	Bytes        uint64         `json:"bytes"`
	Confidence   int            `json:"confidence"`
	Reason       string         `json:"reason"`
	Examples     []string       `json:"examples"`
	ProposedRule map[string]any `json:"proposed_rule"`
}

type sugAcc struct {
	flows, bytes uint64
	subs         int
	examples     []string
}

// suggestFromUnknown regroupe les hôtes non classifiés par domaine racine et
// propose une règle par domaine récurrent/volumineux. Trié par volume.
func suggestFromUnknown(unknown []kv) []suggestion {
	groups := map[string]*sugAcc{}
	for _, h := range unknown {
		dom := registrable(h.Name)
		if dom == "" {
			continue
		}
		g := groups[dom]
		if g == nil {
			g = &sugAcc{}
			groups[dom] = g
		}
		g.flows += h.Flows
		g.bytes += h.Bytes
		g.subs++
		if len(g.examples) < 3 {
			g.examples = append(g.examples, h.Name)
		}
	}

	out := make([]suggestion, 0, len(groups))
	for dom, g := range groups {
		out = append(out, suggestion{
			Domain: dom, Subdomains: g.subs, Flows: g.flows, Bytes: g.bytes,
			Confidence: confiance(g),
			Reason:     raison(g),
			Examples:   g.examples,
			ProposedRule: map[string]any{
				"id":         "learn-" + dom,
				"usage":      "",
				"confidence": confiance(g),
				"match":      map[string]any{"domain_suffix": []string{dom}},
			},
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Bytes != out[j].Bytes {
			return out[i].Bytes > out[j].Bytes
		}
		return out[i].Subdomains > out[j].Subdomains
	})
	return out
}

// confiance : plus il y a de sous-domaines récurrents et de volume, plus la
// proposition est solide. Bornée 0..100, jamais une certitude.
func confiance(g *sugAcc) int {
	c := 30 + (g.subs-1)*15
	if g.bytes >= 1<<30 { // ≥ 1 Gio
		c += 25
	} else if g.bytes >= 1<<20 { // ≥ 1 Mio
		c += 10
	}
	if c > 95 {
		c = 95
	}
	if c < 20 {
		c = 20
	}
	return c
}

func raison(g *sugAcc) string {
	s := strconv.Itoa(g.subs) + " sous-domaine"
	if g.subs > 1 {
		s += "s"
	}
	s += " non classifié"
	if g.subs > 1 {
		s += "s"
	}
	s += " du même domaine, " + humainOctets(g.bytes)
	return s
}

func humainOctets(o uint64) string {
	switch {
	case o >= 1<<30:
		return strconv.FormatFloat(float64(o)/(1<<30), 'f', 1, 64) + " Go"
	case o >= 1<<20:
		return strconv.FormatFloat(float64(o)/(1<<20), 'f', 1, 64) + " Mo"
	case o >= 1<<10:
		return strconv.FormatUint(o/(1<<10), 10) + " Ko"
	default:
		return strconv.FormatUint(o, 10) + " o"
	}
}
