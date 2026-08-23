// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Package resume : résumé COURT et factuel d'un événement, à partir de ce qui
// est COMMUN aux sources. Extractif (sans LLM) : on choisit des phrases
// existantes, on n'invente rien. 2 à 4 phrases.
package resume

import (
	"sort"
	"strings"

	"github.com/CyberMind-FR/secubox-deb/secubox-metanews/internal/cluster"
)

// Item : une source du sujet (titre + extrait).
type Item struct {
	Titre string
	Corps string
}

// Resume produit un résumé extractif d'au plus `maxPhrases` phrases, privilégiant
// les phrases dont le vocabulaire est PARTAGÉ par plusieurs sources.
func Resume(items []Item, maxPhrases int) string {
	if maxPhrases <= 0 {
		maxPhrases = 3
	}
	// Vocabulaire commun : tokens présents dans ≥2 sources (titre + corps).
	compte := map[string]int{}
	for _, it := range items {
		vus := map[string]bool{}
		for _, t := range cluster.Tokens(it.Titre + " " + it.Corps) {
			if !vus[t] {
				vus[t] = true
				compte[t]++
			}
		}
	}
	commun := map[string]bool{}
	for t, n := range compte {
		if n >= 2 {
			commun[t] = true
		}
	}
	// Phrases candidates : celles des corps (à défaut, les titres).
	type ph struct {
		texte string
		score float64
	}
	var cands []ph
	vues := map[string]bool{}
	pousser := func(s string) {
		s = strings.TrimSpace(s)
		if len(s) < 24 || len(s) > 320 {
			return
		}
		clef := strings.ToLower(s)
		if vues[clef] {
			return
		}
		vues[clef] = true
		toks := cluster.Tokens(s)
		if len(toks) == 0 {
			return
		}
		inter := 0
		for _, t := range toks {
			if commun[t] {
				inter++
			}
		}
		cands = append(cands, ph{s, float64(inter) / float64(len(toks))})
	}
	for _, it := range items {
		for _, s := range phrases(it.Corps) {
			pousser(s)
		}
	}
	// Repli : aucun corps exploitable → titres.
	if len(cands) == 0 {
		for _, it := range items {
			pousser(it.Titre)
		}
	}
	sort.SliceStable(cands, func(i, j int) bool { return cands[i].score > cands[j].score })
	var pris []string
	for _, c := range cands {
		if c.score <= 0 {
			break
		}
		pris = append(pris, c.texte)
		if len(pris) >= maxPhrases {
			break
		}
	}
	if len(pris) == 0 && len(items) > 0 {
		return strings.TrimSpace(items[0].Titre)
	}
	out := strings.Join(pris, " ")
	// Prudence : plusieurs sources mais un seul angle retenu → signaler la
	// pluralité plutôt que de laisser croire à une certitude unique.
	if len(items) >= 3 && len(pris) < 2 {
		out += " Les détails varient encore selon les sources."
	}
	return out
}

// phrases découpe grossièrement un texte en phrases.
func phrases(s string) []string {
	s = strings.Join(strings.Fields(s), " ")
	var out []string
	deb := 0
	runes := []rune(s)
	for i, r := range runes {
		if r == '.' || r == '!' || r == '?' {
			out = append(out, string(runes[deb:i+1]))
			deb = i + 1
		}
	}
	if deb < len(runes) {
		out = append(out, string(runes[deb:]))
	}
	return out
}
