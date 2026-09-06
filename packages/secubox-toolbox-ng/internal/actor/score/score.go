// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Package score porte le contrat commun de scoring EXPLICABLE d'Actor
// Intelligence (RFC-0013 §14). Chaque score 0..100 se décompose en contributions
// pondérées, positives ou négatives, chacune traçable à une preuve (evidence_id),
// et porte sa version d'algorithme/poids — une révision des poids ne falsifie
// jamais un ancien verdict (les versions sont figées avec le score stocké).
package score

// Versions courantes du barème. Stockées avec chaque score produit.
const (
	AlgoVersion    = "v1"
	WeightsVersion = "v1"
)

// Contribution est une preuve pondérée d'un score. Weight peut être négatif
// (ex. « présent dans une fuite publique » abaisse KnowledgeScore).
type Contribution struct {
	Label      string `json:"label"`
	Weight     int    `json:"weight"`
	EvidenceID string `json:"evidence_id,omitempty"`
}

// Score est une valeur bornée 0..100 explicable par ses contributions.
type Score struct {
	Value         int            `json:"value"`
	Contributions []Contribution `json:"contributions,omitempty"`
	AlgorithmVer  string         `json:"algorithm_version"`
	WeightsVer    string         `json:"weights_version"`
}

// Clamp borne une valeur à [0,100].
func Clamp(v int) int {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

// New construit un Score : Value = clamp(somme des poids), versions figées.
func New(contribs ...Contribution) Score {
	sum := 0
	for _, c := range contribs {
		sum += c.Weight
	}
	return Score{
		Value:         Clamp(sum),
		Contributions: contribs,
		AlgorithmVer:  AlgoVersion,
		WeightsVer:    WeightsVersion,
	}
}
