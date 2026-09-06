// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Package response propose une défense GRADUÉE et réversible (RFC-0013 §8 /
// RFC-0005). La réponse dépend de Confidence × Knowledge × Intent × Severity et
// s'échelonne OBSERVE → DELAY → CHALLENGE → TARPIT → DENY → QUARANTINE.
//
// En Phase 0/1 le moteur PROPOSE, il n'applique RIEN : chaque recommandation
// porte Shadow=true. Toute recommandation est réversible (TTL + rollback + raison
// + preuves) et il n'existe aucun « hack back » ni action sur l'hôte distant. La
// faible confiance ne fait JAMAIS escalader : on observe et on capture plutôt que
// de bloquer sur une incertitude.
package response

import "time"

// Mode est un cran de l'échelle de défense.
type Mode string

const (
	ModeObserve    Mode = "OBSERVE"
	ModeDelay      Mode = "DELAY"
	ModeChallenge  Mode = "CHALLENGE"
	ModeTarpit     Mode = "TARPIT"
	ModeDeny       Mode = "DENY"
	ModeQuarantine Mode = "QUARANTINE"
)

// ConfidenceFloor : en dessous, aucune escalade au-delà d'OBSERVE (RFC-0005 :
// « forte connaissance mais faible confiance → observation renforcée »).
const ConfidenceFloor = 30

// Recommendation est une proposition de réponse, jamais une action appliquée en
// Phase 0/1. TTL et Rollbackable garantissent la réversibilité (RFC-0013 §8).
type Recommendation struct {
	Mode         Mode          `json:"mode"`
	Reason       string        `json:"reason"`
	TTL          time.Duration `json:"ttl_ns"`
	Rollbackable bool          `json:"rollbackable"`
	Scope        string        `json:"scope"`
	EvidenceRefs []string      `json:"evidence_refs,omitempty"`
	Shadow       bool          `json:"shadow"`
}

// ttlParMode : durée de vie plafonnée par cran (réversibilité).
var ttlParMode = map[Mode]time.Duration{
	ModeObserve:    0,
	ModeDelay:      5 * time.Minute,
	ModeChallenge:  15 * time.Minute,
	ModeTarpit:     30 * time.Minute,
	ModeDeny:       time.Hour,
	ModeQuarantine: 6 * time.Hour,
}

// Recommend dérive une réponse proposée d'un ThreatVector (axes 0..100). shadow
// force Shadow=true (Phase 0/1) ; même hors shadow, la décision reste réversible.
func Recommend(severity, knowledge, intent, confidence int, evidenceRefs []string, shadow bool) Recommendation {
	// Composite d'escalade. L'automation n'y entre PAS (mode opératoire, pas gravité).
	esc := 0.30*float64(severity) + 0.25*float64(intent) +
		0.25*float64(confidence) + 0.20*float64(knowledge)

	var mode Mode
	var reason string
	switch {
	case confidence < ConfidenceFloor:
		// Incertitude : on n'escalade jamais. On observe (renforcé si la
		// connaissance est élevée) et on capture des métadonnées.
		mode = ModeObserve
		if knowledge >= 75 {
			reason = "forte connaissance mais faible confiance : observation renforcée + capture de métadonnées"
		} else {
			reason = "confiance insuffisante : observation seule"
		}
	case esc >= 88:
		mode, reason = ModeQuarantine, "gravité, ciblage et confiance très élevés : quarantaine proposée (temporaire, réversible)"
	case esc >= 75:
		mode, reason = ModeDeny, "attaque à forte gravité et confiance : blocage temporaire proposé"
	case esc >= 60:
		mode, reason = ModeTarpit, "acteur ciblé/persistant : ralentissement (tarpit) proposé"
	case esc >= 42:
		mode, reason = ModeChallenge, "comportement suspect : défi/vérification proposé"
	case esc >= 22:
		mode, reason = ModeDelay, "bruit automatisé : délai/limitation proposé"
	default:
		mode, reason = ModeObserve, "activité générique : journalisation"
	}

	return Recommendation{
		Mode:         mode,
		Reason:       reason,
		TTL:          ttlParMode[mode],
		Rollbackable: true,
		Scope:        "actor",
		EvidenceRefs: evidenceRefs,
		Shadow:       shadow,
	}
}
