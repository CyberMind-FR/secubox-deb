// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: R-level per-peer core (#rlevel-per-peer)
//
// Pure decision core for the per-peer MITM R-level ladder: the enum, the
// effective-mode resolver (explicit force vs. chosen/floor clamp), and the
// verdict clamp that enforces what each mode is allowed to do to a decision
// already produced upstream by the policy layer (policy.go).
//
// Off      — nft handles bypass upstream; this layer is never consulted.
// Passive  — passthrough only: never decrypts, verdict is always "splice".
// Active   — decrypts+inspects but does not enforce block (block→"mitm");
//
//	a pinned host ("splice") must never be decrypted, so it stays splice.
//
// Reel     — full enforcement: verdict passes through unchanged.
//
// Pure standard library — no external modules, no go.sum.
package main

import "strings"

// RLevel is the per-peer MITM depth: how far sbxmitm is allowed to go for
// a given peer, from no interception at all up to full enforcement.
type RLevel int

const (
	Off RLevel = iota
	Passive
	Active
	Reel
)

// parseRLevel parses a case-insensitive, whitespace-trimmed R-level name
// ("off", "passive", "active", "reel") into its RLevel constant. The bool
// result reports whether s was a recognized name.
func parseRLevel(s string) (RLevel, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "off":
		return Off, true
	case "passive":
		return Passive, true
	case "active":
		return Active, true
	case "reel":
		return Reel, true
	default:
		return 0, false
	}
}

// effective resolves the R-level actually applied to a peer. An explicit
// forced level (hasForced) always wins outright. Otherwise the chosen level
// is clamped into [floor, Reel]: it can never fall below the configured
// floor, and never exceeds Reel (the ceiling of the ladder).
func effective(chosen, forced, floor RLevel, hasForced bool) RLevel {
	if hasForced {
		return forced
	}
	return clampRLevel(chosen, floor, Reel)
}

// clampRLevel returns v bounded to [lo, hi].
func clampRLevel(v, lo, hi RLevel) RLevel {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// clampVerdict applies the per-mode ceiling to a verdict already computed
// by the policy layer ("allow", "block", "splice", or "mitm"), enforcing
// what each R-level is actually permitted to do:
//
//   - Off:     unchanged — this mode is never reached in practice, since nft
//     performs the bypass upstream of any decision; must not panic.
//   - Passive: always "splice" — passthrough only, never decrypts regardless
//     of the underlying verdict.
//   - Active:  decrypts and inspects but does not enforce blocking, so
//     "block" is downgraded to "mitm" (visibility without enforcement).
//     Every other verdict is left unchanged — in particular "splice" MUST
//     stay "splice": a pinned host must never be decrypted.
//   - Reel:    unchanged — full enforcement, "block" is honored as-is.
func clampVerdict(mode RLevel, verdict string) string {
	switch mode {
	case Passive:
		return "splice"
	case Active:
		if verdict == "block" {
			return "mitm"
		}
		return verdict
	default: // Off, Reel
		return verdict
	}
}
