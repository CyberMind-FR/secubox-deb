// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package sentinel

// HighConfidenceThreshold is the minimum Verdict.Confidence required for a
// non-heuristic classification to be allowed to auto-neutralize (block,
// strip, sinkhole). Below this threshold, FinalizeAction downgrades the
// verdict to ActionReport regardless of the IOC's declared action.
const HighConfidenceThreshold = 85

// heuristicClasses is the small, explicit allow-list of ThreatClass values
// that are inherently heuristic — i.e. derived from behavioral inference
// rather than a confirmed known-infra indicator match — and therefore MUST
// NEVER auto-block, no matter how the source pack declared their Action.
// Kept as a deliberately small, auditable set: adding a class here is a
// safety-relevant change and should be reviewed as such.
var heuristicClasses = map[ThreatClass]bool{
	ClassZeroClick: true,
}

// IsHeuristicClass reports whether c is an inherently heuristic threat
// classification (see heuristicClasses).
func IsHeuristicClass(c ThreatClass) bool {
	return heuristicClasses[c]
}

// FinalizeAction enforces the Sentinel block/report safety split (see the
// plan's Global Constraints): a heuristic classification (IsHeuristicClass)
// or a confidence below HighConfidenceThreshold is downgraded to
// ActionReport, regardless of what action the matched IOC declared. This is
// the last line of defense against a heuristic or low-confidence false
// positive auto-blocking legitimate traffic — it MUST be called on every
// verdict before any neutralization is applied.
func FinalizeAction(v *Verdict) Action {
	if IsHeuristicClass(v.Class) || v.Confidence < HighConfidenceThreshold {
		return ActionReport
	}
	return v.Action
}
