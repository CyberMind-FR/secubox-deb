// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package sentinel

import "testing"

// TestFinalizeActionHighConfidenceKnownInfraBlocks verifies that a
// high-confidence, non-heuristic classification (known botnet C2
// infrastructure) is allowed to auto-block: the safety guard must not
// suppress legitimate high-confidence blocks.
func TestFinalizeActionHighConfidenceKnownInfraBlocks(t *testing.T) {
	v := &Verdict{Class: ClassBotnetC2, Confidence: 90, Action: ActionBlock}
	if got := FinalizeAction(v); got != ActionBlock {
		t.Fatalf("FinalizeAction() = %q, want %q", got, ActionBlock)
	}
}

// TestFinalizeActionZeroClickForcedReport is the safety-critical case: a
// zero-click (heuristic) verdict that mis-declares ActionBlock MUST be
// forced to ActionReport regardless of confidence, so a heuristic false
// positive can never auto-block legitimate traffic.
func TestFinalizeActionZeroClickForcedReport(t *testing.T) {
	v := &Verdict{Class: ClassZeroClick, Confidence: 100, Action: ActionBlock}
	if got := FinalizeAction(v); got != ActionReport {
		t.Fatalf("FinalizeAction() = %q, want %q (heuristic class must never auto-block)", got, ActionReport)
	}
}

// TestFinalizeActionLowConfidenceForcedReport verifies the confidence-floor
// half of the split: below HighConfidenceThreshold, even a non-heuristic
// class is downgraded to report-only.
func TestFinalizeActionLowConfidenceForcedReport(t *testing.T) {
	v := &Verdict{Class: ClassMalware, Confidence: 60, Action: ActionStrip}
	if got := FinalizeAction(v); got != ActionReport {
		t.Fatalf("FinalizeAction() = %q, want %q (below-threshold confidence must not auto-act)", got, ActionReport)
	}
}

// TestFinalizeActionKnownSpywareInfraBlocks verifies that a high-confidence
// (100) known-spyware-infrastructure hit (e.g. a confirmed Pegasus C2
// domain/JA4, NOT the zero-click delivery heuristic) is allowed to block —
// the report-only guard targets heuristic classes and low confidence, not
// spyware classes as a whole.
func TestFinalizeActionKnownSpywareInfraBlocks(t *testing.T) {
	v := &Verdict{Class: ClassSpywarePegasus, Confidence: 100, Action: ActionBlock}
	if got := FinalizeAction(v); got != ActionBlock {
		t.Fatalf("FinalizeAction() = %q, want %q", got, ActionBlock)
	}
}

// TestFinalizeActionConfidenceAtThresholdBlocks pins the boundary: exactly
// HighConfidenceThreshold is high enough (the check is "< threshold", not
// "<= threshold").
func TestFinalizeActionConfidenceAtThresholdBlocks(t *testing.T) {
	v := &Verdict{Class: ClassTrojan, Confidence: HighConfidenceThreshold, Action: ActionBlock}
	if got := FinalizeAction(v); got != ActionBlock {
		t.Fatalf("FinalizeAction() at threshold = %q, want %q", got, ActionBlock)
	}
}

// TestFinalizeActionJustBelowThresholdReports pins the other side of the
// boundary.
func TestFinalizeActionJustBelowThresholdReports(t *testing.T) {
	v := &Verdict{Class: ClassTrojan, Confidence: HighConfidenceThreshold - 1, Action: ActionBlock}
	if got := FinalizeAction(v); got != ActionReport {
		t.Fatalf("FinalizeAction() just below threshold = %q, want %q", got, ActionReport)
	}
}

func TestIsHeuristicClass(t *testing.T) {
	if !IsHeuristicClass(ClassZeroClick) {
		t.Fatal("IsHeuristicClass(ClassZeroClick) = false, want true")
	}
	if IsHeuristicClass(ClassBotnetC2) {
		t.Fatal("IsHeuristicClass(ClassBotnetC2) = true, want false")
	}
}
