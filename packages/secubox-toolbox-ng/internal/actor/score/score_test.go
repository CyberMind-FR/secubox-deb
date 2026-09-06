// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package score

import "testing"

func TestClamp(t *testing.T) {
	for _, c := range []struct{ in, out int }{{-5, 0}, {0, 0}, {50, 50}, {100, 100}, {130, 100}} {
		if got := Clamp(c.in); got != c.out {
			t.Errorf("Clamp(%d) = %d, attendu %d", c.in, got, c.out)
		}
	}
}

func TestNew(t *testing.T) {
	s := New(
		Contribution{"signal fort", 60, "ev-1"},
		Contribution{"signal moyen", 30, "ev-2"},
		Contribution{"présent en fuite", -10, "ev-3"},
	)
	if s.Value != 80 {
		t.Errorf("Value = %d, attendu 80", s.Value)
	}
	if s.AlgorithmVer != AlgoVersion || s.WeightsVer != WeightsVersion {
		t.Error("versions non figées")
	}
	// Débordement borné.
	if New(Contribution{"x", 200, ""}).Value != 100 {
		t.Error("débordement non borné à 100")
	}
	if New(Contribution{"x", -50, ""}).Value != 0 {
		t.Error("sous-zéro non borné à 0")
	}
}
