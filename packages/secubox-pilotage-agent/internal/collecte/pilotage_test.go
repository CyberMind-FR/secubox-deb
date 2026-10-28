// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package collecte

import (
	"testing"
)

func TestPilotageMainsLiees(t *testing.T) {
	s := NouvelleSourcePilotage(gk5, "0.1.0")
	p := lireTout(t, s)
	if p["Device.X_SECUBOX_Pilotage.MainsLiees"] != true || p["Device.X_SECUBOX_Pilotage.AgentVersion"] != "0.1.0" ||
		p["Device.X_SECUBOX_Pilotage.Profil"] != "passerelle" {
		t.Errorf("pilotage = %v", p)
	}
	verifierChemins(t, s, p)

	vide := t.TempDir()
	p = lireTout(t, NouvelleSourcePilotage(vide, "0.1.0"))
	if p["Device.X_SECUBOX_Pilotage.MainsLiees"] != false || p["Device.X_SECUBOX_Pilotage.Profil"] != "" {
		t.Errorf("sans fichiers : %v", p)
	}
}
