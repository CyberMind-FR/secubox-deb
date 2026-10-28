// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package collecte

import (
	"reflect"
	"testing"
)

func TestExpositionNomsEtPorts(t *testing.T) {
	s := NouvelleSourceExposition(gk5)
	p := lireTout(t, s)
	noms, _ := p["Device.X_SECUBOX_Exposure.Names"].([]string)
	if !reflect.DeepEqual(noms, []string{"admin.gk5.secubox.in", "hub.gk5.secubox.in"}) {
		t.Errorf("noms = %v", noms)
	}
	ports, _ := p["Device.X_SECUBOX_Exposure.Ports"].([]int)
	if !reflect.DeepEqual(ports, []int{80, 443, 9080}) {
		t.Errorf("ports = %v", ports)
	}
	verifierChemins(t, s, p)
}
