// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package collecte

import (
	"context"
	"strings"
	"testing"
)

func TestPaquetsNeGardeQueSecuboxInstalles(t *testing.T) {
	s := NouvelleSourcePaquets(gk5)
	p := lireTout(t, s)
	n := 0
	for k, v := range p {
		if strings.HasSuffix(k, ".Name") {
			n++
			if !strings.HasPrefix(v.(string), "secubox-") || v == "secubox-retire" || v == "secubox-casse" {
				t.Errorf("paquet indésirable : %v", v)
			}
		}
	}
	if n != 24 {
		t.Errorf("%d paquets, attendu 24", n)
	}
	if p["Device.DeviceInfo.SoftwareVersion"] != "1.0.0-1~trixie1" {
		t.Errorf("SoftwareVersion = %v", p["Device.DeviceInfo.SoftwareVersion"])
	}
	verifierChemins(t, s, p)
}

func TestPaquetsSansStatusEnErreur(t *testing.T) {
	if _, err := NouvelleSourcePaquets(t.TempDir()).Lire(context.Background()); err == nil {
		t.Error("une erreur est attendue")
	}
}
