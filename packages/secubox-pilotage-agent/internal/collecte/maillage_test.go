// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package collecte

import (
	"net"
	"testing"
)

func TestMaillagePrendWgMesh(t *testing.T) {
	ifs := func() ([]net.Interface, error) {
		return []net.Interface{{Name: "eth0"}, {Name: "wg-autoload"}, {Name: "wg-mesh"}}, nil
	}
	s := nouvelleSourceMaillage(ifs, func(i net.Interface) ([]net.Addr, error) {
		return []net.Addr{&net.IPNet{IP: net.ParseIP("fe80::1")}, &net.IPNet{IP: net.ParseIP("10.10.0.5"), Mask: net.CIDRMask(24, 32)}}, nil
	})
	p := lireTout(t, s)
	if p["Device.X_SECUBOX_Mesh.Interface"] != "wg-mesh" || p["Device.X_SECUBOX_Mesh.Address"] != "10.10.0.5" || p["Device.X_SECUBOX_Mesh.Present"] != true {
		t.Errorf("maillage = %v", p)
	}
	verifierChemins(t, s, p)
}

func TestMaillageAbsent(t *testing.T) {
	s := NouvelleSourceMaillage(func() ([]net.Interface, error) { return []net.Interface{{Name: "eth0"}}, nil })
	p := lireTout(t, s)
	if p["Device.X_SECUBOX_Mesh.Present"] != false {
		t.Errorf("Present = %v", p["Device.X_SECUBOX_Mesh.Present"])
	}
	verifierChemins(t, s, p)
}
