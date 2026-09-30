// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import "testing"

// #1725 : gk2 relaie hall.gk3 vers 10.10.0.5:9080 ; son bandeau (admin.gk2)
// n'a rien à faire dans la page de gk3, dont la CSP le bloque.
func TestAmontDuMaillage(t *testing.T) {
	for ip, attendu := range map[string]bool{
		"10.10.0.5":     true,
		"10.10.0.1":     true,
		"127.0.0.1":     false,
		"192.168.1.200": false,
		"10.100.0.120":  false, // un conteneur de CETTE box
		"10.10.1.5":     false,
		"":              false,
		"pas-une-ip":    false,
	} {
		if got := amontDuMaillage(ip); got != attendu {
			t.Errorf("amontDuMaillage(%q) = %v, attendu %v", ip, got, attendu)
		}
	}
}
