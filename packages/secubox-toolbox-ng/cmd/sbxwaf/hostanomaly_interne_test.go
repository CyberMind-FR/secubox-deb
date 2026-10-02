// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import "testing"

// #1859 : la boîte qui s'appelle elle-même n'est pas une anomalie ; un client
// externe qui annonce « localhost » en est une.
func TestTraficInterne(t *testing.T) {
	cas := []struct {
		host, ip string
		attendu  bool
	}{
		{"localhost", "127.0.0.1", true},
		{"localhost:9080", "127.0.0.1", true},
		{"127.0.0.1", "127.0.0.1", true},
		{"[::1]:8085", "::1", true},
		{"localhost", "203.0.113.9", false},       // sonde externe
		{"localhost", "192.168.1.50", false},      // LAN : on observe
		{"nc.gk2.secubox.in", "127.0.0.1", false}, // vrai vhost : pas d'exemption
		{"", "127.0.0.1", false},
	}
	for _, c := range cas {
		if got := traficInterne(c.host, c.ip); got != c.attendu {
			t.Errorf("traficInterne(%q,%q) = %v, attendu %v", c.host, c.ip, got, c.attendu)
		}
	}
}
