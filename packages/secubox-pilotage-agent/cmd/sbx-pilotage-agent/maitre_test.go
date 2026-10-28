// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"net/netip"
	"testing"
)

func ifs(l ...ifaceAdr) []ifaceAdr { return l }

func ia(nom string, adrs ...string) ifaceAdr {
	r := ifaceAdr{Nom: nom}
	for _, a := range adrs {
		r.Adresses = append(r.Adresses, netip.MustParsePrefix(a))
	}
	return r
}

func TestChoixMaitre(t *testing.T) {
	cas := []struct {
		nom, env string
		ifs      []ifaceAdr
		maitre   string
		ipSource string
		trouve   bool
	}{
		{"mesh", "", ifs(ia("eth0", "192.168.1.5/24"), ia("wg-mesh", "10.10.0.7/24")), "10.10.0.1:8472", "10.10.0.7/24", true},
		{"autoload", "", ifs(ia("wg-autoload", "10.64.3.9/16")), "10.64.0.1:8472", "10.64.3.9/16", true},
		{"mesh l'emporte", "", ifs(ia("wg-autoload", "10.64.3.9/16"), ia("wg-mesh", "10.10.0.7/24")), "10.10.0.1:8472", "10.10.0.7/24", true},
		{"mesh hors plage, autoload repli", "", ifs(ia("wg-mesh", "172.16.0.2/24"), ia("wg-autoload", "10.64.3.9/16")), "10.64.0.1:8472", "10.64.3.9/16", true},
		{"mesh sans adresse", "", ifs(ia("wg-mesh")), "", "", false},
		{"autoload hors plage", "", ifs(ia("wg-autoload", "10.65.0.2/16")), "", "", false},
		{"aucune", "", nil, "", "", false},
		{"explicite", "10.99.0.1:9000", ifs(ia("wg-mesh", "10.10.0.7/24")), "10.99.0.1:9000", "10.10.0.7/24", true},
		{"explicite sans interface", "10.99.0.1:9000", nil, "10.99.0.1:9000", "", true},
		{"adresse v6 ignorée", "", ifs(ia("wg-mesh", "fd00::1/64")), "", "", false},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			m, ip, ok := choisirMaitre(c.env, c.ifs)
			if m != c.maitre || ip != c.ipSource || ok != c.trouve {
				t.Fatalf("obtenu (%q, %q, %v), attendu (%q, %q, %v)", m, ip, ok, c.maitre, c.ipSource, c.trouve)
			}
		})
	}
}

func TestIntervalleReleve(t *testing.T) {
	for env, att := range map[string]int{"": 30, "abc": 30, "0": 30, "-4": 30, "45": 45, "2": 5} {
		if got := intervalleReleve(env).Seconds(); int(got) != att {
			t.Errorf("%q : %v s, attendu %d", env, got, att)
		}
	}
}
