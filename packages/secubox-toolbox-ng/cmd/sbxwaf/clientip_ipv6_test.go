// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"net/http/httptest"
	"testing"
)

// #2932 — préparation de la double pile (HAProxy `bind :::443 v4v6`). Avec elle, une adresse IPv4 peut arriver en
// notation mappée (::ffff:a.b.c.d) et une adresse IPv6 sous plusieurs écritures : sans normalisation, le set de
// bannissement, l'anti-tempête et les statistiques les compteraient comme des clients différents.
func TestClientIP_IPv6(t *testing.T) {
	cas := []struct {
		nom  string
		pair string
		xff  []string
		veut string
	}{
		{"client IPv6 derrière HAProxy", "127.0.0.1:5555", []string{"2001:db8::7"}, "2001:db8::7"},
		{"valeur forgée ULA, vraie adresse ajoutée à droite", "127.0.0.1:5555", []string{"fd00::5", "2001:db8::7"}, "2001:db8::7"},
		{"écriture non canonique ramenée à la forme canonique", "127.0.0.1:5555", []string{"2001:DB8:0:0:0:0:0:7"}, "2001:db8::7"},
		{"IPv4 mappée ramenée à l'IPv4", "127.0.0.1:5555", []string{"::ffff:198.51.100.7"}, "198.51.100.7"},
		{"HAProxy joint par ::1 : la chaîne compte", "[::1]:5555", []string{"2001:db8::7"}, "2001:db8::7"},
		{"pair IPv6 direct, non fiable : le pair, chaîne ignorée", "[2001:db8::9]:4444", []string{"fd00::1"}, "2001:db8::9"},
		{"mandataire ::1 dans la chaîne sauté", "127.0.0.1:5555", []string{"2001:db8::7, ::1"}, "2001:db8::7"},
	}
	for _, c := range cas {
		r := httptest.NewRequest("GET", "http://waf.test/", nil)
		r.RemoteAddr = c.pair
		for _, v := range c.xff {
			r.Header.Add("X-Forwarded-For", v)
		}
		if got := clientIP(r); got != c.veut {
			t.Errorf("%s : obtenu %q, attendu %q", c.nom, got, c.veut)
		}
	}
}

// Une adresse ULA forgée ne rend pas un client IPv6 public « privé » (donc exempté du WAF).
func TestClientIP_IPv6ForgeNeRendPasPrive(t *testing.T) {
	r := httptest.NewRequest("GET", "http://waf.test/?q=x", nil)
	r.RemoteAddr = "127.0.0.1:5555"
	r.Header.Add("X-Forwarded-For", "fd12:3456::1")
	r.Header.Add("X-Forwarded-For", "2001:db8::7")
	if privateCIDR(clientIP(r)) {
		t.Fatal("un client IPv6 public déguisé en ULA ne doit pas être exempté")
	}
}

func TestPrivateCIDR_IPv6(t *testing.T) {
	for ip, veut := range map[string]bool{
		"::1": true, "fd12:3456::1": true, "fc00::9": true, "::ffff:192.168.1.5": true,
		"2001:db8::7": false, "2a01:e0a:dec:c4e0::200": false, "fe80::1": false,
	} {
		if got := privateCIDR(ip); got != veut {
			t.Errorf("privateCIDR(%q) = %v, attendu %v", ip, got, veut)
		}
	}
}
