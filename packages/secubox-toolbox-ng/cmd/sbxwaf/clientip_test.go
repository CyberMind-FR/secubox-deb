// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"net/http/httptest"
	"testing"
)

// #1697 : l'adresse cliente se lit depuis la DROITE de la chaîne. Tout ce qui
// est à gauche de ce qu'a ajouté le dernier mandataire vient du client.
func TestClientIP_ChaineLueDepuisLaDroite(t *testing.T) {
	cas := []struct {
		nom  string
		pair string
		xff  []string // une entrée = une ligne d'en-tête
		veut string
	}{
		{"pair non fiable : la chaîne est ignorée", "203.0.113.9:4444", []string{"192.168.1.5"}, "203.0.113.9"},
		{"HAProxy, pas de valeur cliente", "127.0.0.1:5555", []string{"198.51.100.7"}, "198.51.100.7"},
		// Le cas vécu : le client écrit une adresse du LAN, HAProxy ajoute la vraie
		// sur une SECONDE ligne d'en-tête.
		{"valeur forgée, deux lignes", "127.0.0.1:5555", []string{"192.168.1.250", "198.51.100.7"}, "198.51.100.7"},
		{"valeur forgée, même ligne", "127.0.0.1:5555", []string{"192.168.1.250, 198.51.100.7"}, "198.51.100.7"},
		{"mandataires de confiance sautés", "127.0.0.1:5555", []string{"198.51.100.7, 10.100.0.1, 127.0.0.1"}, "198.51.100.7"},
		{"client du LAN (vrai)", "127.0.0.1:5555", []string{"192.168.1.20"}, "192.168.1.20"},
		{"chaîne de mandataires seuls : le pair", "127.0.0.1:5555", []string{"127.0.0.1"}, "127.0.0.1"},
		{"pas de chaîne : le pair", "127.0.0.1:5555", nil, "127.0.0.1"},
		{"entrées vides ignorées", "127.0.0.1:5555", []string{" , 198.51.100.7 ,"}, "198.51.100.7"},
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

// La conséquence qui comptait : une valeur forgée ne rend plus « privé » un
// client public — donc plus d'exemption du WAF.
func TestClientIP_ForgeNeRendPasPrive(t *testing.T) {
	r := httptest.NewRequest("GET", "http://waf.test/?q=x", nil)
	r.RemoteAddr = "127.0.0.1:5555"
	r.Header.Add("X-Forwarded-For", "192.168.1.250")
	r.Header.Add("X-Forwarded-For", "198.51.100.7")
	if privateCIDR(clientIP(r)) {
		t.Fatal("un client public déguisé en adresse privée ne doit pas être exempté")
	}
}
