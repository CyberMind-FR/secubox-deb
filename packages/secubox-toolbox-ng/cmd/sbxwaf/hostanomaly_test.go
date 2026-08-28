// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import "testing"

func TestClassifyHost(t *testing.T) {
	cas := []struct {
		host   string
		name   string
		strong bool
	}{
		{"", "empty", true},
		{"   ", "empty", true},
		{"192.168.1.200", "ip_literal", true},
		{"8.8.8.8", "ip_literal", true},
		{"[2a00:1450:400c:c06::1a]", "ip_literal", true},
		// DGA : longues étiquettes imprononçables / chiffrées.
		{"xqzkwbrtplmn.com", "dga", true},
		{"a1b2c3d4e5f6g7.example.net", "dga", true},
		// Noms plausibles mais non routés → faible (lien périmé possible).
		{"webmail.example.com", "unrouted", false},
		{"anibal-amiot.fr", "unrouted", false},
		{"mon-service-interne-2.gk2.secubox.in", "unrouted", false},
		{"blog.acme.io", "unrouted", false},
	}
	for _, c := range cas {
		got := classifyHost(c.host)
		if got.Name != c.name {
			t.Errorf("classifyHost(%q) = %q ; attendu %q", c.host, got.Name, c.name)
		}
		if got.Strong != c.strong {
			t.Errorf("classifyHost(%q) Strong=%v ; attendu %v", c.host, got.Strong, c.strong)
		}
	}
}

func TestEstDGA_NePasSurClasserLesNomsLegitimes(t *testing.T) {
	// Aucun de ces sous-domaines légitimes ne doit être vu comme DGA.
	legit := []string{
		"www", "admin", "nextcloud", "photoprism", "grafana",
		"mail-relay", "media-flow", "anibal-amiot", "peertube",
		"my-long-but-real-service-name",
	}
	for _, h := range legit {
		if estDGA(h) {
			t.Errorf("estDGA(%q) = true (faux positif)", h)
		}
	}
}

func TestEstDGA_AttrapeLesNomsGeneres(t *testing.T) {
	dga := []string{
		"xqzkwbrtplmn",       // pas de voyelle, long
		"kdjfhgqwzxcvbnm",    // imprononçable
		"a1b2c3d4e5f6g7h8",   // saupoudré de chiffres
		"zx9k2m7q4w1n8p",     // dense, chiffré
	}
	for _, h := range dga {
		if !estDGA(h) {
			t.Errorf("estDGA(%q) = false (raté)", h)
		}
	}
}

// #1266 : notre propre domaine n'est jamais banni comme host-anomaly. L'appli
// Nextcloud iOS pointant sur nextcloud.gk2.secubox.in (non routé) ne doit pas
// couper l'utilisateur — ni, en CGNAT mobile, tous ceux qui partagent son IP.
func TestEstPremierePartie(t *testing.T) {
	sfx := []string{"gk2.secubox.in", "secubox.in", "gk2.net", "cybermind.fr"}
	cas := []struct {
		host string
		veut bool
	}{
		{"nextcloud.gk2.secubox.in", true},
		{"nc.gk2.secubox.in", true},
		{"gk2.secubox.in", true},
		{"hall.gk2.net", true},
		{"GK2.NET", true},
		{"nextcloud.gk2.secubox.in:443", true},
		{"evil.com", false},
		{"notgk2.net", false},          // pas une frontière de label
		{"gk2.secubox.in.evil.com", false},
		{"", false},
	}
	for _, c := range cas {
		if got := estPremierePartie(c.host, sfx); got != c.veut {
			t.Errorf("estPremierePartie(%q) = %v, veut %v", c.host, got, c.veut)
		}
	}
}
