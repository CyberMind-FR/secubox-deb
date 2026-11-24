// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/envelope"
)

func evtAuth(cible, regle string) *envelope.Envelope {
	return &envelope.Envelope{EventID: "e", Timestamp: time.Now().Unix(), Sensor: envelope.SensorAuthWatch,
		SrcIP: "198.51.100.1", DstService: cible, RuleID: regle, Severity: 50}
}

// TestServiceNonMasqueCompteMasque : authwatch met le SERVICE dans DstService ;
// un nom de la liste fermée s'affiche, tout le reste est traité en compte.
func TestServiceNonMasqueCompteMasque(t *testing.T) {
	for cible, attendu := range map[string]string{
		"smtp": "smtp", "ssh": "ssh", "SSH": "ssh", "imap": "imap", "telnet": "telnet", "nextcloud": "nextcloud",
		"root": "roo…", "admin": "adm…", "gerald": "ger…", "smtp@exemple.test": "smt…", "smtpd": "smt…",
		"mail": "mai…", "ab": "…", "ssh root": "ssh…",
	} {
		if got := cibleAffichee(evtAuth(cible, "auth_ssh:failed_password")); got != attendu {
			t.Errorf("cible %q → %q, attendu %q", cible, got, attendu)
		}
	}
	// Même règle quand l'origine est une étiquette auth_* d'un autre capteur.
	e := evtAuth("root", "")
	e.Sensor, e.BehaviorTags = envelope.SensorWAF, []string{"auth_ssh:invalid_user"}
	if got := cibleAffichee(e); got != "roo…" {
		t.Errorf("compte d'un autre capteur : %q", got)
	}
	// Seul authwatch met un service dans DstService : ailleurs, même « mysql » est un compte.
	e.DstService = "mysql"
	if got := cibleAffichee(e); got != "mys…" {
		t.Errorf("compte homonyme d'un service, autre capteur : %q", got)
	}
}

// TestServicesConnusSuiventAuthwatch : la liste fermée couvre tous les services
// que sbx-authwatch émet (motifs, leurres, bannières, filtres déclarés livrés).
func TestServicesConnusSuiventAuthwatch(t *testing.T) {
	lire := func(chemin, motif string) (out []string) {
		b, err := os.ReadFile(chemin)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range regexp.MustCompile(motif).FindAllStringSubmatch(string(b), -1) {
			out = append(out, m[1])
		}
		if len(out) == 0 {
			t.Fatalf("%s : aucun service lu", chemin)
		}
		return out
	}
	var noms []string
	noms = append(noms, lire("../sbx-authwatch/motifs.go", `(?m)^\t\{"([a-z0-9]+)", "auth_`)...)
	noms = append(noms, lire("../sbx-authwatch/leurre.go", `(?m)^\t\{\d+, "([a-z0-9]+)"\}`)...)
	noms = append(noms, lire("../sbx-authwatch/banniere.go", `(?m)^\t"([a-z0-9]+)":\s+(?:nil|\[\]byte)`)...)
	noms = append(noms, lire("../../debian/authwatch/services.json", `"id":\s*"([a-z0-9]+)"`)...)
	for _, n := range noms {
		if !servicesAuthwatch[n] {
			t.Errorf("service %q d'authwatch absent de servicesAuthwatch", n)
		}
	}
}

// TestCibleJamaisUneAdresse : un hôte qui est une adresse ne sort jamais.
func TestCibleJamaisUneAdresse(t *testing.T) {
	for _, h := range []string{"203.0.113.9", "203.0.113.9:443", "[2001:db8::1]", "[2001:db8::1]:443", "2001:db8::1",
		"203.0.113.9.", "010.1.2.3", "3405803785", "0xcb007109", "exemple.0x7f", " 203.0.113.9 "} {
		e := evtSource("198.51.100.1", time.Now().Unix(), h)
		if got := cibleAffichee(e); got != "" {
			t.Errorf("hôte %q affiché : %q", h, got)
		}
	}
	for _, h := range []string{"forge.exemple.test", "forge.exemple.test:443", "git2", "a1.exemple.test"} {
		if cibleAffichee(evtSource("198.51.100.1", time.Now().Unix(), h)) == "" {
			t.Errorf("hôte %q écarté à tort", h)
		}
	}
}

// TestBalayageDePorts : les capteurs DPI et pare-feu mettent « ports:N » dans
// DstService. Ce n'est pas un hôte : une seule étiquette lisible, et un hôte réel
// passe toujours devant, quel que soit son nombre d'événements.
func TestBalayageDePorts(t *testing.T) {
	for _, d := range []string{"ports:2", "ports:119"} {
		if got := cibleAffichee(evtSource("198.51.100.1", time.Now().Unix(), d)); got != "ports (balayage)" {
			t.Errorf("%q → %q", d, got)
		}
	}
	s := &Server{}
	ips := map[string]bool{"198.51.100.1": true}
	for i := 0; i < 9; i++ {
		s.noterSource(evtSource("198.51.100.1", time.Now().Unix(), "ports:2"))
	}
	g := &campagne{}
	s.enrichir(g, ips)
	if len(g.CiblesNoms) != 1 || g.CiblesNoms[0] != "ports (balayage)" {
		t.Errorf("cibles_noms = %v", g.CiblesNoms)
	}
	s.noterSource(evtSource("198.51.100.1", time.Now().Unix(), "forge.exemple.test"))
	g = &campagne{}
	s.enrichir(g, ips)
	if len(g.CiblesNoms) != 1 || g.CiblesNoms[0] != "forge.exemple.test" {
		t.Errorf("hôte réel présent : cibles_noms = %v", g.CiblesNoms)
	}
}

// TestCibleBornee : une cible est bornée à 64 caractères dans la fiche.
func TestCibleBornee(t *testing.T) {
	s := &Server{}
	now := time.Now().Unix()
	s.noterSource(evtSource("198.51.100.1", now, strings.Repeat("é", 5000)+".exemple.test"))
	s.noterSource(evtSource("198.51.100.1", now, strings.Repeat("b", 5000)+".exemple.test"))
	f := s.sources["198.51.100.1"]
	if n := utf8.RuneCountInString(f.cible); n == 0 || n > 64 || !utf8.ValidString(f.cible) {
		t.Errorf("première cible : %d caractères", n)
	}
	for k := range f.cibles {
		if utf8.RuneCountInString(k) > 64 {
			t.Errorf("cible suivante : %d caractères", utf8.RuneCountInString(k))
		}
	}
}
