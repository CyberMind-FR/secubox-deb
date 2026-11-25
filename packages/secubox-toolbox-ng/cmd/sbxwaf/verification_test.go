// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifierConfiguration(t *testing.T) {
	d := t.TempDir()
	ecrire := func(nom, texte string) string {
		p := filepath.Join(d, nom)
		_ = os.WriteFile(p, []byte(texte), 0o600)
		return p
	}
	regles := ecrire("r.json", `{"_meta":{},"categories":{"x":{"name":"x","severity":"high","patterns":[{"id":"a","pattern":"abc","desc":""}]}}}`)
	routes := ecrire("h.json", `{"a.exemple":["127.0.0.1",9080]}`)
	if b, err := VerifierConfiguration(ConfigVerifiee{Regles: regles, Routes: routes}); err != nil || !strings.Contains(b, "1 catégorie") || !strings.Contains(b, "1 route") {
		t.Fatalf("%q %v", b, err)
	}
	for nom, f := range map[string]func() error{
		"règles illisibles": func() error {
			_, err := VerifierConfiguration(ConfigVerifiee{Regles: ecrire("k.json", "{"), Routes: routes, Profils: "", Restants: nil})
			return err
		},
		"règles vides": func() error {
			_, err := VerifierConfiguration(ConfigVerifiee{Regles: ecrire("v.json", "{}"), Routes: routes, Profils: "", Restants: nil})
			return err
		},
		"routes illisibles": func() error {
			_, err := VerifierConfiguration(ConfigVerifiee{Regles: regles, Routes: ecrire("w.json", "[]"), Profils: "", Restants: nil})
			return err
		},
		"argument sans tiret": func() error {
			_, err := VerifierConfiguration(ConfigVerifiee{Regles: regles, Routes: routes, Profils: "", Restants: []string{"auto"}})
			return err
		},
	} {
		if f() == nil {
			t.Errorf("%s : refus attendu", nom)
		}
	}
	if b, err := VerifierConfiguration(ConfigVerifiee{Regles: regles, Routes: d + "/non", Profils: "", Restants: nil}); err != nil || !strings.Contains(b, "absent") {
		t.Fatalf("absent : le WAF démarre ainsi, dit : %q %v", b, err)
	}
	if b, err := VerifierConfiguration(ConfigVerifiee{Regles: regles, Routes: routes, Profils: ecrire("p.json", "{"), Restants: nil}); err != nil || !strings.Contains(b, "phase G") {
		t.Fatalf("profils illisibles : dit, pas refusé : %q %v", b, err)
	}
}

func TestVerifierConfiguration_JournauxOuvrables(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ouvre tout")
	}
	d := t.TempDir()
	ferme, bon, dossier := filepath.Join(d, "ferme"), filepath.Join(d, "bon"), filepath.Join(d, "dossier")
	_ = os.WriteFile(ferme, []byte("x"), 0o400)
	_ = os.WriteFile(bon, []byte("x"), 0o600)
	_ = os.Mkdir(dossier, 0o500)
	for nom, c := range map[string]struct {
		chemin string
		ok     bool
	}{
		"inscriptible":           {bon, true},
		"lecture seule":          {ferme, false},
		"un dossier":             {dossier, false},
		"à créer":                {filepath.Join(d, "neuf.jsonl"), true},
		"à créer, dossier aussi": {filepath.Join(d, "a", "b", "neuf.jsonl"), true},
		"dossier fermé":          {filepath.Join(dossier, "neuf.jsonl"), false},
		"sous un fichier":        {filepath.Join(bon, "neuf.jsonl"), false},
		"désactivé":              {"", true},
	} {
		_, e1 := VerifierConfiguration(ConfigVerifiee{Cookies: c.chemin})
		_, e2 := VerifierConfiguration(ConfigVerifiee{Menaces: c.chemin})
		if (e1 == nil) != c.ok || (e2 == nil) != c.ok {
			t.Errorf("%s : %v / %v", nom, e1, e2)
		}
	}
	if b, _ := os.ReadFile(bon); string(b) != "x" {
		t.Fatal("rien n'est écrit")
	}
	for _, n := range []string{"neuf.jsonl", "a"} {
		if _, err := os.Stat(filepath.Join(d, n)); err == nil {
			t.Fatalf("%s créé", n)
		}
	}
}

func TestPlagesProtegees_Bornes(t *testing.T) {
	for c, accepte := range map[string]bool{
		"203.0.113.7": true, "82.67.0.0/16": true, "2a01:e0a::/32": true, "2001:db8::1": true, "::ffff:203.0.113.7/128": true,
		"10.0.0.0/8": true, "172.16.0.0/12": true, "100.64.0.0/10": true, "fc00::/7": true, "fd00::/8": true, // jamais bannissables
		// Plages réelles d'un opérateur (Meta, protegees.env de la production, 2026-11-25) : jamais refusées.
		"57.144.0.0/14": true, "2803:6080::/29": true, "2a03:2880::/31": true, "82.64.0.0/12": true, "2a00::/28": true,
		"82.67.100.75/3": false, "0.0.0.0/0": false, "82.0.0.0/11": false, "::/0": false, "2a00::/27": false,
		"::ffff:0.0.0.0/96": false, "8.0.0.0/7": false, "10.0.0.0/7": false, "172.0.0.0/8": false, "fc00::/6": false,
	} {
		plages, larges, illisibles := analyserCIDRs(c)
		if (len(plages) == 1) != accepte || (len(larges) == 1) == accepte || len(illisibles) != 0 {
			t.Errorf("%s : %v %v %v", c, plages, larges, illisibles)
		}
		if _, err := VerifierConfiguration(ConfigVerifiee{Protegees: "203.0.113.7/32," + c}); (err == nil) != accepte {
			t.Errorf("--verifier %s : %v", c, err)
		}
	}
	if p := parseCIDRs("203.0.113.7, 0.0.0.0/0 ,x,2001:db8::/48"); len(p) != 2 {
		t.Fatalf("le reste de la liste est gardé : %v", p)
	}
}
