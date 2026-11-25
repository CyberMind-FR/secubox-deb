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
	if b, err := VerifierConfiguration(regles, routes, "", nil); err != nil || !strings.Contains(b, "1 catégorie") || !strings.Contains(b, "1 route") {
		t.Fatalf("%q %v", b, err)
	}
	for nom, f := range map[string]func() error{
		"règles illisibles":   func() error { _, err := VerifierConfiguration(ecrire("k.json", "{"), routes, "", nil); return err },
		"règles vides":        func() error { _, err := VerifierConfiguration(ecrire("v.json", "{}"), routes, "", nil); return err },
		"routes illisibles":   func() error { _, err := VerifierConfiguration(regles, ecrire("w.json", "[]"), "", nil); return err },
		"argument sans tiret": func() error { _, err := VerifierConfiguration(regles, routes, "", []string{"auto"}); return err },
	} {
		if f() == nil {
			t.Errorf("%s : refus attendu", nom)
		}
	}
	if b, err := VerifierConfiguration(regles, d+"/non", "", nil); err != nil || !strings.Contains(b, "absent") {
		t.Fatalf("absent : le WAF démarre ainsi, dit : %q %v", b, err)
	}
	if b, err := VerifierConfiguration(regles, routes, ecrire("p.json", "{"), nil); err != nil || !strings.Contains(b, "phase G") {
		t.Fatalf("profils illisibles : dit, pas refusé : %q %v", b, err)
	}
}
