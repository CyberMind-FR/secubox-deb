// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

// TestVerifierAncreParLeCtl : seule la sortie exacte {"ok": true} du ctl vaut ancre vérifiée ; toute autre sortie,
// une erreur ou un code non nul vaut échec. L'argv est celui que le sudoers accorde.
func TestVerifierAncreParLeCtl(t *testing.T) {
	cas := []struct {
		sortie string
		err    error
		ok     bool
	}{
		{`{"ok": true}` + "\n", nil, true},
		{`{"ok":true}`, nil, true},
		{`{"ok": false, "refus": "ancre différente"}` + "\n", nil, false},
		{`{"ok": false, "refus": "ancre absente"}`, nil, false},
		{`{"ok": "true"}`, nil, false},
		{`{"ok": 1}`, nil, false},
		{`{}`, nil, false},
		{`{"ok": true} {"ok": true}`, nil, false},
		{`{"ok": true}` + "\nencore", nil, false},
		{``, nil, false},
		{`{"ok": true}`, errors.New("code 1"), false},
		{`{"ok": false, "erreur": "audit impossible"}`, nil, false},
	}
	for _, c := range cas {
		var vu []string
		lancer := func(_ context.Context, args ...string) ([]byte, error) {
			vu = args
			return []byte(c.sortie), c.err
		}
		if got := verifieurAncre(lancer)(context.Background()); got != c.ok {
			t.Errorf("sortie %q, err %v : %v, attendu %v", c.sortie, c.err, got, c.ok)
		}
		if want := []string{"-n", "/usr/sbin/secubox-pilotagectl", "ancre-verifier"}; !reflect.DeepEqual(vu, want) {
			t.Fatalf("argv %v, attendu %v", vu, want)
		}
	}
}
