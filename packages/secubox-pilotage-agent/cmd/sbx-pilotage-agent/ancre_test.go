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

	"github.com/CyberMind-FR/secubox-deb/secubox-pilotage-agent/internal/canal"
)

// TestVerifierAncreParLeCtl : seule la sortie exacte {"ok": true} du ctl vaut ancre vérifiée ; « raison » absente ou
// differente est reprise (R-L2-19) ; toute autre sortie, une erreur ou un code non nul vaut illisible (canal coupé).
// L'argv est celui que le sudoers accorde.
func TestVerifierAncreParLeCtl(t *testing.T) {
	cas := []struct {
		sortie string
		err    error
		v      canal.Verdict
	}{
		{`{"ok": true}` + "\n", nil, canal.AncreOK},
		{`{"ok":true}`, nil, canal.AncreOK},
		{`{"ok": false, "raison": "differente"}` + "\n", nil, canal.AncreDifferente},
		{`{"ok": false, "raison": "absente"}`, nil, canal.AncreAbsente},
		{`{"ok": false, "raison": "illisible"}`, nil, canal.AncreIllisible},
		{`{"ok": false, "raison": "autre"}`, nil, canal.AncreIllisible},
		{`{"ok": false}`, nil, canal.AncreIllisible},
		{`{"ok": true, "raison": "absente"}`, nil, canal.AncreIllisible},
		{`{"ok": "true"}`, nil, canal.AncreIllisible},
		{`{"ok": 1}`, nil, canal.AncreIllisible},
		{`{}`, nil, canal.AncreIllisible},
		{`{"ok": true} {"ok": true}`, nil, canal.AncreIllisible},
		{`{"ok": true}` + "\nencore", nil, canal.AncreIllisible},
		{``, nil, canal.AncreIllisible},
		{`{"ok": true}`, errors.New("code 1"), canal.AncreIllisible},
		{`{"ok": false, "raison": "absente"}`, errors.New("code 1"), canal.AncreIllisible},
		{`{"ok": false, "erreur": "audit impossible"}`, nil, canal.AncreIllisible},
	}
	for _, c := range cas {
		var vu []string
		lancer := func(_ context.Context, args ...string) ([]byte, error) {
			vu = args
			return []byte(c.sortie), c.err
		}
		if got := verifieurAncre(lancer)(context.Background()); got != c.v {
			t.Errorf("sortie %q, err %v : %q, attendu %q", c.sortie, c.err, got, c.v)
		}
		if want := []string{"-n", "/usr/sbin/secubox-pilotagectl", "ancre-verifier"}; !reflect.DeepEqual(vu, want) {
			t.Fatalf("argv %v, attendu %v", vu, want)
		}
	}
}
