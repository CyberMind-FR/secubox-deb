// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"context"
	"errors"
	"net/netip"
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
		if got := verifieurAncre(lancer, "10.10.0.1:8472")(context.Background()); got != c.v {
			t.Errorf("sortie %q, err %v : %q, attendu %q", c.sortie, c.err, got, c.v)
		}
		if want := []string{"-n", "/usr/sbin/secubox-pilotagectl", "ancre-verifier", "wg-mesh"}; !reflect.DeepEqual(vu, want) {
			t.Fatalf("argv %v, attendu %v", vu, want)
		}
	}
}

// TestAgentWgMeshSansAdresseVerifieLeBonCanal (I1, R-L2-23) : wg-mesh existe mais n'a pas (encore) d'adresse,
// l'agent prend le maître de wg-autoload ; la vérification porte sur l'interface de CE canal, déduite du maître
// retenu, jamais sur la seule présence de wg-mesh. Un maître hors des deux canaux vaut illisible sans appeler le ctl.
func TestAgentWgMeshSansAdresseVerifieLeBonCanal(t *testing.T) {
	ifs := []ifaceAdr{
		{Nom: "wg-mesh"},
		{Nom: "wg-autoload", Adresses: []netip.Prefix{netip.MustParsePrefix("10.64.0.9/16")}},
	}
	maitre, _, ok := choisirMaitre("", ifs)
	if !ok || maitre != "10.64.0.1:8472" {
		t.Fatalf("maître attendu 10.64.0.1:8472, %q", maitre)
	}
	var vu []string
	lancer := func(_ context.Context, args ...string) ([]byte, error) {
		vu = args
		return []byte(`{"ok": true}`), nil
	}
	if v := verifieurAncre(lancer, maitre)(context.Background()); v != canal.AncreOK {
		t.Fatalf("verdict %q", v)
	}
	if want := []string{"-n", "/usr/sbin/secubox-pilotagectl", "ancre-verifier", "wg-autoload"}; !reflect.DeepEqual(vu, want) {
		t.Fatalf("argv %v, attendu %v", vu, want)
	}
	for m, iface := range map[string]string{"10.10.0.1": "wg-mesh", "10.10.0.1:8472": "wg-mesh", "10.64.0.1": "wg-autoload"} {
		vu = nil
		verifieurAncre(lancer, m)(context.Background())
		if len(vu) != 4 || vu[3] != iface {
			t.Errorf("%s : argv %v, interface %s attendue", m, vu, iface)
		}
	}
	for _, m := range []string{"127.0.0.1", "127.0.0.1:8472", "10.10.0.2", ""} {
		vu = nil
		if v := verifieurAncre(lancer, m)(context.Background()); v != canal.AncreIllisible || vu != nil {
			t.Errorf("%q : verdict %q, appel %v ; illisible sans appel attendu", m, v, vu)
		}
	}
}
