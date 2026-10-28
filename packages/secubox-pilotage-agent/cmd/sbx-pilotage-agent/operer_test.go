// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

const racineTest = "../../internal/collecte/testdata/gk5"

func TestOperateFormeJSON(t *testing.T) {
	op := operateur(racineTest, func(context.Context, time.Duration) error { return nil })
	sortie, err := op(context.Background(), "Device.X_SECUBOX_Releve.Mesurer()", map[string]any{"duree_s": 10})
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(sortie)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"duree_s", "cpu_pct", "ctxt_par_s", "ecritures_ko_s", "mem_dispo_mo", "swap_mo", "top"} {
		if _, ok := m[k]; !ok {
			t.Errorf("clé %q absente : %s", k, b)
		}
	}
	if len(m) != 7 {
		t.Errorf("clés inattendues : %s", b)
	}
	if m["duree_s"].(float64) != 10 {
		t.Errorf("duree_s : %v", m["duree_s"])
	}
	for k := range m {
		if strings.ContainsAny(k, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
			t.Errorf("clé non snake_case : %s", k)
		}
	}
	if top, _ := m["top"].([]any); top == nil {
		t.Errorf("top doit être une liste (même vide) : %s", b)
	}
}

func TestOperateTopSnakeCase(t *testing.T) {
	b, _ := json.Marshal(sortieProc{Nom: "nginx", CPUPct: 1.5, PSSMo: 12})
	if string(b) != `{"nom":"nginx","cpu_pct":1.5,"pss_mo":12}` {
		t.Fatal(string(b))
	}
}

func TestOperateRefuseAutreCommande(t *testing.T) {
	op := operateur(racineTest, nil)
	if _, err := op(context.Background(), "Device.Reboot()", nil); err == nil {
		t.Fatal("commande inconnue acceptée")
	}
}

func TestOperateRespecteLeContexte(t *testing.T) {
	op := operateur(racineTest, nil) // attente réelle
	ctx, annule := context.WithCancel(context.Background())
	go func() { time.Sleep(200 * time.Millisecond); annule() }()
	debut := time.Now()
	_, err := op(ctx, "Device.X_SECUBOX_Releve.Mesurer()", map[string]any{"duree_s": 300})
	if err == nil {
		t.Fatal("annulation sans erreur")
	}
	if d := time.Since(debut); d > 2*time.Second {
		t.Fatalf("relevé non interrompu : %v", d)
	}
}
