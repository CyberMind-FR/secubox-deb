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

	"github.com/CyberMind-FR/secubox-deb/secubox-pilotage-agent/internal/notifs"
	"github.com/CyberMind-FR/secubox-deb/secubox-pilotage-agent/internal/operations"
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

// TestExecuteurDeLAgent (tâche 3) : l'exécuteur passe par sudo vers le ctl (argv exact du sudoers) et lit l'unité
// par systemctl sans sudo ; une progression ne bloque jamais quand la file des notifications est pleine.
func TestExecuteurDeLAgent(t *testing.T) {
	var vusCtl, vusSystemctl []string
	ctl := func(_ context.Context, args ...string) ([]byte, error) {
		vusCtl = append(vusCtl, strings.Join(args, " "))
		return []byte(`{"ok": true, "job": "0123456789abcdef"}`), nil
	}
	sysctl := func(_ context.Context, args ...string) ([]byte, error) {
		vusSystemctl = append(vusSystemctl, strings.Join(args, " "))
		return []byte("active\n"), nil
	}
	ev := make(chan notifs.Evenement) // jamais lue : pleine d'emblée
	ex, boite := executeur(ctl, sysctl, ev)
	if boite == nil {
		t.Fatal("boîte des résultats attendue")
	}
	ctx, annule := context.WithCancel(context.Background())
	fini := make(chan operations.Reponse, 1)
	go func() { fini <- ex.Operer(ctx, operations.CmdReboot, nil, "gk2admin") }()
	select {
	case r := <-fini:
		if r.Etat != operations.Accepte {
			t.Fatalf("accepte attendu : %+v", r)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Operer bloqué par la file des notifications")
	}
	annule()
	ex.Attendre()
	if len(vusCtl) != 1 || vusCtl[0] != "-n /usr/sbin/secubox-pilotagectl --acteur gk2admin reboot" {
		t.Fatalf("argv du ctl inattendu : %v", vusCtl)
	}
}
