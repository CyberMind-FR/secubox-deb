// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-pilotage-agent/internal/notifs"
)

func TestModeleAssemble(t *testing.T) {
	m := construireModele(func(context.Context, ...string) ([]byte, error) { return nil, nil })
	sup := strings.Join(m.Supportes(), "\n")
	for _, r := range []string{
		"Device.DeviceInfo.", "Device.X_SECUBOX_Services.", "Device.X_SECUBOX_Packages.",
		"Device.X_SECUBOX_Exposure.", "Device.X_SECUBOX_Mesh.", "Device.X_SECUBOX_Pilotage.",
	} {
		if !strings.Contains(sup, r) {
			t.Errorf("racine %q absente de GetSupportedDM", r)
		}
	}
}

func TestSurveillerArreteAvecLeContexte(t *testing.T) {
	m := construireModele(func(context.Context, ...string) ([]byte, error) { return nil, nil })
	ctx, annule := context.WithCancel(context.Background())
	fini := make(chan struct{})
	go func() { surveiller(ctx, m, time.Hour, make(chan notifs.Evenement, 4)); close(fini) }()
	time.Sleep(50 * time.Millisecond)
	annule()
	select {
	case <-fini:
	case <-time.After(2 * time.Second):
		t.Fatal("surveiller ne s'arrête pas")
	}
}

func TestMaitreRefuseNeReessaiePas(t *testing.T) {
	appels := 0
	lister := func() []ifaceAdr { appels++; return nil }
	ctx, annule := context.WithCancel(context.Background())
	type res struct{ m, ip string }
	ch := make(chan res, 1)
	go func() {
		m, ip := attendreMaitre(ctx, "maitre.example:8472", lister, 10*time.Millisecond)
		ch <- res{m, ip}
	}()
	time.Sleep(200 * time.Millisecond) // vingt périodes de revérification : aucune ne doit avoir lieu
	select {
	case <-ch:
		t.Fatal("rendu avant l'annulation")
	default:
	}
	annule()
	select {
	case r := <-ch:
		if r.m != "" {
			t.Fatalf("maître %q rendu pour une valeur refusée", r.m)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("pas de retour à l'annulation")
	}
	if appels != 0 {
		t.Fatalf("%d lectures d'interfaces pour une valeur refusée", appels)
	}
}

func TestMaitreAbsentRevérifie(t *testing.T) {
	appels := 0
	lister := func() []ifaceAdr {
		appels++
		if appels < 3 {
			return nil
		}
		return []ifaceAdr{ia("wg-mesh", "10.10.0.7/24")}
	}
	m, ip := attendreMaitre(context.Background(), "", lister, 10*time.Millisecond)
	if m != "10.10.0.1:8472" || ip != "10.10.0.7/24" || appels != 3 {
		t.Fatalf("%q %q %d", m, ip, appels)
	}
}
