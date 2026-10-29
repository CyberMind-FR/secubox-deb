// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-pilotage-agent/internal/modele"
	"github.com/CyberMind-FR/secubox-deb/secubox-pilotage-agent/internal/notifs"
)

func TestModeleAssemble(t *testing.T) {
	m, cpu := construireModele(func(context.Context, ...string) ([]byte, error) { return nil, nil })
	if cpu == nil {
		t.Fatal("pas d'échantillonneur CPU")
	}
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
	m, cpu := construireModele(func(context.Context, ...string) ([]byte, error) { return nil, nil })
	ctx, annule := context.WithCancel(context.Background())
	fini := make(chan struct{})
	go func() { surveiller(ctx, m, cpu, time.Hour, make(chan notifs.Evenement, 4)); close(fini) }()
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

// R35 : sur le maître (wg-mesh en 10.10.0.1, wg-autoload en 10.64.0.1), l'agent journalise une fois et attend l'arrêt,
// sans jamais rendre de maître (donc sans contacter le canal, qui le refuserait à vie et remplirait l'audit).
func TestAgentSurLeMaitreAttendSansContacterLeCanal(t *testing.T) {
	for nom, adrs := range map[string][]ifaceAdr{
		"wg-mesh":     {ia("wg-mesh", "10.10.0.1/24"), ia("wg-autoload", "10.64.0.1/16")},
		"wg-autoload": {ia("wg-autoload", "10.64.0.1/16")},
	} {
		t.Run(nom, func(t *testing.T) {
			j := journal(t)
			appels := 0
			lister := func() []ifaceAdr { appels++; return adrs }
			ctx, annule := context.WithCancel(context.Background())
			type res struct{ m, ip string }
			ch := make(chan res, 1)
			go func() {
				m, ip := attendreMaitre(ctx, "", lister, 10*time.Millisecond)
				ch <- res{m, ip}
			}()
			time.Sleep(200 * time.Millisecond)
			select {
			case r := <-ch:
				t.Fatalf("maître %q rendu sur le maître lui-même", r.m)
			default:
			}
			annule()
			select {
			case r := <-ch:
				if r.m != "" || r.ip != "" {
					t.Fatalf("rendu (%q, %q) à l'arrêt", r.m, r.ip)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("pas de retour à l'annulation")
			}
			if appels != 1 {
				t.Errorf("%d lectures d'interfaces : le maître ne revérifie pas", appels)
			}
			if n := strings.Count(j.String(), "adresse du maître"); n != 1 {
				t.Errorf("%d ligne(s) de journal, attendu 1 : %q", n, j.String())
			}
		})
	}
}

type lue struct {
	nom     string
	chemins []string
	n       *atomic.Int32
}

func (l lue) Nom() string       { return l.nom }
func (l lue) Chemins() []string { return l.chemins }
func (l lue) Lire(context.Context) (map[string]any, error) {
	l.n.Add(1)
	return map[string]any{}, nil
}

type compteCPU struct{ n atomic.Int32 }

func (c *compteCPU) EchantillonnerCPU() { c.n.Add(1) }

// M3 + M1 : la surveillance ne lit que les sources dont le détecteur a besoin (mémoire, UpTime, services) et
// fait avancer, seule, la fenêtre CPU (un échantillon par tour).
func TestSurveillerNeLitQueLesSourcesDuDetecteur(t *testing.T) {
	var sys, svc, pkg, expo atomic.Int32
	m := modele.NouveauModele(
		lue{"systeme", []string{"Device.DeviceInfo.UpTime", "Device.DeviceInfo.MemoryStatus.X_SECUBOX_Available"}, &sys},
		lue{"systemd", []string{"Device.X_SECUBOX_Services.{i}.NRestarts"}, &svc},
		lue{"paquets", []string{"Device.DeviceInfo.SoftwareVersion", "Device.X_SECUBOX_Packages.{i}.Name"}, &pkg},
		lue{"exposition", []string{"Device.X_SECUBOX_Exposure.Names"}, &expo},
	)
	cpu := &compteCPU{}
	ctx, annule := context.WithCancel(context.Background())
	fini := make(chan struct{})
	go func() { surveiller(ctx, m, cpu, 20*time.Millisecond, make(chan notifs.Evenement, 4)); close(fini) }()
	time.Sleep(110 * time.Millisecond)
	annule()
	<-fini
	if sys.Load() == 0 || svc.Load() == 0 {
		t.Fatalf("sources du détecteur non lues : systeme=%d systemd=%d", sys.Load(), svc.Load())
	}
	if pkg.Load() != 0 || expo.Load() != 0 {
		t.Fatalf("sources inutiles au détecteur lues : paquets=%d exposition=%d", pkg.Load(), expo.Load())
	}
	if n := cpu.n.Load(); n != sys.Load() {
		t.Fatalf("%d échantillons CPU pour %d tours", n, sys.Load())
	}
}
