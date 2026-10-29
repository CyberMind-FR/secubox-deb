// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package collecte

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func lanceurFixe(t *testing.T) func(context.Context, ...string) ([]byte, error) {
	return func(ctx context.Context, args ...string) ([]byte, error) {
		b, err := os.ReadFile("testdata/systemctl/show.txt")
		if err != nil {
			t.Fatal(err)
		}
		return b, nil
	}
}

func TestSystemdLitLesRelancesEtLesEchecs(t *testing.T) {
	appels := 0
	var args []string
	l := func(ctx context.Context, a ...string) ([]byte, error) {
		appels++
		args = a
		return lanceurFixe(t)(ctx, a...)
	}
	s := NouvelleSourceSystemd(l)
	p := lireTout(t, s)
	if appels != 1 {
		t.Errorf("%d appels, attendu 1", appels)
	}
	if got := strings.Join(args, " "); !strings.HasPrefix(got, "show --property=Id,ActiveState,SubState,NRestarts,Result secubox-*") ||
		!strings.Contains(got, "nginx.service unbound.service ssh.service nftables.service") {
		t.Errorf("arguments inattendus : %s", got)
	}
	const r = "Device.X_SECUBOX_Services."
	if p[r+"1.Name"] != "secubox-ndpisrvd.service" || p[r+"1.NRestarts"] != uint64(391) ||
		p[r+"1.ActiveState"] != "activating" || p[r+"1.SubState"] != "auto-restart" || p[r+"1.Result"] != "exit-code" {
		t.Errorf("service 1 inattendu : %v", p)
	}
	if p[r+"FailedNumberOfEntries"] != 1 {
		t.Errorf("FailedNumberOfEntries = %v", p[r+"FailedNumberOfEntries"])
	}
	if _, ok := p[r+"5.Name"]; ok {
		t.Error("« autre.service » ne doit pas être publié")
	}
	if p[r+"4.Name"] != "secubox-core.service" {
		t.Errorf("4 = %v", p[r+"4.Name"])
	}
	verifierChemins(t, s, p)
}

func TestSystemdBorneA200Unites(t *testing.T) {
	var sb strings.Builder
	for i := 0; i < 250; i++ {
		fmt.Fprintf(&sb, "Id=secubox-m%d.service\nActiveState=active\nSubState=running\nNRestarts=0\nResult=success\n\n", i)
	}
	s := NouvelleSourceSystemd(func(context.Context, ...string) ([]byte, error) { return []byte(sb.String()), nil })
	p := lireTout(t, s)
	if _, ok := p["Device.X_SECUBOX_Services.200.Name"]; !ok {
		t.Error("la 200e unité manque")
	}
	if _, ok := p["Device.X_SECUBOX_Services.201.Name"]; ok {
		t.Error("au plus 200 unités")
	}
}

func TestSystemdDelaiDepasse(t *testing.T) {
	s := NouvelleSourceSystemd(func(ctx context.Context, _ ...string) ([]byte, error) {
		time.Sleep(10 * time.Second) // ignore volontairement le contexte
		return nil, nil
	})
	debut := time.Now()
	_, err := s.Lire(context.Background())
	if err == nil {
		t.Fatal("une erreur est attendue")
	}
	if d := time.Since(debut); d > 6*time.Second {
		t.Errorf("Lire a bloqué %v", d)
	}
}

func TestSystemdErreurDuLanceur(t *testing.T) {
	s := NouvelleSourceSystemd(func(context.Context, ...string) ([]byte, error) { return nil, fmt.Errorf("absent") })
	if _, err := s.Lire(context.Background()); err == nil {
		t.Error("une erreur est attendue")
	}
}
