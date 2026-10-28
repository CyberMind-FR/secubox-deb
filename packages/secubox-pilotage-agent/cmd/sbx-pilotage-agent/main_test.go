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
