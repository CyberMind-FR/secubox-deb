// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-pilotage-agent/internal/notifs"
)

// TestVeilleNotifieLesBasculesLocales : l'agent lit `sudo -n secubox-pilotagectl etat` à chaque pas (aucun autre droit
// que le sudoers existant) et pousse HandsTied, Consent et Support quand l'état change ; une lecture en échec ne
// produit rien.
func TestVeilleNotifieLesBasculesLocales(t *testing.T) {
	etats := []string{
		`{"ok": true, "mains_liees": false, "consentements": [{"id": "0123456789abcdef", "etat": "en_attente"}], "support": null}`,
		"", // échec du ctl
		`{"ok": true, "mains_liees": true, "consentements": [{"id": "0123456789abcdef", "etat": "annule"}], "support": null}`,
	}
	var mu sync.Mutex
	var argvs [][]string
	i := 0
	ctl := func(_ context.Context, args ...string) ([]byte, error) {
		mu.Lock()
		defer mu.Unlock()
		argvs = append(argvs, args)
		if i >= len(etats) {
			return []byte(etats[len(etats)-1]), nil
		}
		s := etats[i]
		i++
		if s == "" {
			return nil, errors.New("sudo : code 1")
		}
		return []byte(s), nil
	}
	ev := make(chan notifs.Evenement, 8)
	ctx, arret := context.WithCancel(context.Background())
	fini := make(chan struct{})
	go func() { veiller(ctx, ctl, time.Millisecond, ev); close(fini) }()
	var recus []notifs.Evenement
	for len(recus) < 2 {
		select {
		case e := <-ev:
			recus = append(recus, e)
		case <-time.After(5 * time.Second):
			t.Fatalf("notifications attendues, reçues %+v", recus)
		}
	}
	arret()
	<-fini
	if recus[0].Type != notifs.TypeMainsLiees || recus[0].Etat != "on" ||
		recus[1].Type != notifs.TypeConsentement || recus[1].ID != "0123456789abcdef" || recus[1].Decision != "annule" {
		t.Fatalf("notifications %+v", recus)
	}
	mu.Lock()
	defer mu.Unlock()
	if want := []string{"-n", "/usr/sbin/secubox-pilotagectl", "etat"}; !reflect.DeepEqual(argvs[0], want) {
		t.Fatalf("argv %v, attendu %v", argvs[0], want)
	}
}
