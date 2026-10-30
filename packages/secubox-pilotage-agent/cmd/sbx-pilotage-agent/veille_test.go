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
	"github.com/CyberMind-FR/secubox-deb/secubox-pilotage-agent/internal/operations"
)

func recevoir(t *testing.T, ev <-chan notifs.Evenement, n int) []notifs.Evenement {
	t.Helper()
	var recus []notifs.Evenement
	for len(recus) < n {
		select {
		case e := <-ev:
			recus = append(recus, e)
		case <-time.After(5 * time.Second):
			t.Fatalf("%d notifications attendues, reçues %+v", n, recus)
		}
	}
	return recus
}

// TestVeilleNotifieLesBasculesLocales : l'agent lit `sudo -n secubox-pilotagectl etat` à chaque pas (aucun autre droit
// que le sudoers existant) et pousse HandsTied, Consent et Support quand l'état change ; le premier état renotifie
// les mains liées (R-L2-33) ; une lecture en échec ne produit rien.
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
	go func() { veiller(ctx, ctl, time.Millisecond, nil, ev); close(fini) }()
	recus := recevoir(t, ev, 3)
	arret()
	<-fini
	if recus[0].Type != notifs.TypeMainsLiees || recus[0].Etat != "off" ||
		recus[1].Type != notifs.TypeMainsLiees || recus[1].Etat != "on" ||
		recus[2].Type != notifs.TypeConsentement || recus[2].ID != "0123456789abcdef" || recus[2].Decision != "annule" {
		t.Fatalf("notifications %+v", recus)
	}
	mu.Lock()
	defer mu.Unlock()
	if want := []string{"-n", "/usr/sbin/secubox-pilotagectl", "etat"}; !reflect.DeepEqual(argvs[0], want) {
		t.Fatalf("argv %v, attendu %v", argvs[0], want)
	}
}

// TestVeilleToutesLesCinqMinutesEtApresChaqueOperate (R-L2-30) : le pas est de 5 min ; un Operate traité provoque une
// lecture immédiate (sans attendre le pas), une seule même pour plusieurs Operate rapprochés.
func TestVeilleToutesLesCinqMinutesEtApresChaqueOperate(t *testing.T) {
	if pasVeille != 5*time.Minute {
		t.Fatalf("pasVeille %v", pasVeille)
	}
	etats := []string{
		`{"ok": true, "mains_liees": false, "consentements": [], "support": null}`,
		`{"ok": true, "mains_liees": true, "consentements": [], "support": null}`,
	}
	var mu sync.Mutex
	appels := 0
	ctl := func(_ context.Context, _ ...string) ([]byte, error) {
		mu.Lock()
		defer mu.Unlock()
		s := etats[min(appels, len(etats)-1)]
		appels++
		return []byte(s), nil
	}
	relire := make(chan struct{}, 1)
	agir := apresOperate(func(context.Context, string, map[string]any, string) operations.Reponse {
		return operations.Reponse{Etat: operations.Refuse, Raison: "mains liées"}
	}, relire)
	ev := make(chan notifs.Evenement, 8)
	ctx, arret := context.WithCancel(context.Background())
	defer arret()
	go veiller(ctx, ctl, time.Hour, relire, ev)
	recevoir(t, ev, 1) // premier état : mains déliées
	if r := agir(ctx, "Device.Reboot()", nil, "gk2admin"); r.Raison != "mains liées" {
		t.Fatalf("réponse non transmise : %+v", r)
	}
	agir(ctx, "Device.Reboot()", nil, "gk2admin") // signal non bloquant, coalescé
	if e := recevoir(t, ev, 1)[0]; e.Type != notifs.TypeMainsLiees || e.Etat != "on" {
		t.Fatalf("notification %+v", e)
	}
}
