// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
package main

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// LE PREMIER TOUR ATTEND LES PASSES DE DÉMARRAGE (#1835). Côte à côte, les
// deux regroupaient les mêmes orphelins : sujets créés deux fois, travail
// doublé, vingt-cinq minutes de démarrage sur gk2.
func TestPremierTourApresLesPasses(t *testing.T) {
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	var passesFinies, tourAvant atomic.Bool
	tours := make(chan struct{}, 4)
	avant := func() {
		time.Sleep(50 * time.Millisecond)
		passesFinies.Store(true)
	}
	tour := func() {
		if !passesFinies.Load() {
			tourAvant.Store(true)
		}
		tours <- struct{}{}
	}
	go boucle(ctx, avant, tour, time.Hour)
	select {
	case <-tours:
	case <-time.After(2 * time.Second):
		t.Fatal("aucun tour après les passes")
	}
	if tourAvant.Load() {
		t.Fatal("un tour a commencé avant la fin des passes de démarrage")
	}
}

func TestArretPendantLesPassesSansTour(t *testing.T) {
	ctx, stop := context.WithCancel(context.Background())
	var tours atomic.Int32
	fini := make(chan struct{})
	go func() {
		boucle(ctx, func() { stop() }, func() { tours.Add(1) }, time.Hour)
		close(fini)
	}()
	select {
	case <-fini:
	case <-time.After(2 * time.Second):
		t.Fatal("boucle ne s'arrête pas")
	}
	if tours.Load() != 0 {
		t.Fatalf("%d tour(s) après l'arrêt", tours.Load())
	}
}
