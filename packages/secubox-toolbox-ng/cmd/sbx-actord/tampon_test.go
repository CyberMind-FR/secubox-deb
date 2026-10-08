// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestTamponServeLInstantaneSansCalculerSurLaRequete(t *testing.T) {
	var b tampon[int]
	var n atomic.Int32
	liberer := make(chan struct{})
	calcule := func() (int, error) {
		k := int(n.Add(1))
		if k > 1 {
			<-liberer // le renouvellement est LENT : la requête ne doit pas l'attendre
		}
		return k, nil
	}
	if v, _ := b.lire(time.Hour, calcule); v != 1 {
		t.Fatalf("démarrage à froid : %d", v)
	}
	b.perime()
	fait := make(chan int, 1)
	go func() { v, _ := b.lire(time.Hour, calcule); fait <- v }()
	select {
	case v := <-fait:
		if v != 1 {
			t.Fatalf("un instantané périmé doit être servi tel quel : %d", v)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("la requête a attendu le recalcul : ce n'est pas un double tampon")
	}
	close(liberer)
	for i := 0; i < 200; i++ {
		if v, _ := b.lire(time.Hour, calcule); v == 2 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("le nouvel instantané n'a jamais été publié")
}

func TestTamponUnSeulRenouvellementALaFois(t *testing.T) {
	var b tampon[int]
	var n atomic.Int32
	liberer := make(chan struct{})
	calcule := func() (int, error) {
		k := int(n.Add(1))
		if k > 1 {
			<-liberer
		}
		return k, nil
	}
	b.lire(time.Hour, calcule)
	b.perime()
	for i := 0; i < 20; i++ {
		b.lire(time.Hour, calcule)
	}
	time.Sleep(50 * time.Millisecond)
	if got := n.Load(); got != 2 {
		t.Fatalf("20 appels pendant un renouvellement ont lancé %d calculs (1 à froid + 1 attendu)", got)
	}
	close(liberer)
}

func TestTamponUneErreurNeRemplacePasLInstantane(t *testing.T) {
	var b tampon[int]
	ok := true
	calcule := func() (int, error) {
		if ok {
			return 7, nil
		}
		return 0, errDeTest
	}
	b.lire(time.Hour, calcule)
	ok = false
	b.perime()
	b.lire(time.Hour, calcule)
	time.Sleep(50 * time.Millisecond)
	if v, err := b.lire(time.Hour, calcule); err != nil || v != 7 {
		t.Fatalf("l'instantané valide doit survivre à une erreur : %d %v", v, err)
	}
}

type erreurTest string

func (e erreurTest) Error() string { return string(e) }

const errDeTest = erreurTest("calcul impossible")
