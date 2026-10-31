// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"testing"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/envelope"
	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/graph"
)

// #3320 : un fichier inchange n'est pas reecrit, sauf pour rester frais aux yeux
// de sbxwaf (qui ignore un fichier trop vieux).
func TestEcritureConditionnelle(t *testing.T) {
	var e etatEcriture
	t0 := time.Unix(1000, 0)
	if !e.doitEcrire([]byte("a"), t0, 5*time.Minute) {
		t.Fatal("premiere ecriture attendue")
	}
	if e.doitEcrire([]byte("a"), t0.Add(time.Minute), 5*time.Minute) {
		t.Fatal("contenu identique et recent : pas d'ecriture")
	}
	if !e.doitEcrire([]byte("b"), t0.Add(2*time.Minute), 5*time.Minute) {
		t.Fatal("contenu change : ecriture")
	}
	if !e.doitEcrire([]byte("b"), t0.Add(8*time.Minute), 5*time.Minute) {
		t.Fatal("contenu identique mais trop vieux : ecriture de rafraichissement")
	}
}

// #3320 : la purge horaire retire aussi les acteurs du graphe et leurs signaux.
func TestPurgerMemoire(t *testing.T) {
	s := &Server{graph: graph.New(0), accum: map[string]*actorSignals{}}
	s.observe(&envelope.Envelope{EventID: "e1", SrcIP: "1.1.1.1", PathShape: "p", Timestamp: 100})
	s.observe(&envelope.Envelope{EventID: "e2", SrcIP: "2.2.2.2", PathShape: "q", Timestamp: 9000})
	if n := s.purgerMemoire(1000); n != 1 || s.graph.Len() != 1 || len(s.accum) != 1 {
		t.Fatalf("purge : n=%d graphe=%d accum=%d", n, s.graph.Len(), len(s.accum))
	}
}

// #3320 : les observations de connaissance sont bornees par niveau.
func TestObservationsConnaissanceBornees(t *testing.T) {
	acc := &actorSignals{windows: map[int64]bool{}, days: map[string]bool{}}
	for i := 0; i < 3*knowMaxParNiveau; i++ {
		mergeTags(acc, &envelope.Envelope{EventID: "e", Timestamp: 1, BehaviorTags: []string{"k1", "k3"}})
	}
	if len(acc.know) != 2*knowMaxParNiveau {
		t.Fatalf("know = %d, attendu %d", len(acc.know), 2*knowMaxParNiveau)
	}
}

// #3320 : le worker regroupe les evenements en lots (une transaction par lot
// pour le magasin et pour le ledger), sans rien perdre ni rien correler deux fois.
func TestWorkerParLots(t *testing.T) {
	s := serveur(t)
	ch := make(chan *envelope.Envelope, 1024)
	for i := 0; i < 600; i++ {
		ch <- &envelope.Envelope{EventID: envelope.NewEventID(), SrcIP: "1.1.1.1", PathShape: "p", Sensor: "sbxwaf", Timestamp: int64(1000 + i)}
	}
	close(ch)
	s.worker(ch) // rend la main a la fermeture du canal
	if s.ingested.Load() != 600 || s.correlated.Load() != 600 {
		t.Fatalf("ingested=%d correlated=%d", s.ingested.Load(), s.correlated.Load())
	}
	if n, _ := s.ledger.Count(); n != 600 {
		t.Fatalf("ledger = %d", n)
	}
	if evs, _ := s.store.Recent(1000); len(evs) != 600 {
		t.Fatalf("magasin = %d", len(evs))
	}
}
