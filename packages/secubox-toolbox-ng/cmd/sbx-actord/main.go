// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Command sbx-actord — moteur Actor Intelligence de SecuBox Toolbox NG (RFC-0013).
//
// Phase 0/1 : SHADOW, 100 % observation. Le démon reçoit les Event Envelopes des
// capteurs (sbxwaf, sbxdpi, sbx-authwatch, sbx-sentinel) sur un socket unix non
// bloquant, les valide et les persiste (bbolt append-only), et expose une API
// read-only locale que la console consomme. Il ne prend AUCUNE décision et
// n'applique AUCUN blocage — la corrélation, le scoring et la réponse graduée
// arriveront dans internal/actor/{similarity,graph,knowledge,intent,response}.
//
// Si actord tombe, les capteurs (SBX WAF/DPI) continuent de protéger : l'émission
// vers actord est fire-and-forget (RFC-0013 §15, backpressure).
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/envelope"
	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/store"
)

func main() {
	var (
		dbPath     = flag.String("db", "/var/lib/secubox/actor/actord.db", "chemin du magasin bbolt")
		ingestSock = flag.String("ingest-socket", "/run/secubox/actord.sock", "socket unix d'ingestion des enveloppes")
		apiSock    = flag.String("api-socket", "/run/secubox/actor.sock", "socket unix de l'API read-only")
		shadow     = flag.Bool("shadow", true, "mode observation (Phase 0/1) : ne décide ni n'applique rien")
		readOnly   = flag.Bool("read-only", false, "n'ingère pas ; sert uniquement l'API sur un store existant")
		retention  = flag.Duration("retention", 30*24*time.Hour, "durée de rétention des événements")
		queue      = flag.Int("queue", 4096, "profondeur de la file d'ingestion (backpressure)")
		workers    = flag.Int("workers", 2, "nombre de workers d'écriture")
	)
	flag.Parse()
	log.SetFlags(log.LstdFlags | log.LUTC)

	if !*shadow {
		// Garde-fou : la Phase 0/1 est shadow. Activer l'enforcement viendra dans
		// une phase ultérieure et séparée (RFC-0013 §18) — refus explicite ici.
		log.Fatal("actord: --shadow=false non supporté en Phase 0/1 (aucun enforcement livré)")
	}

	if err := os.MkdirAll(filepath.Dir(*dbPath), 0o750); err != nil {
		log.Fatalf("actord: création du répertoire du store : %v", err)
	}
	st, err := store.Open(*dbPath)
	if err != nil {
		log.Fatalf("actord: %v", err)
	}
	defer st.Close()

	srv := &Server{store: st, shadow: *shadow}

	if !*readOnly {
		ch := make(chan *envelope.Envelope, *queue)
		for i := 0; i < *workers; i++ {
			go srv.worker(ch)
		}
		go func() {
			if err := srv.serveIngest(*ingestSock, ch); err != nil {
				log.Fatalf("actord: ingestion : %v", err)
			}
		}()
	} else {
		log.Printf("actord: --read-only : ingestion désactivée, API seule")
	}

	go func() {
		if err := srv.serveAPI(*apiSock); err != nil {
			log.Fatalf("actord: API : %v", err)
		}
	}()

	go srv.pruneLoop(*retention)

	// Arrêt propre.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	log.Printf("actord: démarré (db=%s, retention=%s)", *dbPath, *retention)
	<-ctx.Done()
	log.Printf("actord: arrêt")
}

// pruneLoop applique la rétention toutes les heures.
func (s *Server) pruneLoop(retention time.Duration) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for range t.C {
		before := time.Now().Add(-retention).Unix()
		if n, err := s.store.Prune(before); err != nil {
			log.Printf("actord: prune: %v", err)
		} else if n > 0 {
			log.Printf("actord: prune %d événements antérieurs à %s", n, time.Unix(before, 0).UTC())
		}
	}
}
