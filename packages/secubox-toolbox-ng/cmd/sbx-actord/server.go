// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/envelope"
	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/evidence"
	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/graph"
	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/store"
)

// Server porte l'état partagé du démon. Phase 0/1 : SHADOW — on ingère, on
// corrèle et on expose, on ne décide ni n'applique rien (RFC-0013 §11).
type Server struct {
	store  *store.Store
	shadow bool

	// Corrélation en mémoire (reconstruite au démarrage depuis le store).
	mu     sync.Mutex
	graph  *graph.Graph
	ledger *evidence.Ledger
	accum  map[string]*actorSignals

	ingested   atomic.Uint64 // enveloppes persistées
	correlated atomic.Uint64 // enveloppes passées par le pipeline de corrélation
	dropped    atomic.Uint64 // rejetées faute de place (backpressure, jamais bloquant)
	invalid    atomic.Uint64 // rejetées par Validate (événements forgés/malformés)
}

// worker draine la file d'ingestion vers le store puis corrèle. C'est la seule
// voie qui écrit sur bbolt.
func (s *Server) worker(ch <-chan *envelope.Envelope) {
	for e := range ch {
		if err := s.store.Ingest(e); err != nil {
			log.Printf("actord: ingest: %v", err)
			continue
		}
		s.ingested.Add(1)
		s.correlate(e)
	}
}

// serveIngest écoute le socket d'ingestion. Chaque connexion apporte des
// enveloppes JSON délimitées par newline (même transport que sentinel.Mirror).
// L'écriture producteur n'est JAMAIS bloquée : si la file est pleine on DÉPOSE
// l'événement et on l' compte (backpressure) — le hot path prime (§11, §15).
func (s *Server) serveIngest(path string, ch chan<- *envelope.Envelope) error {
	_ = os.Remove(path) // socket périmé d'un run précédent
	ln, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	_ = os.Chmod(path, 0o660)
	log.Printf("actord: ingestion sur %s (shadow=%v)", path, s.shadow)
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			log.Printf("actord: accept: %v", err)
			continue
		}
		go s.handleConn(conn, ch)
	}
}

func (s *Server) handleConn(conn net.Conn, ch chan<- *envelope.Envelope) {
	defer conn.Close()
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20) // ligne max 1 Mio (anti-forge)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		e := new(envelope.Envelope)
		if json.Unmarshal(line, e) != nil {
			s.invalid.Add(1)
			continue
		}
		if e.EventID == "" {
			e.EventID = envelope.NewEventID()
		}
		if err := e.Validate(); err != nil {
			s.invalid.Add(1)
			continue
		}
		select {
		case ch <- e:
		default:
			s.dropped.Add(1) // file pleine : on dépose plutôt que bloquer le producteur
		}
	}
}

// serveAPI expose l'API read-only locale (RFC-0013 §9) sur un socket unix, que
// le vhost du Hall proxie. Aucune route n'écrit ni ne décide.
func (s *Server) serveAPI(path string) error {
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	_ = os.Chmod(path, 0o660)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"ok": true, "schema": envelope.SchemaVersion})
	})
	// Routes exposées à DEUX préfixes : le préfixe complet (relais nginx du Hall,
	// chemin préservé) ET la racine (agrégateur admin.gk2, qui STRIPPE le préfixe
	// /api/v1/<module>). Le même socket sert ainsi le Hall ET le panneau admin,
	// sans divergence de chemin.
	for _, p := range []string{"/api/v1/actor", ""} {
		mux.HandleFunc("GET "+p+"/stats", s.handleStats)
		mux.HandleFunc("GET "+p+"/actors", s.handleActors)
		mux.HandleFunc("GET "+p+"/actors/{id}", s.handleActor)
		mux.HandleFunc("GET "+p+"/campaigns", s.handleCampaigns)
		mux.HandleFunc("GET "+p+"/evidence/{id}", s.handleEvidence)
		mux.HandleFunc("POST "+p+"/feedback/{id}", s.handleFeedback)
	}
	log.Printf("actord: API sur %s", path)
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	return srv.Serve(ln)
}

func (s *Server) handleStats(w http.ResponseWriter, _ *http.Request) {
	st, err := s.store.Stats(time.Now().Unix())
	if err != nil {
		http.Error(w, "stats indisponibles", http.StatusInternalServerError)
		return
	}
	// Agrégats de corrélation (acteurs, campagnes, posture) depuis le graphe.
	s.mu.Lock()
	actors := s.graph.Len()
	campaigns, top := 0, 0
	for _, a := range s.graph.Actors() {
		if len(a.IPs) >= 2 || len(a.Countries) >= 2 {
			campaigns++
		}
		if a.Priority > top {
			top = a.Priority
		}
	}
	s.mu.Unlock()

	// Posture globale : 100 quand rien ne pèse, dégradée par l'acteur le plus
	// prioritaire (dérivée du réel, pas une valeur fixe).
	global := 100 - top/3

	// Contrat consommé par docs/design/actor-intelligence-webui.html.
	writeJSON(w, map[string]any{
		"mode":         "observe",
		"shadow":       s.shadow,
		"posture":      "Protégée",
		"blocked_24h":  st.Blocked24h,
		"attempts_24h": st.Attempts24h,
		"events_24h":   st.Events24h,
		"actors":       actors,
		"campaigns":    campaigns,
		"honey_active": 0, // framework honey-identities : déclaratif, pas encore de leurres actifs
		"honey_hit":    0,
		"global":       global,
		"by_sensor":    st.BySensor,
		"total_events": st.Total,
		"ingested":     s.ingested.Load(),
		"dropped":      s.dropped.Load(),
		"invalid":      s.invalid.Load(),
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
