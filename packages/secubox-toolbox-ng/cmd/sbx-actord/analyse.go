// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/analysis"
	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/envelope"
	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/graph"
)

// Actor Intelligence 2.0, phase 3 (#2240) : ce que fait un acteur (chronologie), avec qui et vers quoi (graphe), et ce qu'on en conclut (risque,
// confiance, scénario, décision). Lecture seule. Ces routes portent des ADRESSES et des CIBLES : elles n'existent que dans la vue complète, comme
// /proposals et /evidence — la vue réduite et l'arbre relayé répondent comme une route inexistante.

const (
	evenementsTTL   = 10 * time.Second
	evenementsRelus = 20000
	limiteParDefaut = 200
	limiteMax       = 1000
)

// evenements rend les derniers événements du store, relus au plus toutes les 10 s (double tampon : jamais de calcul sur le chemin d'une requête).
func (s *Server) evenements() ([]envelope.Envelope, error) {
	return s.evT.lire(evenementsTTL, func() ([]envelope.Envelope, error) { return s.store.Recent(evenementsRelus) })
}

func projeter(e envelope.Envelope) analysis.Event {
	return analysis.Event{ID: e.EventID, TS: e.Timestamp, Sensor: e.Sensor, Rule: e.RuleID, Action: e.Action, Target: e.DstService, Severity: e.Severity,
		Tags: e.BehaviorTags, SrcIP: e.SrcIP}
}

// evenementsActeur : les événements dont la source est l'une des adresses de l'acteur. Les robots connus (#2201) ne sont pas des acteurs : écartés.
func (s *Server) evenementsActeur(a *graph.Actor) ([]analysis.Event, error) {
	tous, err := s.evenements()
	if err != nil {
		return nil, err
	}
	ips := map[string]bool{}
	for _, ip := range a.IPs {
		ips[ip] = true
	}
	var out []analysis.Event
	for _, e := range tous {
		if !ips[e.SrcIP] {
			continue
		}
		if _, robot := estRobotConnu(&e); robot {
			continue
		}
		out = append(out, projeter(e))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TS < out[j].TS })
	return out, nil
}

func (s *Server) acteur(w http.ResponseWriter, r *http.Request) (*graph.Actor, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.graph.Get(r.PathValue("id"))
	if !ok {
		http.Error(w, "acteur inconnu", http.StatusNotFound)
		return nil, false
	}
	copie := *a // l'acteur est lu hors verrou ensuite : on n'expose jamais le pointeur du graphe vivant
	copie.IPs = append([]string(nil), a.IPs...)
	copie.ASNs = append([]string(nil), a.ASNs...)
	copie.Countries = append([]string(nil), a.Countries...)
	copie.Targets = append([]string(nil), a.Targets...)
	return &copie, true
}

func limiteDe(r *http.Request) int {
	n, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil || n <= 0 {
		return limiteParDefaut
	}
	if n > limiteMax {
		return limiteMax
	}
	return n
}

func (s *Server) handleActorRisk(w http.ResponseWriter, r *http.Request) {
	a, ok := s.acteur(w, r)
	if !ok {
		return
	}
	evs, err := s.evenementsActeur(a)
	if err != nil {
		http.Error(w, "événements illisibles", http.StatusServiceUnavailable)
		return
	}
	var muets []string
	for _, m := range strings.Split(r.URL.Query().Get("muets"), ",") {
		if m = strings.TrimSpace(m); m != "" {
			muets = append(muets, m)
		}
	}
	ev := analysis.Evaluer(analysis.Entree{Events: evs, Vecteur: a.Vector, CapteursMuets: muets, Maintenant: time.Now().Unix()})
	writeJSON(w, map[string]any{"actor_id": a.ID, "genere_le": time.Now().Unix(), "politique": analysis.VersionPolitique, "evaluation": ev,
		"modele_actord": map[string]any{"priorite": a.Priority, "vecteur": a.Vector}})
}

type webEvenement struct {
	analysis.Event
	Etape analysis.Etape `json:"etape"`
	Heure string         `json:"heure"`
}

func (s *Server) handleActorTimeline(w http.ResponseWriter, r *http.Request) {
	a, ok := s.acteur(w, r)
	if !ok {
		return
	}
	evs, err := s.evenementsActeur(a)
	if err != nil {
		http.Error(w, "événements illisibles", http.StatusServiceUnavailable)
		return
	}
	total := len(evs)
	if n := limiteDe(r); len(evs) > n {
		evs = evs[len(evs)-n:] // les n plus récents, toujours en ordre chronologique
	}
	out := make([]webEvenement, 0, len(evs))
	for _, e := range evs {
		out = append(out, webEvenement{Event: e, Etape: analysis.Classer(e), Heure: time.Unix(e.TS, 0).UTC().Format(time.RFC3339)})
	}
	writeJSON(w, map[string]any{"actor_id": a.ID, "total": total, "events": out})
}

func (s *Server) handleActorGraph(w http.ResponseWriter, r *http.Request) {
	a, ok := s.acteur(w, r)
	if !ok {
		return
	}
	evs, err := s.evenementsActeur(a)
	if err != nil {
		http.Error(w, "événements illisibles", http.StatusServiceUnavailable)
		return
	}
	// Pairs : les autres acteurs qui visent exactement le même jeu de cibles (même signature de campagne, voir handleCampaigns).
	var pairs []string
	if len(a.Targets) > 0 {
		sig := signatureCampagne(a.Targets)
		s.mu.Lock()
		for _, b := range s.graph.Actors() {
			if b.ID != a.ID && len(b.Targets) > 0 && signatureCampagne(b.Targets) == sig {
				pairs = append(pairs, b.ID)
			}
		}
		s.mu.Unlock()
	}
	writeJSON(w, analysis.ConstruireGraphe(analysis.EntreeGraphe{ActeurID: a.ID, IPs: a.IPs, ASNs: a.ASNs, Pays: a.Countries, Cibles: a.Targets, Pairs: pairs, Events: evs}))
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	tous, err := s.evenements()
	if err != nil {
		http.Error(w, "événements illisibles", http.StatusServiceUnavailable)
		return
	}
	capteur, regle, lim := r.URL.Query().Get("sensor"), r.URL.Query().Get("rule"), limiteDe(r)
	out := make([]webEvenement, 0, lim)
	for _, e := range tous { // Recent = plus récent d'abord
		if (capteur != "" && e.Sensor != capteur) || (regle != "" && e.RuleID != regle) {
			continue
		}
		if _, robot := estRobotConnu(&e); robot {
			continue
		}
		p := projeter(e)
		out = append(out, webEvenement{Event: p, Etape: analysis.Classer(p), Heure: time.Unix(p.TS, 0).UTC().Format(time.RFC3339)})
		if len(out) >= lim {
			break
		}
	}
	writeJSON(w, map[string]any{"genere_le": time.Now().Unix(), "limite": lim, "events": out})
}
