// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/evidence"
	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/graph"
	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/score"
)

// webActor est la projection d'un graph.Actor dans le format consommé par la
// console (docs/design/actor-intelligence-webui.html). Rien n'est inventé : tous
// les champs dérivent du ThreatVector réel et des agrégats du graphe.
type webActor struct {
	ID       string       `json:"id"`
	Name     string       `json:"name"`
	Priority int          `json:"priority"`
	Level    string       `json:"level"`
	Tags     [][2]string  `json:"tags"`
	Vec      graph.Vector `json:"vec"`
	Src      srcCounts    `json:"src"`
	First    string       `json:"first"`
	Last     string       `json:"last"`
	Targets  []string     `json:"targets"`
	Hyp      [][2]any     `json:"hyp"`
	TL       []any        `json:"tl"`
}

type srcCounts struct {
	IPs       int `json:"ips"`
	ASNs      int `json:"asns"`
	Countries int `json:"countries"`
}

func hhmm(ts int64) string {
	if ts == 0 {
		return "—"
	}
	return time.Unix(ts, 0).UTC().Format("15:04")
}

func niveau(prio int) string {
	switch {
	case prio >= 80:
		return "HIGH"
	case prio >= 50:
		return "MED"
	default:
		return "LOW"
	}
}

func tags(v graph.Vector) [][2]string {
	var out [][2]string
	if v.Automation >= 70 {
		out = append(out, [2]string{"automatisé", "auto"})
	}
	if v.Intent >= 70 {
		out = append(out, [2]string{"ciblé", "target"})
	}
	if v.Knowledge >= 45 {
		out = append(out, [2]string{"reconnaissance", "recon"})
	}
	if len(out) == 0 {
		out = append(out, [2]string{"observé", ""})
	}
	return out
}

// hypotheses dérive une distribution d'hypothèses concurrentes du ThreatVector
// (RFC-0013 §10 : contre-hypothèses). Probabilités normalisées, arrondies.
func hypotheses(v graph.Vector) [][2]any {
	type h struct {
		label string
		w     float64
	}
	hs := []h{
		{"campagne ciblée automatisée", float64(v.Automation+v.Intent) / 2},
		{"bot générique / scanner", float64(v.Automation)},
		{"bruit non relié", float64(score.Clamp(100 - v.Confidence))},
	}
	sum := 0.0
	for _, x := range hs {
		sum += x.w
	}
	if sum <= 0 {
		sum = 1
	}
	sort.Slice(hs, func(i, j int) bool { return hs[i].w > hs[j].w })
	out := make([][2]any, 0, len(hs))
	for _, x := range hs {
		p := float64(int(x.w/sum*100+0.5)) / 100
		out = append(out, [2]any{x.label, p})
	}
	return out
}

func toWeb(a *graph.Actor) webActor {
	return webActor{
		ID: a.ID, Name: "", Priority: a.Priority, Level: niveau(a.Priority),
		Tags: tags(a.Vector), Vec: a.Vector,
		Src:   srcCounts{IPs: len(a.IPs), ASNs: len(a.ASNs), Countries: len(a.Countries)},
		First: hhmm(a.FirstSeen), Last: hhmm(a.LastSeen),
		Targets: a.Targets, Hyp: hypotheses(a.Vector), TL: []any{},
	}
}

func (s *Server) handleActors(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	list := s.graph.Actors()
	out := make([]webActor, 0, len(list))
	for _, a := range list {
		out = append(out, toWeb(a))
	}
	s.mu.Unlock()
	writeJSON(w, out)
}

func (s *Server) handleActor(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.mu.Lock()
	a, ok := s.graph.Get(id)
	var wa webActor
	if ok {
		wa = toWeb(a)
	}
	s.mu.Unlock()
	if !ok {
		http.Error(w, "acteur inconnu", http.StatusNotFound)
		return
	}
	writeJSON(w, wa)
}

// handleCampaigns : une campagne = un acteur multi-sources (plusieurs IP ou pays)
// — un même comportement reproduit par des sources successives (RFC-0004).
func (s *Server) handleCampaigns(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	var out []map[string]any
	for _, a := range s.graph.Actors() {
		if len(a.IPs) >= 2 || len(a.Countries) >= 2 {
			out = append(out, map[string]any{
				"actor_id": a.ID, "priority": a.Priority,
				"continuity": a.Vector.Continuity, "sources": len(a.IPs),
				"asns": len(a.ASNs), "countries": len(a.Countries), "targets": a.Targets,
			})
		}
	}
	s.mu.Unlock()
	writeJSON(w, out)
}

func (s *Server) handleEvidence(w http.ResponseWriter, r *http.Request) {
	if s.ledger == nil {
		http.Error(w, "ledger indisponible", http.StatusServiceUnavailable)
		return
	}
	rec, ok, err := s.ledger.Get(r.PathValue("id"))
	if err != nil {
		http.Error(w, "erreur ledger", http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "preuve inconnue", http.StatusNotFound)
		return
	}
	writeJSON(w, rec)
}

// handleFeedback : le feedback opérateur (RFC-0013 §9) est CONSIGNÉ (preuve
// inviolable) mais ne réécrit jamais l'historique ; l'ajustement des poids
// futurs viendra dans une phase de calibration séparée.
func (s *Server) handleFeedback(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	body, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
	var in struct {
		Label string `json:"label"`
	}
	_ = json.Unmarshal(body, &in)
	valid := map[string]bool{"false_positive": true, "confirmed_campaign": true, "known_scanner": true, "unknown": true}
	if !valid[in.Label] {
		http.Error(w, "label invalide", http.StatusUnprocessableEntity)
		return
	}
	if s.ledger != nil {
		_, _ = s.ledger.Append(evidence.Record{
			ID:               "fb-" + id + "-" + time.Now().UTC().Format("20060102T150405"),
			Timestamp:        time.Now().Unix(),
			Sensor:           "operator",
			Observation:      "feedback " + in.Label + " sur " + id,
			Explanation:      "consigné, sans réécriture de l'historique",
			AlgorithmVersion: score.AlgoVersion,
		})
	}
	writeJSON(w, map[string]any{"ok": true, "label": in.Label, "actor": id})
}
