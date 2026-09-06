// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"bufio"
	"encoding/json"
	"os"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/envelope"
)

// ReplayReport résume un rejeu de calibration (RFC-0013 §13).
type ReplayReport struct {
	Journal   string         `json:"journal"`
	Lines     int            `json:"lines"`
	Kept      int            `json:"kept"`
	Invalid   int            `json:"invalid"`
	OutOfWin  int            `json:"out_of_window"`
	Actors    int            `json:"actors"`
	Campaigns int            `json:"campaigns"`
	BySensor  map[string]int `json:"by_sensor"`
}

// replay rejoue un journal NDJSON d'Event Envelopes (copie anonymisée des
// événements existants) à travers le pipeline de corrélation, SANS écrire de
// preuve (le ledger reflète le live). Sert à mesurer clusters, sources par
// cluster et coûts avant activation (RFC-0013 §13). Retourne un rapport.
func (s *Server) replay(path string, since time.Duration) (ReplayReport, error) {
	rep := ReplayReport{Journal: path, BySensor: map[string]int{}}
	f, err := os.Open(path)
	if err != nil {
		return rep, err
	}
	defer f.Close()

	var cutoff int64
	if since > 0 {
		cutoff = time.Now().Add(-since).Unix()
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		rep.Lines++
		e := new(envelope.Envelope)
		if json.Unmarshal(line, e) != nil {
			rep.Invalid++
			continue
		}
		if e.EventID == "" {
			e.EventID = envelope.NewEventID()
		}
		if cutoff > 0 && e.Timestamp < cutoff {
			rep.OutOfWin++
			continue
		}
		if e.Validate() != nil {
			rep.Invalid++
			continue
		}
		rep.Kept++
		rep.BySensor[e.Sensor]++
		_ = s.store.Ingest(e)
		s.observe(e) // pas de preuve pendant un rejeu
	}
	if err := sc.Err(); err != nil {
		return rep, err
	}

	s.mu.Lock()
	rep.Actors = s.graph.Len()
	for _, a := range s.graph.Actors() {
		if len(a.IPs) >= 2 || len(a.Countries) >= 2 {
			rep.Campaigns++
		}
	}
	s.mu.Unlock()
	return rep, nil
}
