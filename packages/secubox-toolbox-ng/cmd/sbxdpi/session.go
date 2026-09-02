// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// SecuBox-Deb :: toolbox-ng :: sbxdpi :: corrélation multi-flux → SESSIONS (L3)
//
// « Un flow ne doit plus être considéré indépendamment. » On regroupe les flux
// SORTANTS d'un même terminal (IP source locale) partageant la même famille
// d'usage dans une fenêtre temporelle → une SESSION d'usage (youtube.com +
// googlevideo + QUIC dans les mêmes minutes = « Session YouTube »), pas une
// liste de sockets. Classification per-flow via l'enrichisseur (host+nDPI+port).
// Modèle inspiré de sbxwaf/profiler.go (clé stable → agrégat temporel).
package main

import (
	"sort"
	"sync"
)

const (
	sessWindow    = int64(300) // 5 min : même device+usage dans la fenêtre = 1 session
	sessMaxOpen   = 2000
	sessMaxClosed = 500
	sessHostsCap  = 6
	sessOutCap    = 200
)

// usageSession : une activité corrélée, pas un socket.
type usageSession struct {
	Device     string   `json:"device"` // IP source locale (attribution device légère)
	Usage      string   `json:"usage"`
	App        string   `json:"application,omitempty"`
	Infra      string   `json:"infra,omitempty"`
	Start      int64    `json:"start"`
	Last       int64    `json:"last"`
	Flows      uint64   `json:"flows"`
	Bytes      uint64   `json:"bytes"`
	Hosts      []string `json:"hosts"`
	Confidence int      `json:"confidence"`
}

type sessionTracker struct {
	mu     sync.Mutex
	enr    *enricher
	open   map[string]*usageSession // clé = device|usage
	closed []usageSession
}

func newSessionTracker(enr *enricher) *sessionTracker {
	return &sessionTracker{enr: enr, open: map[string]*usageSession{}}
}

func addHost(u *usageSession, h string) {
	if h == "" {
		return
	}
	for _, x := range u.Hosts {
		if x == h {
			return
		}
	}
	if len(u.Hosts) < sessHostsCap {
		u.Hosts = append(u.Hosts, h)
	}
}

// close déplace une session vers l'anneau fermé (borné). Caller tient le lock.
func (s *sessionTracker) close(u *usageSession) {
	s.closed = append(s.closed, *u)
	if len(s.closed) > sessMaxClosed {
		s.closed = s.closed[len(s.closed)-sessMaxClosed:]
	}
}

// observe attribue un flux (au flow-end, octets connus) à une session. On ne
// suit que le SORTANT du parc et les flux classifiables.
func (s *sessionTracker) observe(ev *dpiEvent, now int64) {
	if s == nil || s.enr == nil || !ev.outbound() {
		return
	}
	en := s.enr.Classify(ev.host(), ev.app(), ev.master(), ev.DstPort)
	if en.Confidence == 0 || en.Usage == "" {
		return
	}
	key := ev.SrcIP + "|" + en.Usage
	s.mu.Lock()
	defer s.mu.Unlock()
	cur := s.open[key]
	if cur != nil && now-cur.Last <= sessWindow {
		cur.Last = now
		cur.Flows++
		cur.Bytes += ev.bytes()
		if en.Confidence > cur.Confidence {
			cur.Confidence = en.Confidence
		}
		if en.Application != "" && cur.App == "" {
			cur.App = en.Application
		}
		addHost(cur, ev.host())
		return
	}
	if cur != nil {
		s.close(cur) // fenêtre expirée → on clôt et on rouvre
	}
	if len(s.open) >= sessMaxOpen {
		return
	}
	ns := &usageSession{
		Device: ev.SrcIP, Usage: en.Usage, App: en.Application, Infra: en.Infra,
		Start: now, Last: now, Flows: 1, Bytes: ev.bytes(), Confidence: en.Confidence,
	}
	addHost(ns, ev.host())
	s.open[key] = ns
}

// snapshot : sessions (ouvertes récentes + fermées), triées par activité récente.
func (s *sessionTracker) snapshot(now int64) []usageSession {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, u := range s.open {
		if now-u.Last > sessWindow {
			s.close(u)
			delete(s.open, k)
		}
	}
	out := make([]usageSession, 0, len(s.open)+len(s.closed))
	for _, u := range s.open {
		out = append(out, *u)
	}
	out = append(out, s.closed...)
	sort.Slice(out, func(i, j int) bool { return out[i].Last > out[j].Last })
	if len(out) > sessOutCap {
		out = out[:sessOutCap]
	}
	return out
}
