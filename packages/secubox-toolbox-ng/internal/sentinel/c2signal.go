// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package sentinel

// C2 auto-learn corroborating signals (#823): beaconing alone is not enough to
// learn a host — at least one of these independent signals must also fire, so a
// browser-driven periodic poll (admin dashboard) is not mistaken for a beacon.

import (
	"container/list"
	"strings"
	"sync"
)

const (
	// c2RareMaxHits: a host seen at most this many times across the daemon's
	// window counts as "rare". A real C2 destination stays rare; a CDN/portal
	// the user browses climbs past it quickly.
	c2RareMaxHits = 20
	// c2FreqCap bounds the rarity map (LRU).
	// keep in sync with c2MaxEntries (c2cand.go)
	c2FreqCap = 2000
	// c2DGAMinEntropy: Shannon entropy (bits/char) of the most-significant
	// label above which the domain looks algorithmically generated. Ordinary
	// words sit well below; a random 16-char label sits near log2(distinct).
	c2DGAMinEntropy = 3.6
	// c2DGAMinLen: don't call a short label DGA (too little signal).
	c2DGAMinLen = 10
)

type C2Signals struct {
	browser map[string]bool // known browser JA4/JA3 fingerprints

	mu    sync.Mutex
	freq  map[string]*list.Element // host → LRU element
	order *list.List               // front = most-recent
}

type freqEntry struct {
	host string
	hits int
}

func NewC2Signals(browserJA4 []string) *C2Signals {
	b := make(map[string]bool, len(browserJA4))
	for _, f := range browserJA4 {
		if f = strings.TrimSpace(f); f != "" {
			b[f] = true
		}
	}
	return &C2Signals{browser: b, freq: make(map[string]*list.Element), order: list.New()}
}

// Observe records one contact with host for the rarity estimate. Call on every
// flow (not only beacons) so "rare" reflects true global frequency.
func (s *C2Signals) Observe(host string) {
	if host == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if el, ok := s.freq[host]; ok {
		el.Value.(*freqEntry).hits++
		s.order.MoveToFront(el)
		return
	}
	el := s.order.PushFront(&freqEntry{host: host, hits: 1})
	s.freq[host] = el
	for s.order.Len() > c2FreqCap {
		back := s.order.Back()
		if back == nil {
			break
		}
		delete(s.freq, back.Value.(*freqEntry).host)
		s.order.Remove(back)
	}
}

func (s *C2Signals) hits(host string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if el, ok := s.freq[host]; ok {
		return el.Value.(*freqEntry).hits
	}
	return 0
}

// Fired returns the corroborating signal names present for m. Order-stable,
// deduped. Never panics on missing fields.
func (s *C2Signals) Fired(m FlowMeta) []string {
	var out []string
	if s.hits(m.Host) <= c2RareMaxHits {
		out = append(out, "rare")
	}
	// non-browser: only when a fingerprint is PRESENT and not a known browser.
	fp := m.JA4
	if fp == "" {
		fp = m.JA3
	}
	if fp != "" && !s.browser[fp] {
		out = append(out, "non_browser_ja")
	}
	if isDGA(m.Host) {
		out = append(out, "dga")
	}
	return out
}

// isDGA reports whether host's most-significant label looks algorithmically
// generated (long + high own-entropy). Fail-safe on empty/short input.
func isDGA(host string) bool {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "" {
		return false
	}
	labels := strings.Split(host, ".")
	// pick the longest label (the registrable label is usually the signal)
	cand := ""
	for _, l := range labels {
		if len(l) > len(cand) {
			cand = l
		}
	}
	if len(cand) < c2DGAMinLen {
		return false
	}
	return shannonEntropy(cand) >= c2DGAMinEntropy
}
