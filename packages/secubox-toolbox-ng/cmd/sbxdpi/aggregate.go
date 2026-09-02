// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// SecuBox-Deb :: toolbox-ng :: sbxdpi :: in-memory stats aggregator
//
// Mirrors sbxwaf/visitstats.go: a mutex-guarded set of capped counter maps on
// the hot path (O(1) increments under a short lock), a periodic atomic
// snapshot flush (temp file + rename so a reader never sees a half-written
// file), and bounded memory (each map capped so a flood of unique keys cannot
// grow the daemon without limit).
package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// mapCap bounds every counter map. Past the cap, new keys are dropped (existing
// keys keep counting) — the top talkers/protocols are what the dashboard shows,
// and the long tail is noise.
const mapCap = 5000

// counter holds the two metrics we track per key.
type counter struct {
	Flows uint64
	Bytes uint64
}

type aggregator struct {
	mu         sync.Mutex
	protocols  map[string]*counter // master proto: "TLS"
	apps       map[string]*counter // full proto: "TLS.Google"
	categories map[string]*counter // "Web", "Cloud"
	talkers    map[string]*counter // "src->dst"
	hosts      map[string]*counter // SNI/DNS hostname (pivot des règles usage/CDN)
	risks      map[string]*riskCounter
	firstParty map[string]bool // apps seen as first-party (our own vhosts)

	totalFlows uint64
	totalBytes uint64
	filtered   uint64

	connected atomic.Bool
}

type riskCounter struct {
	Count    uint64
	Severity string
}

func newAggregator() *aggregator {
	return &aggregator{
		protocols:  map[string]*counter{},
		apps:       map[string]*counter{},
		categories: map[string]*counter{},
		talkers:    map[string]*counter{},
		hosts:      map[string]*counter{},
		risks:      map[string]*riskCounter{},
		firstParty: map[string]bool{},
	}
}

func (a *aggregator) setConnected(v bool) { a.connected.Store(v) }

// bump increments a capped map's counter, creating the key only if the map is
// under cap. Caller holds a.mu.
func bump(m map[string]*counter, key string, flows, bytes uint64) {
	c := m[key]
	if c == nil {
		if len(m) >= mapCap {
			return
		}
		c = &counter{}
		m[key] = c
	}
	c.Flows += flows
	c.Bytes += bytes
}

func (a *aggregator) recordFlow(ev *dpiEvent, firstParty bool) {
	a.mu.Lock()
	a.totalFlows++
	bump(a.protocols, ev.master(), 1, 0)
	bump(a.apps, ev.app(), 1, 0)
	bump(a.categories, ev.category(), 1, 0)
	bump(a.talkers, ev.SrcIP+" → "+ev.DstIP, 1, 0)
	if h := ev.host(); h != "" {
		bump(a.hosts, h, 1, 0)
	}
	if firstParty {
		if len(a.firstParty) < mapCap {
			a.firstParty[ev.app()] = true
		}
	}
	a.mu.Unlock()
}

func (a *aggregator) recordBytes(ev *dpiEvent) {
	b := ev.bytes()
	if b == 0 {
		return
	}
	a.mu.Lock()
	a.totalBytes += b
	bump(a.protocols, ev.master(), 0, b)
	bump(a.apps, ev.app(), 0, b)
	bump(a.categories, ev.category(), 0, b)
	bump(a.talkers, ev.SrcIP+" → "+ev.DstIP, 0, b)
	if h := ev.host(); h != "" {
		bump(a.hosts, h, 0, b)
	}
	a.mu.Unlock()
}

func (a *aggregator) recordRisks(ev *dpiEvent, filt *filter) {
	if len(ev.NDPI.FlowRisk) == 0 {
		return
	}
	a.mu.Lock()
	for _, r := range ev.NDPI.FlowRisk {
		if r.Risk == "" || filt.riskMuted(r.Risk) {
			continue
		}
		rc := a.risks[r.Risk]
		if rc == nil {
			if len(a.risks) >= mapCap {
				continue
			}
			rc = &riskCounter{}
			a.risks[r.Risk] = rc
		}
		rc.Count++
		if r.Severity != "" {
			rc.Severity = r.Severity
		}
	}
	a.mu.Unlock()
}

func (a *aggregator) countFiltered() {
	a.mu.Lock()
	a.filtered++
	a.mu.Unlock()
}

// --- snapshot / serialization ---------------------------------------------

// kv is one ranked entry in the API/snapshot output.
type kv struct {
	Name  string  `json:"name"`
	Flows uint64  `json:"flows"`
	Bytes uint64  `json:"bytes"`
	Pct   float64 `json:"pct"` // share of totalBytes (or totalFlows if no bytes)
}

type riskKV struct {
	Name     string `json:"name"`
	Count    uint64 `json:"count"`
	Severity string `json:"severity"`
}

// snapshot is the full on-disk / API-root document.
type snapshot struct {
	UpdatedAt   int64    `json:"updated_at"`
	Connected   bool     `json:"connected"`
	TotalFlows  uint64   `json:"total_flows"`
	TotalBytes  uint64   `json:"total_bytes"`
	Filtered    uint64   `json:"filtered"`
	FirstPartyN int      `json:"first_party_apps"`
	Protocols   []kv     `json:"protocols"`
	Apps        []kv     `json:"apps"`
	Categories  []kv     `json:"categories"`
	Talkers     []kv     `json:"talkers"`
	Hosts       []kv     `json:"hosts"` // SNI/DNS destinations (#DPI-sémantique, additif)
	Risks       []riskKV `json:"risks"`
}

// rank sorts a counter map into a bytes-desc (flows-desc tiebreak) slice, with
// each entry's Pct as its share of the total. Caller holds a.mu.
func rank(m map[string]*counter, totalBytes, totalFlows uint64) []kv {
	out := make([]kv, 0, len(m))
	for name, c := range m {
		var pct float64
		if totalBytes > 0 {
			pct = float64(c.Bytes) / float64(totalBytes) * 100
		} else if totalFlows > 0 {
			pct = float64(c.Flows) / float64(totalFlows) * 100
		}
		out = append(out, kv{Name: name, Flows: c.Flows, Bytes: c.Bytes, Pct: pct})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Bytes != out[j].Bytes {
			return out[i].Bytes > out[j].Bytes
		}
		return out[i].Flows > out[j].Flows
	})
	return out
}

// snapshot builds a consistent document under one lock hold.
func (a *aggregator) snapshot() snapshot {
	a.mu.Lock()
	defer a.mu.Unlock()
	tb, tf := a.totalBytes, a.totalFlows
	risks := make([]riskKV, 0, len(a.risks))
	for name, r := range a.risks {
		risks = append(risks, riskKV{Name: name, Count: r.Count, Severity: r.Severity})
	}
	sort.Slice(risks, func(i, j int) bool { return risks[i].Count > risks[j].Count })
	return snapshot{
		UpdatedAt:   time.Now().Unix(),
		Connected:   a.connected.Load(),
		TotalFlows:  tf,
		TotalBytes:  tb,
		Filtered:    a.filtered,
		FirstPartyN: len(a.firstParty),
		Protocols:   rank(a.protocols, tb, tf),
		Apps:        rank(a.apps, tb, tf),
		Categories:  rank(a.categories, tb, tf),
		Talkers:     rank(a.talkers, tb, tf),
		Hosts:       rank(a.hosts, tb, tf),
		Risks:       risks,
	}
}

// writeSnapshot atomically rewrites the cache JSON (temp + rename).
func (a *aggregator) writeSnapshot(path string) {
	if path == "" {
		return
	}
	snap := a.snapshot()
	buf, err := json.Marshal(snap)
	if err != nil {
		log.Printf("sbxdpi: snapshot marshal: %v", err)
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		log.Printf("sbxdpi: snapshot mkdir: %v", err)
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, buf, 0o640); err != nil {
		log.Printf("sbxdpi: snapshot write: %v", err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		log.Printf("sbxdpi: snapshot rename: %v", err)
	}
}

// loadSnapshot warm-starts the counters from a prior snapshot so the API is
// non-empty immediately after a restart. Fail-safe: unreadable/corrupt → no-op.
func (a *aggregator) loadSnapshot(path string) {
	if path == "" {
		return
	}
	buf, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var snap snapshot
	if err := json.Unmarshal(buf, &snap); err != nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.totalFlows = snap.TotalFlows
	a.totalBytes = snap.TotalBytes
	a.filtered = snap.Filtered
	restore := func(dst map[string]*counter, src []kv) {
		for _, e := range src {
			if len(dst) >= mapCap {
				break
			}
			dst[e.Name] = &counter{Flows: e.Flows, Bytes: e.Bytes}
		}
	}
	restore(a.protocols, snap.Protocols)
	restore(a.apps, snap.Apps)
	restore(a.categories, snap.Categories)
	restore(a.talkers, snap.Talkers)
	for _, r := range snap.Risks {
		if len(a.risks) >= mapCap {
			break
		}
		a.risks[r.Name] = &riskCounter{Count: r.Count, Severity: r.Severity}
	}
}

// flushLoop rewrites the snapshot every FlushInterval until ctx is cancelled.
func flushLoop(ctx context.Context, cfg Config, agg *aggregator) {
	t := time.NewTicker(cfg.FlushInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			agg.writeSnapshot(cfg.CachePath)
		}
	}
}
