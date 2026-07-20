// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// SecuBox-Deb :: toolbox-ng :: sbxwaf — per-vhost signal emitter (#896 Task 15)
//
// SecuBox scale-to-zero: the profiles-side sleeper (secubox-profiles,
// api/sleeper.py) decides whether an on-demand public vhost is idle from two
// per-vhost numbers — "how long since its last request" and "how many
// requests are in flight right now". Nothing in sbxwaf tracked either: the
// #747 visit-stats aggregator (visitstats.go) only keeps cumulative COUNTS,
// no timestamps, no in-flight tracking. This file adds that missing signal.
//
// Shape mirrors VisitStats deliberately (lock-guarded maps + a background
// flusher doing an atomic temp-write + rename — see writeSnapshot in
// visitstats.go): the hot path only ever touches an in-memory counter, disk
// I/O happens on a timer, never on the request path.
//
// Two differences from VisitStats, both intentional:
//   - The flush interval is 5s, not 30s. The sleeper (api/sleeper_daemon.py)
//     polls every ~30s by default; a snapshot that is stale by up to 30s
//     itself would double the effective latency of the idle decision. 5s
//     keeps that skew small relative to the sleeper's own poll interval.
//   - No top-N cap on the vhost map. VisitStats caps at visitMapCap because
//     it tracks EVERY vhost the WAF ever sees (thousands of public sites);
//     dropping the least-busy is fine because the panel only shows a
//     top-N chart. Here the sleeper needs EVERY on-demand vhost's signal —
//     dropping one under memory pressure would silently disable auto-sleep
//     for that vhost. A cap is unnecessary anyway: recording is gated to
//     on-demand vhosts only (see the Begin/End call site in main.go), and
//     that set is operator-curated and expected to stay small (it is the
//     handful of rarely-used services worth scaling to zero, not the whole
//     public vhost fleet).
package main

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

// vhostSignalsFlushInterval is how often the in-memory Begin/End state is
// snapshotted to disk. Shorter than visitFlushInterval (30s) — see the
// package doc comment above for why.
const vhostSignalsFlushInterval = 5 * time.Second

// VhostSignals tracks, per on-demand vhost, the wall-clock time of its most
// recent request (lastSeen) and how many requests are currently in flight
// (active). All maps are guarded by mu; Begin/End are the only hot-path
// operations and take the lock only for an O(1) map update.
type VhostSignals struct {
	mu       sync.Mutex
	lastSeen map[string]int64 // vhost -> unix seconds of the most recent Begin
	active   map[string]int64 // vhost -> count of requests currently in flight
	path     string
}

// NewVhostSignals builds the aggregator and starts the background flusher
// writing to path every vhostSignalsFlushInterval. path == "" disables
// persistence (the aggregator still counts, useful for tests).
func NewVhostSignals(path string) *VhostSignals {
	v := &VhostSignals{
		lastSeen: map[string]int64{},
		active:   map[string]int64{},
		path:     path,
	}
	if path != "" {
		go v.runFlusher()
	}
	return v
}

// Begin records the start of a request to vhost: bumps lastSeen to now and
// increments the in-flight counter. Pair with a deferred End(vhost) at the
// call site so a panic mid-request still decrements (see main.go handler()).
func (v *VhostSignals) Begin(vhost string) {
	if v == nil {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.lastSeen[vhost] = time.Now().Unix()
	v.active[vhost]++
}

// End records the end of a request to vhost: decrements the in-flight
// counter, pruning the map entry once it reaches zero (so an idle vhost's
// active-conns snapshot is simply "key absent" == 0, never a stale zero
// left lying around). lastSeen is NEVER touched here — the idle-age math on
// the profiles side needs the timestamp of the LAST request to survive long
// after active_conns has dropped back to zero.
func (v *VhostSignals) End(vhost string) {
	if v == nil {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.active[vhost]--
	if v.active[vhost] <= 0 {
		delete(v.active, vhost)
	}
}

// vhostSignalEntry is the per-vhost on-disk JSON shape the profiles-side
// sleeper reads (api/front_signals.py::vhost_signals). last_request_ts is a
// UNIX WALL-CLOCK timestamp (time.Now().Unix()) — the Python reader MUST
// compute its age against a wall-clock `now` (time.time), not a monotonic
// one, or the age math is meaningless.
type vhostSignalEntry struct {
	LastRequestTS int64 `json:"last_request_ts"`
	ActiveConns   int64 `json:"active_conns"`
}

// snapshot copies the counters under the lock into the on-disk shape.
func (v *VhostSignals) snapshot() map[string]vhostSignalEntry {
	v.mu.Lock()
	defer v.mu.Unlock()
	out := make(map[string]vhostSignalEntry, len(v.lastSeen))
	for vhost, ts := range v.lastSeen {
		out[vhost] = vhostSignalEntry{
			LastRequestTS: ts,
			ActiveConns:   v.active[vhost], // 0 (map default) when no key — pruned by End
		}
	}
	return out
}

// writeSnapshot atomically writes the snapshot JSON to path (temp + rename)
// so the reader never sees a half-written file. Best-effort: errors are
// swallowed, mirroring VisitStats.writeSnapshot.
func (v *VhostSignals) writeSnapshot() {
	if v.path == "" {
		return
	}
	snap := v.snapshot()
	buf, err := json.Marshal(snap)
	if err != nil {
		return
	}
	tmp := v.path + ".tmp"
	if err := os.WriteFile(tmp, buf, 0o640); err != nil {
		return
	}
	_ = os.Rename(tmp, v.path)
}

// runFlusher overwrites the signals file every vhostSignalsFlushInterval for
// the process lifetime. Started once from NewVhostSignals.
func (v *VhostSignals) runFlusher() {
	t := time.NewTicker(vhostSignalsFlushInterval)
	defer t.Stop()
	for range t.C {
		v.writeSnapshot()
	}
}
