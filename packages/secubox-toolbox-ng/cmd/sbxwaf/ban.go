// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: sbxwaf :: ban — sliding-window graduated ban state
//
// Mirrors the Python BAN_THRESHOLD=3 / BAN_WINDOW=300s semantics from
// packages/secubox-mitmproxy/addons/secubox_waf.py.
//
// Design notes:
//   - Window:    300 s (default, matches Python BAN_WINDOW)
//   - Threshold: 3 hits within the window triggers a ban (matches BAN_THRESHOLD)
//   - Map cap:   100 000 unique IPs. Once reached, new IPs are silently dropped
//     (not recorded, not banned). This bounds memory under a flood: at 8 bytes
//     per int64 timestamp × ~10 hits × 100k IPs ≈ 8 MB worst-case, well below
//     any realistic RAM budget. The cap is intentionally generous; operator can
//     tune via NewBan if needed in the future.
//   - Pruning:   Per-call, only for the affected IP. No background goroutine;
//     avoids timer complexity for Task 3.1 scope.
//   - Concurrency: single sync.Mutex guards the whole map. A sharded approach
//     can be added later if contention shows up in profiling.

package main

import (
	"sync"
	"time"
)

const banMapCap = 100_000

// Ban holds the sliding-window threat state for all client IPs.
type Ban struct {
	mu        sync.Mutex
	window    int64 // window size in seconds
	threshold int
	hits      map[string][]int64 // IP → slice of Unix timestamps of threat hits
}

// NewBan creates a new Ban tracker.
//
//	window    — size of the sliding time window (e.g. 300*time.Second)
//	threshold — number of hits within the window that triggers a ban
func NewBan(window time.Duration, threshold int) *Ban {
	return &Ban{
		window:    int64(window.Seconds()),
		threshold: threshold,
		hits:      make(map[string][]int64),
	}
}

// Record records one threat hit for ip at time nowUnix (Unix seconds).
// It prunes hits older than nowUnix-window BEFORE counting, then appends.
// Returns:
//
//	count  — number of hits within the window after this one (≥ 1)
//	banned — true when count >= threshold
//
// New IPs are silently ignored (not recorded) once the map reaches banMapCap
// to bound memory under a SYN/scan flood. In that case count=0, banned=false.
func (b *Ban) Record(ip string, nowUnix int64) (count int, banned bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	cutoff := nowUnix - b.window

	ts, exists := b.hits[ip]
	if !exists {
		// Guard: enforce map cap against IP-flood amplification.
		if len(b.hits) >= banMapCap {
			return 0, false
		}
	}

	// Prune timestamps outside the window.
	pruned := ts[:0]
	for _, t := range ts {
		if t > cutoff {
			pruned = append(pruned, t)
		}
	}

	// Append this hit.
	pruned = append(pruned, nowUnix)
	b.hits[ip] = pruned

	count = len(pruned)
	banned = count >= b.threshold
	return count, banned
}

// Count reports the number of recorded hits currently stored for ip, without
// pruning or mutating state. It exists so tests (and diagnostics) can assert
// that a code path never called Record for a given IP — a detect-mode match
// must leave this at zero.
func (b *Ban) Count(ip string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.hits[ip])
}
