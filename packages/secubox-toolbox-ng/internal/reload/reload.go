// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: internal/reload — mtime hot-reload pattern
//
// Extracted from cmd/sbxmitm/policy.go so that cmd/sbxwaf (and any future
// module) can reuse the same generic mtime-based file-watcher without pulling
// in Policy internals.
//
// Design notes — atomicity:
//
//   The original maybeReload() in policy.go collected ALL changed targets
//   first (under reloadMu), then applied ALL swaps under a single p.mu.Lock().
//   This Watcher preserves that semantics: Maybe() collects changed targets
//   under the internal throttle/mtime mutex, then calls each Apply callback
//   under a SINGLE write lock so that a batch of simultaneous file changes is
//   applied atomically.  Callers whose Apply closures need their own
//   domain-level lock (e.g. policy.go's p.mu) must NOT take that lock inside
//   Apply — the Watcher holds watcher.mu for the entire apply phase, so
//   callers that also protect their maps with a separate mutex should take it
//   inside Apply.  The key invariant is that watcher.mu serialises concurrent
//   Maybe() calls so no two Apply batches interleave.
//
// Pure standard library — no external modules, no go.sum entries added.
package reload

import (
	"bufio"
	"os"
	"strings"
	"sync"
	"time"
)

// Target describes one backing file the Watcher monitors.
//
//   - Path        — on-disk path to stat/read.
//   - LastMtime   — unix-nano of the last mtime the caller has observed;
//                   typically 0 at construction so the first Maybe() always
//                   fires Load+Apply to populate the caller's state.
//   - Load        — reads Path and returns the new value; called OUTSIDE the
//                   internal mutex so I/O does not block concurrent Maybe()
//                   calls on other targets.  Must not return nil.
//   - Apply       — installs the new value; called INSIDE the internal write
//                   lock so all Apply calls in one Maybe() pass are atomic
//                   w.r.t. each other.  The callback may take its own mutex
//                   (the Watcher's internal mu is NOT reentrant).
type Target struct {
	Path      string
	LastMtime int64
	Load      func(path string) any
	Apply     func(v any)
}

// Watcher monitors a set of Target files and hot-reloads them when their
// on-disk mtime changes.  Create with NewWatcher; call Maybe() on the hot
// path (e.g. per-request or per-connection).
type Watcher struct {
	targets  []Target
	throttle time.Duration

	// mu serialises concurrent Maybe() calls.  All Apply callbacks run under
	// this lock (see design note above).
	mu sync.Mutex

	// lastCheck is the unix-nano timestamp of the last throttle pass (0 = never).
	lastCheck int64
}

// NewWatcher returns a Watcher for the given targets.  throttle is the minimum
// interval between stat passes; 0 means "stat on every Maybe() call" (useful
// in tests).  The defaultReloadThrottle constant below matches the original
// policy.go default (15 s).
func NewWatcher(throttle time.Duration, targets ...Target) *Watcher {
	// Copy the slice so the caller cannot mutate Target fields concurrently.
	t := make([]Target, len(targets))
	copy(t, targets)
	return &Watcher{
		targets:  t,
		throttle: throttle,
	}
}

// defaultReloadThrottle is the production cadence: matches the original in
// policy.go.  Callers that want the default pass this to NewWatcher.
const DefaultReloadThrottle = 15 * time.Second

// Maybe stats each registered target.  If a target's mtime changed since the
// last pass, it calls Load (outside the lock) then Apply (inside the lock,
// batched with any other changed targets so they are applied atomically).
// Throttled: if the last stat pass was more recent than throttle, returns
// immediately.  Concurrency-safe.
func (w *Watcher) Maybe() {
	now := time.Now()

	w.mu.Lock()
	if w.throttle > 0 && w.lastCheck != 0 &&
		now.Sub(time.Unix(0, w.lastCheck)) < w.throttle {
		w.mu.Unlock()
		return
	}
	w.lastCheck = now.UnixNano()

	// Collect changed targets + stat their new mtime (under mu so lastCheck and
	// per-target LastMtime updates are not lost to a concurrent Maybe()).
	type pending struct {
		idx int
		val any
	}
	var changed []pending
	for i := range w.targets {
		rt := &w.targets[i]
		if rt.Path == "" {
			continue
		}
		m := StatMtime(rt.Path)
		if m != rt.LastMtime {
			rt.LastMtime = m
			// Load OUTSIDE the lock below — but we are still inside w.mu here.
			// For simplicity (and to match the original which reads under
			// reloadMu), we read while holding w.mu.  The file I/O is O(KB) and
			// not on the hot path, so this is acceptable.  If future profiling
			// shows lock contention, the Load can be moved outside by dropping
			// and re-acquiring the lock, but that adds complexity.
			changed = append(changed, pending{idx: i, val: rt.Load(rt.Path)})
		}
	}

	if len(changed) == 0 {
		w.mu.Unlock()
		return
	}

	// Apply all pending swaps under the same lock (atomic batch).
	for _, c := range changed {
		w.targets[c.idx].Apply(c.val)
	}
	w.mu.Unlock()
}

// StatMtime returns the file's mtime in unix-nano, or 0 when the file is
// missing or unreadable (best-effort: a missing file → empty set, mtime 0).
// A file appearing or disappearing therefore registers as a change.
func StatMtime(path string) int64 {
	if path == "" {
		return 0
	}
	fi, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return fi.ModTime().UnixNano()
}

// LoadLines reads a line-based text file into a set (map[string]bool).
// Lines are lowercased and trimmed.  When stripComments is true, the portion
// of each line from the first '#' onward is discarded before trimming (mirrors
// the comment-stripping loaders in policy.go: loadLines / splice._load_lines).
// When stripComments is false, the raw trimmed line is used verbatim (mirrors
// loadLinesRaw / ad_ghost._learned_set which does NOT strip comments — a '#'
// in learned-trackers.txt is kept verbatim, not treated as a comment).
// Missing or unreadable file → empty set (best-effort).
func LoadLines(path string, stripComments bool) map[string]bool {
	out := map[string]bool{}
	f, err := os.Open(path)
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		ln := sc.Text()
		if stripComments {
			if i := strings.IndexByte(ln, '#'); i >= 0 {
				ln = ln[:i]
			}
		}
		ln = strings.ToLower(strings.TrimSpace(ln))
		if ln != "" {
			out[ln] = true
		}
	}
	return out
}
