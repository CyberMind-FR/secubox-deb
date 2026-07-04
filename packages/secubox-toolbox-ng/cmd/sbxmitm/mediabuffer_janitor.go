// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: R4 media buffer janitor (#812)
//
// Phase 1 eviction: the actual bytes captured by mediabuffer.go must NEVER
// outlive a short rolling window (design §Global Constraints — "Retention:
// time-only, default 1200s"), with an early LRU valve under a size ceiling for
// when the window alone isn't enough to keep /data bounded. Only the METATAG
// line is meant to survive forever (or until the DPI module/operator prunes
// the log) — the bytes are removed and the record is flipped in place (via an
// append, since the log is append-only) to expired:true + buffer_ref:null.
//
// CONCURRENCY / IDEMPOTENCY: sbxmitm runs as 4 concurrent worker processes
// (ref project memory: "R3 mitm is Go sbxmitm (ng-worker@1..4)"), and each one
// starts its own RunJanitor — there is no single leader/lock. SweepOnce is
// therefore written to be safe when run concurrently, from multiple processes,
// against the SAME buffer root:
//   - os.RemoveAll on an already-removed session dir is a no-op (no error
//     surfaced, nothing to swallow).
//   - Flipping an already-expired record is skipped (this process's in-memory
//     view already sees Expired:true after reading the log) — but even if two
//     processes race and BOTH append a flip line for the same id in the same
//     sweep window, that is harmless: the log is append-only and every reader
//     (Python's read_records, this file's own readMetatags) dedups by id with
//     last-line-wins, so a duplicate flip line just gets read as the same
//     expired:true/buffer_ref:null state.
//   - Two processes racing to RemoveAll the same session dir is safe for the
//     same reason (RemoveAll is idempotent); worst case one process's
//     RemoveAll finds nothing to remove.
//
// Pure standard library.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// mediaBufferJanitorTailMaxBytes bounds how much of media-buffer.jsonl the
// janitor reads per sweep. Mirrors common/secubox_core/media_catch.py's
// bounded tail-read convention: fail-empty on read errors, drop a possibly
// partial first line after truncating to the tail window. The log only grows
// by a couple of lines per captured object, so a generous window comfortably
// covers the live retention/size-ceiling working set without needing to load
// an unbounded file.
const mediaBufferJanitorTailMaxBytes = 8 << 20 // 8 MiB

// defaultJanitorTick is RunJanitor's real-world sweep period.
const defaultJanitorTick = 30 * time.Second

// readMetatags parses every line of the metatag log, deduping by "id" with
// LAST LINE WINS (mirrors the Python reader and honours a prior eviction
// flip: a later expired:true line always overrides an earlier live one).
// Fail-empty: a missing/unreadable log returns an empty (non-nil) map rather
// than an error — a media buffer must never affect anything outside itself.
func (b *MediaBuffer) readMetatags() map[string]mediaBufferRecord {
	out := make(map[string]mediaBufferRecord)
	data, err := os.ReadFile(b.metatagPath())
	if err != nil {
		return out
	}
	if int64(len(data)) > mediaBufferJanitorTailMaxBytes {
		data = data[int64(len(data))-mediaBufferJanitorTailMaxBytes:]
		// The tail cut may have landed mid-line: drop that partial first line.
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			data = data[i+1:]
		} else {
			data = nil
		}
	}
	for _, line := range bytes.Split(data, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var rec mediaBufferRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			continue // corrupt/partial line: skip, never let it abort the sweep.
		}
		if rec.ID == "" {
			continue
		}
		out[rec.ID] = rec // last line wins.
	}
	return out
}

// dirTotalBytes sums the size of every regular file under root (recursively),
// EXCLUDING the metatag log itself (media-buffer.jsonl at the root). The size
// ceiling exists to bound the actual buffered MEDIA bytes on /data; the log is
// append-only and only ever grows (every eviction appends another flip line),
// so counting it here would make the ceiling partly self-defeating — an
// eviction can never shrink it, and for a small enough ceiling the log's own
// growth could out-pace the few bytes an eviction reclaims. At realistic scale
// (GiB ceiling vs. a log of a few hundred bytes per capture) this is a
// rounding error either way; excluding it just keeps the ceiling's meaning
// exact. Best-effort: a walk error on any entry is swallowed and that entry
// simply doesn't count — the janitor must never fail loudly.
func dirTotalBytes(root string) int64 {
	metaPath := filepath.Join(root, mediaBufferLogName)
	var total int64
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d == nil || d.IsDir() {
			return nil
		}
		if p == metaPath {
			return nil
		}
		if info, ierr := d.Info(); ierr == nil {
			total += info.Size()
		}
		return nil
	})
	return total
}

// evict removes a session's bytes from disk (idempotent — RemoveAll on an
// already-gone dir is a no-op, safe against a racing janitor in another
// worker process) and appends a corrected metatag line for the same id with
// expired:true and buffer_ref:null, otherwise preserving every field of rec
// unchanged. The log is append-only; this "flip" is the mechanism — readers
// (Python + this file's own readMetatags) resolve the true current state by
// taking the LAST line per id.
func (b *MediaBuffer) evict(rec mediaBufferRecord) mediaBufferRecord {
	if rec.SessionID != "" {
		_ = os.RemoveAll(filepath.Join(b.root, rec.SessionID))
	}
	rec.Expired = true
	rec.BufferRef = nil
	b.appendMetatag(rec)
	return rec
}

// SweepOnce is the testable eviction unit, run every tick by RunJanitor (and
// directly by tests). It performs two passes against the SAME in-memory read
// of the metatag log (read once per sweep — a fresh read next tick will pick
// up whatever any concurrent worker process appended in the meantime):
//
//  1. Time eviction: every non-expired record whose first_ts + retentionSecs
//     has elapsed is evicted (bytes removed, metatag flipped).
//  2. LRU eviction: if the buffer root is still over sizeCeilBytes afterwards,
//     remaining non-expired records are evicted oldest-first (by first_ts)
//     until the root is back under the ceiling — this can trigger even for a
//     record that has NOT yet hit its time retention, when disk pressure
//     demands it.
//
// nil-safe (no-op on a nil MediaBuffer or an empty root — mirrors every other
// method's defensiveness in mediabuffer.go).
func (b *MediaBuffer) SweepOnce(now int64) {
	if b == nil || b.root == "" {
		return
	}

	retention := b.retentionSecs
	if retention <= 0 {
		retention = defaultRetentionSecs
	}
	ceil := b.sizeCeilBytes
	if ceil <= 0 {
		ceil = defaultSizeCeilBytes
	}

	records := b.readMetatags()

	// Pass 1 — time-based expiry.
	for id, rec := range records {
		if rec.Expired {
			continue
		}
		if rec.FirstTS > 0 && rec.FirstTS+retention <= now {
			records[id] = b.evict(rec)
		}
	}

	// Pass 2 — LRU eviction under the size ceiling, oldest first_ts first.
	// Skip anything already expired (by pass 1, a prior sweep, or a racing
	// sibling worker process).
	if dirTotalBytes(b.root) <= ceil {
		return
	}
	ids := make([]string, 0, len(records))
	for id, rec := range records {
		if !rec.Expired {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool {
		return records[ids[i]].FirstTS < records[ids[j]].FirstTS
	})
	for _, id := range ids {
		if dirTotalBytes(b.root) <= ceil {
			break
		}
		records[id] = b.evict(records[id])
	}
}

// RunJanitor ticks SweepOnce forever (30s by default; overridable in tests via
// janitorTick) until ctx is cancelled. Intended to be started once per worker
// process as `go mbuf.RunJanitor(ctx)` — see the CONCURRENCY note atop this
// file for why running 4 of these against one buffer root is safe. nil-safe
// and a no-op when the buffer is disabled (nothing to sweep).
func (b *MediaBuffer) RunJanitor(ctx context.Context) {
	if b == nil || !b.enabled {
		return
	}
	period := b.janitorTick
	if period <= 0 {
		period = defaultJanitorTick
	}
	ticker := time.NewTicker(period)
	defer ticker.Stop()
	now := b.nowFn
	if now == nil {
		now = func() int64 { return time.Now().Unix() }
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			b.SweepOnce(now())
		}
	}
}
