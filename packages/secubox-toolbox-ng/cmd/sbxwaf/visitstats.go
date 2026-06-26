// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// SecuBox-Deb :: sbxwaf :: non-attacker visit statistics (#747)
//
// The WAF sees ALL inbound external traffic, so it is the right place to produce
// real "who actually visited" statistics — NOT just the threats already captured
// in the threat log. This aggregates LEGITIMATE (non-blocked) requests in memory
// (lock-guarded, capped maps) and flushes an aggregate JSON snapshot periodically
// (the double-caching pattern: hot path only touches counters, never disk). The
// WAF API reads the snapshot, geo-maps the top client IPs (it already ships a
// GeoIP reader), and serves the dashboard's Visits panel.
//
// Privacy: the snapshot is AGGREGATE counters (client-type / OS / per-vhost /
// status buckets) plus the top-N busiest client IPs for geo-mapping — no
// per-request PII, no full request log. UA is classified into coarse buckets, not
// stored verbatim. Pure standard library.
package main

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// statusRecorder wraps an http.ResponseWriter to remember the status code that
// was written, so the handler can tally the visit's outcome (2xx/3xx vs the
// blocked 403/421 it filters out) after the proxy has served the response. It
// forwards Flush so progressive responses still stream.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// visitMapCap bounds each per-key map so a flood of distinct vhosts/IPs cannot
// grow memory without bound. NEW keys past the cap are dropped (existing keys
// keep counting) until the next flush clears the buffer.
const visitMapCap = 5000

// visitFlushInterval is how often the in-memory counters are snapshotted to disk.
const visitFlushInterval = 30 * time.Second

// VisitStats aggregates legitimate (non-blocked) request counts. All maps are
// guarded by mu; the hot path takes mu only for the O(1) increment.
type VisitStats struct {
	mu           sync.Mutex
	total        int64
	byVhost      map[string]int64
	byClientType map[string]int64 // browser | mobile-app | bot | crawler | other
	byOS         map[string]int64 // Windows | macOS | Linux | Android | iOS | other
	byStatus     map[string]int64 // 2xx | 3xx | 4xx | 5xx
	topIP        map[string]int64 // busiest client IPs (geo-mapped by the API)
	statsPath    string
}

// NewVisitStats builds the aggregator and starts the background flusher writing
// to statsPath every visitFlushInterval. statsPath == "" disables persistence
// (the aggregator still counts, useful for tests).
func NewVisitStats(statsPath string) *VisitStats {
	v := &VisitStats{
		byVhost:      map[string]int64{},
		byClientType: map[string]int64{},
		byOS:         map[string]int64{},
		byStatus:     map[string]int64{},
		topIP:        map[string]int64{},
		statsPath:    statsPath,
	}
	if statsPath != "" {
		go v.runFlusher()
	}
	return v
}

// Record tallies one legitimate visit. The caller filters out blocked/misdirected
// responses (403/421) before calling — this counts real traffic to real backends.
func (v *VisitStats) Record(vhost, ua, ip string, status int) {
	if v == nil {
		return
	}
	ct, os := classifyUA(ua)
	v.mu.Lock()
	defer v.mu.Unlock()
	v.total++
	bump(v.byClientType, ct)              // small fixed key-set — no cap needed
	bump(v.byOS, os)                      // small fixed key-set
	bump(v.byStatus, statusBucket(status)) // 4 keys
	capBump(v.byVhost, vhost)
	if ip != "" {
		capBump(v.topIP, ip)
	}
}

// Total returns the current cumulative visit count (lock-guarded) for the
// WAF-injected health widget.
func (v *VisitStats) Total() int64 {
	if v == nil {
		return 0
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.total
}

// bump increments an unbounded-but-tiny key set (client type / OS / status).
func bump(m map[string]int64, k string) {
	if k == "" {
		k = "other"
	}
	m[k]++
}

// capBump increments k, adding a NEW key only while the map is under visitMapCap.
func capBump(m map[string]int64, k string) {
	if k == "" {
		return
	}
	if _, ok := m[k]; ok {
		m[k]++
	} else if len(m) < visitMapCap {
		m[k] = 1
	}
}

// statusBucket coarsens an HTTP status code into a 2xx/3xx/4xx/5xx bucket.
func statusBucket(code int) string {
	switch {
	case code >= 200 && code < 300:
		return "2xx"
	case code >= 300 && code < 400:
		return "3xx"
	case code >= 400 && code < 500:
		return "4xx"
	case code >= 500:
		return "5xx"
	default:
		return "other"
	}
}

// classifyUA maps a raw User-Agent string into a coarse (clientType, os) pair.
// Order matters: bots/crawlers are checked before browsers because crawler UAs
// also carry "Mozilla". Heuristic, not exhaustive — good enough for a dashboard
// breakdown, and never stores the raw UA.
func classifyUA(ua string) (clientType, os string) {
	l := strings.ToLower(ua)
	if l == "" {
		return "other", "other"
	}

	// ── OS ──────────────────────────────────────────────────────────────────
	switch {
	case strings.Contains(l, "android"):
		os = "Android"
	case strings.Contains(l, "iphone"), strings.Contains(l, "ipad"), strings.Contains(l, "ios "):
		os = "iOS"
	case strings.Contains(l, "windows"):
		os = "Windows"
	case strings.Contains(l, "mac os x"), strings.Contains(l, "macintosh"):
		os = "macOS"
	case strings.Contains(l, "linux"), strings.Contains(l, "x11"):
		os = "Linux"
	default:
		os = "other"
	}

	// ── client type ─────────────────────────────────────────────────────────
	switch {
	case strings.Contains(l, "bot"), strings.Contains(l, "spider"),
		strings.Contains(l, "slurp"), strings.Contains(l, "crawl"):
		clientType = "crawler"
	case strings.Contains(l, "curl"), strings.Contains(l, "wget"),
		strings.Contains(l, "python"), strings.Contains(l, "go-http"),
		strings.Contains(l, "okhttp"), strings.Contains(l, "java/"),
		strings.Contains(l, "libwww"), strings.Contains(l, "scanner"):
		clientType = "bot"
	case (os == "Android" || os == "iOS") &&
		!strings.Contains(l, "mobile safari") && !strings.Contains(l, "version/"):
		// A mobile OS UA without a browser marker → native app.
		clientType = "mobile-app"
	case strings.Contains(l, "mozilla"):
		clientType = "browser"
	default:
		clientType = "other"
	}
	return clientType, os
}

// visitSnapshot is the on-disk JSON shape the WAF API reads.
type visitSnapshot struct {
	Total        int64            `json:"total"`
	ByVhost      map[string]int64 `json:"by_vhost"`
	ByClientType map[string]int64 `json:"by_client_type"`
	ByOS         map[string]int64 `json:"by_os"`
	ByStatus     map[string]int64 `json:"by_status"`
	TopIP        map[string]int64 `json:"top_ips"`
	UpdatedUnix  int64            `json:"updated_unix"`
}

// snapshot copies the counters under the lock. The counters are CUMULATIVE (not
// cleared) so the dashboard shows running totals since process start; the flusher
// overwrites the file each tick with the latest cumulative state.
func (v *VisitStats) snapshot(nowUnix int64) visitSnapshot {
	v.mu.Lock()
	defer v.mu.Unlock()
	return visitSnapshot{
		Total:        v.total,
		ByVhost:      copyTopN(v.byVhost, 50),
		ByClientType: copyMap(v.byClientType),
		ByOS:         copyMap(v.byOS),
		ByStatus:     copyMap(v.byStatus),
		TopIP:        copyTopN(v.topIP, 50),
		UpdatedUnix:  nowUnix,
	}
}

func copyMap(m map[string]int64) map[string]int64 {
	out := make(map[string]int64, len(m))
	for k, n := range m {
		out[k] = n
	}
	return out
}

// copyTopN returns the n highest-count entries of m (keeps the file small even
// when the in-memory map holds thousands of vhosts/IPs).
func copyTopN(m map[string]int64, n int) map[string]int64 {
	if len(m) <= n {
		return copyMap(m)
	}
	type kv struct {
		k string
		v int64
	}
	all := make([]kv, 0, len(m))
	for k, v := range m {
		all = append(all, kv{k, v})
	}
	// partial selection of the top n by count (simple insertion into a bounded slice)
	top := make([]kv, 0, n)
	for _, e := range all {
		if len(top) < n {
			top = append(top, e)
			continue
		}
		// find the current minimum in top and replace if e is larger
		minI := 0
		for i := 1; i < len(top); i++ {
			if top[i].v < top[minI].v {
				minI = i
			}
		}
		if e.v > top[minI].v {
			top[minI] = e
		}
	}
	out := make(map[string]int64, n)
	for _, e := range top {
		out[e.k] = e.v
	}
	return out
}

// writeSnapshot atomically writes the snapshot JSON to statsPath (temp + rename)
// so the API never reads a half-written file. Best-effort: errors are swallowed.
func (v *VisitStats) writeSnapshot(nowUnix int64) {
	if v.statsPath == "" {
		return
	}
	snap := v.snapshot(nowUnix)
	buf, err := json.Marshal(snap)
	if err != nil {
		return
	}
	tmp := v.statsPath + ".tmp"
	if err := os.WriteFile(tmp, buf, 0o640); err != nil {
		return
	}
	_ = os.Rename(tmp, v.statsPath)
}

// runFlusher overwrites the stats file every visitFlushInterval for the process
// lifetime. Started once from NewVisitStats.
func (v *VisitStats) runFlusher() {
	t := time.NewTicker(visitFlushInterval)
	defer t.Stop()
	for range t.C {
		v.writeSnapshot(time.Now().Unix())
	}
}
