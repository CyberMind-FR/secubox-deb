// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package sentinel

// C2 auto-learn orchestrator (#823): wraps the Behavioral beacon detector, and
// for each beacon runs the FP gate + corroborating signals + candidate
// lifecycle. A confirmed host joins the learned set (persisted, report-only)
// and re-contact with a learned host yields a botnet_c2 report verdict. All
// report-only.
//
// Window-advance design note: Behavioral.checkBeaconing latches — it fires a
// ClassBotnetC2 "beaconing" verdict at most ONCE per (mac,host) key. Relying
// on repeated Behavioral fires to accumulate C2Cand's c2MinWindows would
// therefore never promote anything (only the very first window would ever be
// recorded). Instead, C2Learner tracks its own per-host "beaconing" state
// (interval + last-recorded-window timestamp) once Behavioral's first fire
// passes the FP gate and carries >=1 corroborating signal, and advances a
// window on its OWN timing: every subsequent flow to that host that arrives
// at least ~meanInterval (floored at c2WindowFloorSec) after the last
// recorded window counts as one more window. Sustained contact then
// accumulates windows across c2MinSpanSec exactly as C2Cand expects, without
// depending on Behavioral firing again.
import (
	"encoding/json"
	"os"
	"strconv"
	"sync"
)

const c2LearnedTTLSec int64 = 30 * 24 * 3600 // 30d; a quiet host ages out

// c2WindowFloorSec bounds how soon after the last recorded window a
// subsequent flow may advance another one. This keeps a degenerate/zero
// parsed interval from causing a window-per-message runaway, while still
// letting a fast beacon (e.g. every few seconds) accumulate windows at a
// sane pace.
const c2WindowFloorSec int64 = 60

// Re-contact throttle bounds: scaled to the learned beacon's own interval
// (never faster than c2RecontactMinThrottleSec, never slower than
// c2RecontactMaxThrottleSec) rather than a single flat cadence. A learned
// host is, by construction, contacted roughly every IntervalS seconds — using
// that as the throttle means at most one report per natural check-in cycle
// (no spam on a fast beacon) while a slow beacon still gets a timely report
// on its very next contact (no waiting a full hour past a 6-minute cycle).
const (
	c2RecontactMinThrottleSec int64 = 60
	c2RecontactMaxThrottleSec int64 = 3600
)

type LearnedC2 struct {
	Host      string   `json:"host"`
	Signals   []string `json:"signals"`
	IntervalS float64  `json:"interval_s"`
	Devices   int      `json:"devices"`
	FirstSeen int64    `json:"first_seen"`
	LastSeen  int64    `json:"last_seen"`
}

type C2Config struct {
	AllowFile   string
	BoxFile     string
	CandFile    string
	LearnedFile string
	BrowserJA4  []string
}

// beaconState is the per-host own-timing tracker used to advance candidate
// windows independently of Behavioral's latched beacon verdict.
type beaconState struct {
	intervalS  float64
	lastWindow int64
}

type C2Learner struct {
	behavioral *Behavioral
	allow      *C2Allow
	signals    *C2Signals
	cand       *C2Cand
	learnedFN  string

	mu       sync.Mutex
	learned  map[string]*LearnedC2
	reported map[string]int64 // host → last re-contact verdict TS (throttle)

	beaconMu  sync.Mutex
	beaconing map[string]*beaconState // host → own-timing window tracker
}

func NewC2Learner(b *Behavioral, cfg C2Config) *C2Learner {
	l := &C2Learner{
		behavioral: b,
		allow:      NewC2Allow(cfg.AllowFile, cfg.BoxFile),
		signals:    NewC2Signals(cfg.BrowserJA4),
		cand:       NewC2Cand(cfg.CandFile),
		learnedFN:  cfg.LearnedFile,
		learned:    make(map[string]*LearnedC2),
		reported:   make(map[string]int64),
		beaconing:  make(map[string]*beaconState),
	}
	l.loadLearned()
	return l
}

// Analyze satisfies the daemon Analyzer interface. It always runs Behavioral,
// updates the rarity estimate, learns from beacons (both the initial
// Behavioral fire and, on its own timing, sustained subsequent contact), and
// re-emits for learned hosts. Never blocks; never auto-blocks.
func (l *C2Learner) Analyze(m MirrorMsg) []*Verdict {
	// rarity reflects ALL traffic, not only beacons.
	l.signals.Observe(m.Meta.Host)

	verdicts := l.behavioral.Analyze(m)

	// learned re-contact → throttled report verdict
	if v := l.recontact(m); v != nil {
		verdicts = append(verdicts, v)
	}

	// The FIRST beacon verdict Behavioral produces for a (mac,host) key
	// starts our own-timing window tracker (and records candidate window 1).
	for _, v := range verdicts {
		if v == nil || v.Class != ClassBotnetC2 || v.Evidence["pattern"] != "beaconing" {
			continue
		}
		l.startBeaconing(m, v)
	}

	// Because Behavioral's beacon verdict latches (fires only once per key),
	// sustained contact afterwards is tracked here: advance a window when
	// enough real time has elapsed since the last one recorded for this
	// host. No-op for hosts never started above (allowlisted / no signal /
	// not yet beaconing).
	l.tickWindow(m)

	return verdicts
}

// startBeaconing runs the FP gate + corroborating-signals check on the FIRST
// beacon verdict for a host and, if it passes both, begins this learner's own
// per-host window tracking and records candidate window 1.
func (l *C2Learner) startBeaconing(m MirrorMsg, beacon *Verdict) {
	host := m.Meta.Host
	if host == "" || l.allow.Allowed(host) {
		return
	}
	fired := l.signals.Fired(m.Meta)
	if !hasStrongSignal(fired) {
		return // periodicity + rarity alone never promotes — need dga / non-browser
	}
	interval := parseIntervalSec(beacon.Evidence["interval_s"])

	l.beaconMu.Lock()
	if _, exists := l.beaconing[host]; !exists && len(l.beaconing) >= c2MaxEntries {
		// Bound l.beaconing the same way C2Cand bounds candidates: evict the
		// oldest-tracked entry (by last recorded window) before inserting a
		// new one. Simple linear scan — the map is small.
		var victim string
		var oldest int64
		first := true
		for h, st := range l.beaconing {
			if first || st.lastWindow < oldest {
				victim, oldest = h, st.lastWindow
				first = false
			}
		}
		if victim != "" {
			delete(l.beaconing, victim)
		}
	}
	l.beaconing[host] = &beaconState{intervalS: interval, lastWindow: m.TS}
	l.beaconMu.Unlock()

	l.recordWindow(host, m.Meta.MacHash, m.TS, interval, fired)
}

// tickWindow advances host's window tracker, on the learner's own timing,
// once at least ~intervalS (floored) has elapsed since the last recorded
// window. It is a no-op for any host not already being tracked (i.e. one
// whose first beacon never passed the FP gate / signal check).
func (l *C2Learner) tickWindow(m MirrorMsg) {
	host := m.Meta.Host
	if host == "" {
		return
	}
	// A learned host is handled by recontact — don't keep re-recording /
	// re-persisting candidate windows for it. Check under mu and release
	// before ever touching beaconMu (sequential, never nested) so lock
	// ordering stays identical to the rest of this file.
	l.mu.Lock()
	_, isLearned := l.learned[host]
	l.mu.Unlock()
	if isLearned {
		return
	}
	l.beaconMu.Lock()
	st, ok := l.beaconing[host]
	if !ok {
		l.beaconMu.Unlock()
		return
	}
	floor := int64(st.intervalS)
	if floor < c2WindowFloorSec {
		floor = c2WindowFloorSec
	}
	elapsed := m.TS - st.lastWindow
	if elapsed < floor {
		l.beaconMu.Unlock()
		return
	}
	// Pace the next check regardless of outcome below, so a host that keeps
	// losing corroboration doesn't get re-evaluated on every single message.
	st.lastWindow = m.TS
	interval := st.intervalS
	l.beaconMu.Unlock()

	fired := l.signals.Fired(m.Meta)
	if !hasStrongSignal(fired) {
		// No STRONG corroboration on THIS contact — do not advance the candidate
		// window. C2Cand unions signals across windows permanently (once fired, a
		// signal name stays), so recording a window on a weak-only ("rare")
		// contact would let a transient rarity (an initial low-hit-count burst
		// that later becomes common) silently carry a common, browser-driven host
		// across c2MinWindows on periodicity+rarity alone — exactly the false
		// positive the strong-signal requirement exists to prevent.
		return
	}
	l.recordWindow(host, m.Meta.MacHash, m.TS, interval, fired)
}

// recordWindow folds one window observation into the candidate store and
// promotes to the learned set on the (fail-safe, latched) first call where
// C2Cand's promotion criteria are met.
func (l *C2Learner) recordWindow(host, mac string, ts int64, intervalS float64, signals []string) {
	promote, cd := l.cand.Record(host, mac, ts, intervalS, signals)
	_ = l.cand.Persist()
	if promote {
		l.promote(cd)
	}
}

func (l *C2Learner) promote(cd C2Candidate) {
	sigs := make([]string, 0, len(cd.Signals))
	for s := range cd.Signals {
		sigs = append(sigs, s)
	}
	l.mu.Lock()
	l.learned[cd.Host] = &LearnedC2{
		Host: cd.Host, Signals: sigs, IntervalS: cd.IntervalS,
		Devices: len(cd.Devices), FirstSeen: cd.FirstSeen, LastSeen: cd.LastSeen,
	}
	// Hard cap: evict the oldest-contacted entry (by LastSeen) if promotion
	// pushed the learned set over budget.
	if len(l.learned) > c2MaxEntries {
		var victim string
		var oldest int64
		first := true
		for h, le := range l.learned {
			if first || le.LastSeen < oldest {
				victim, oldest = h, le.LastSeen
				first = false
			}
		}
		if victim != "" {
			delete(l.learned, victim)
		}
	}
	l.mu.Unlock()

	// A promoted host is covered by recontact from here on — its beacon-
	// window tracker is dead weight. Acquire/release beaconMu separately
	// (never nested inside mu) to preserve the existing lock ordering.
	l.beaconMu.Lock()
	delete(l.beaconing, cd.Host)
	l.beaconMu.Unlock()

	// The promoted host leaves the candidate store too, so it stops showing
	// in both the learned AND candidate WebUI rows.
	l.cand.Remove(cd.Host)

	l.persistLearned()
}

// recontact returns a throttled report-only botnet_c2 verdict when m hits a
// host already in the learned set.
func (l *C2Learner) recontact(m MirrorMsg) *Verdict {
	host := m.Meta.Host
	if host == "" {
		return nil
	}
	l.mu.Lock()
	le, ok := l.learned[host]
	if !ok {
		l.mu.Unlock()
		return nil
	}
	throttle := int64(le.IntervalS)
	if throttle < c2RecontactMinThrottleSec {
		throttle = c2RecontactMinThrottleSec
	}
	if throttle > c2RecontactMaxThrottleSec {
		throttle = c2RecontactMaxThrottleSec
	}
	if m.TS-l.reported[host] < throttle {
		l.mu.Unlock()
		return nil
	}
	l.reported[host] = m.TS
	le.LastSeen = m.TS
	l.mu.Unlock()

	return &Verdict{
		Class:      ClassBotnetC2,
		Severity:   75,
		Confidence: 75,
		Action:     ActionReport, // learned behavioral — NEVER auto-block
		Evidence: map[string]string{
			"pattern": "learned_c2",
			"host":    host,
			"source":  "autolearn",
		},
		MacHash: m.Meta.MacHash,
		TS:      m.TS,
	}
}

func (l *C2Learner) Learned() []LearnedC2 {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]LearnedC2, 0, len(l.learned))
	for _, le := range l.learned {
		out = append(out, *le)
	}
	return out
}

func (l *C2Learner) Candidates() []C2Candidate { return l.cand.Snapshot() }

// Allow adds host to the operator allowlist and removes it from the learned
// set, the candidate store, and this learner's own-timing tracker (the
// "Ignorer" safety valve).
func (l *C2Learner) Allow(host string) error {
	if err := l.allow.Add(host); err != nil {
		return err
	}
	l.allow.Reload()
	l.mu.Lock()
	delete(l.learned, host)
	l.mu.Unlock()
	l.beaconMu.Lock()
	delete(l.beaconing, host)
	l.beaconMu.Unlock()
	l.cand.Remove(host)
	l.persistLearned()
	_ = l.cand.Persist()
	return nil
}

func (l *C2Learner) loadLearned() {
	b, err := os.ReadFile(l.learnedFN)
	if err != nil {
		return
	}
	var list []*LearnedC2
	if json.Unmarshal(b, &list) != nil {
		return
	}
	l.mu.Lock()
	for _, le := range list {
		if le != nil && le.Host != "" {
			l.learned[le.Host] = le
		}
	}
	l.mu.Unlock()
}

// persistLearned atomically writes the learned set, dropping TTL-expired
// hosts. TTL is evaluated against the newest LastSeen in the set
// (monotonic-free — the daemon has no wall clock guarantee across restarts,
// so decay is relative).
func (l *C2Learner) persistLearned() {
	if l.learnedFN == "" {
		return
	}
	l.mu.Lock()
	var newest int64
	for _, le := range l.learned {
		if le.LastSeen > newest {
			newest = le.LastSeen
		}
	}
	list := make([]*LearnedC2, 0, len(l.learned))
	for h, le := range l.learned {
		if newest-le.LastSeen > c2LearnedTTLSec {
			delete(l.learned, h)
			delete(l.reported, h) // drop the paired throttle entry too
			continue
		}
		list = append(list, le)
	}
	l.mu.Unlock()
	if b, err := json.Marshal(list); err == nil {
		_ = atomicWriteFile(l.learnedFN, b, 0o640)
	}
}

// parseIntervalSec is a fail-safe best-effort parse of Behavioral's
// "interval_s" evidence string; 0 on any parse failure (non-fatal — a zero
// interval just falls back to the c2WindowFloorSec floor in tickWindow).
func parseIntervalSec(s string) float64 {
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0
	}
	return v
}
