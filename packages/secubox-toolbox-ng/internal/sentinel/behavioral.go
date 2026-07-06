// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Behavioral heuristic engine: the async counterpart to the inline IOC gate
// (Task 3) that infers likely-malicious PATTERNS rather than matching known-
// bad indicators. Two heuristics are implemented:
//
//   - beaconing: a single device (MacHash) hitting the same host repeatedly
//     at near-constant intervals — a classic botnet-C2 / check-in fingerprint.
//   - one-time-link: a URL whose last path segment has the shape of a
//     high-entropy, single-use token — a common zero-click / spyware
//     delivery-link pattern (this flags the DELIVERY shape only; it proves
//     nothing about payload or intent).
//
// Per the plan's Global Constraints, heuristic inference is fundamentally
// different from a confirmed known-infra IOC hit: it can be wrong. Every
// verdict this engine emits therefore hardcodes Action: ActionReport — it
// NEVER auto-blocks, no matter how confident the heuristic looks. This is
// enforced twice over in the full pipeline: here (the source), and again by
// the daemon's sentinel.FinalizeAction (ClassBotnetC2/ClassZeroClick — the
// latter is in the heuristicClasses allow-list in scorer.go) — defense in
// depth against a future edit to this file accidentally wiring in a block.
package sentinel

import (
	"container/list"
	"fmt"
	"math"
	"net/url"
	"strings"
	"sync"
)

const (
	// beaconMinHits is the minimum number of requests to the same host from
	// the same device required before beaconing is even considered.
	beaconMinHits = 6

	// beaconJitterCV is the coefficient-of-variation (stddev/mean) ceiling
	// on inter-arrival deltas for them to count as "near-constant". Human-
	// driven browsing intervals are close to exponentially distributed
	// (CV ~= 1); a scheduled check-in beacon sits well under this.
	beaconJitterCV = 0.20

	// maxTrackedKeys bounds the number of distinct (macHash,host) timing
	// states Behavioral keeps in memory. On a long-running daemon watching
	// many devices/hosts this must not grow without bound; the state map is
	// an LRU capped at this size — the least-recently-touched key is
	// evicted to make room for a new one once the cap is reached.
	maxTrackedKeys = 4096

	// oneTimeMinLen is the minimum length of a URL's last path segment to
	// even be considered as a one-time-token shape. Short segments (slugs,
	// short IDs) are far too common to be a useful signal on their own.
	oneTimeMinLen = 16

	// oneTimeMinEntropy is the minimum own-distribution Shannon entropy (in
	// bits/char) a candidate segment must have. A genuinely random token
	// has close to one distinct value per character, so its own-frequency
	// entropy sits near log2(distinct-chars) — well above ordinary words or
	// slugs, which repeat characters heavily.
	oneTimeMinEntropy = 3.5
)

// hostState is the bounded per-(macHash,host) timing state used to detect
// beaconing. times holds at most beaconMinHits recent timestamps (oldest
// dropped as new ones arrive), so each tracked key costs a handful of
// int64s — trivial, fixed memory regardless of how long the daemon runs.
type hostState struct {
	key            string
	times          []int64
	beaconReported bool // true once a beaconing verdict has fired for this key
}

// Behavioral implements the sbx-sentinel Analyzer interface (Analyze). It
// keeps LRU-bounded per-(macHash,host) timing state to detect beaconing, and
// stateless per-message URL-shape inspection to flag one-time-link delivery
// patterns. A zero-value Behavioral is not usable; construct with
// NewBehavioral. All exported methods are safe for concurrent use.
type Behavioral struct {
	mu    sync.Mutex
	order *list.List               // *hostState, front = most recently used
	index map[string]*list.Element // key -> node in order
}

// NewBehavioral returns a ready-to-use Behavioral with empty tracked state.
func NewBehavioral() *Behavioral {
	return &Behavioral{
		order: list.New(),
		index: make(map[string]*list.Element),
	}
}

// Analyze implements the Analyzer interface: it runs both heuristics against
// m and returns every verdict that fired (zero, one, or both). It never
// blocks and never panics on malformed input — missing Host/MacHash/URL
// fields simply make the corresponding heuristic a no-op.
func (b *Behavioral) Analyze(m MirrorMsg) []*Verdict {
	var verdicts []*Verdict

	if v := b.checkOneTimeLink(m); v != nil {
		verdicts = append(verdicts, v)
	}
	if v := b.checkBeaconing(m); v != nil {
		verdicts = append(verdicts, v)
	}
	return verdicts
}

// checkBeaconing updates the LRU timing state for (m.Meta.MacHash,
// m.Meta.Host) and, once at least beaconMinHits timestamps have been seen
// for that key, evaluates whether the inter-arrival deltas are near-constant
// (low jitter). It fires at most once per key (beaconReported latches) so a
// long-lived beacon doesn't re-report on every subsequent hit.
func (b *Behavioral) checkBeaconing(m MirrorMsg) *Verdict {
	host := m.Meta.Host
	mac := m.Meta.MacHash
	if host == "" || mac == "" {
		return nil
	}
	key := mac + "|" + host

	b.mu.Lock()
	defer b.mu.Unlock()

	st := b.touchLocked(key)
	st.times = append(st.times, m.TS)
	if len(st.times) > beaconMinHits {
		// Keep only the most recent beaconMinHits samples: bounded memory
		// per key, and the freshest window for the jitter check.
		st.times = st.times[len(st.times)-beaconMinHits:]
	}

	if st.beaconReported || len(st.times) < beaconMinHits {
		return nil
	}

	cv, meanInterval := deltaStats(st.times)
	if cv > beaconJitterCV {
		return nil
	}

	st.beaconReported = true

	return &Verdict{
		Class:      ClassBotnetC2,
		Severity:   70,
		Confidence: 70,
		Action:     ActionReport, // heuristic inference — NEVER auto-block
		Evidence: map[string]string{
			"pattern":    "beaconing",
			"host":       host,
			"interval_s": fmt.Sprintf("%.1f", meanInterval),
		},
		MacHash: mac,
		TS:      m.TS,
	}
}

// touchLocked returns the hostState for key, creating it if absent, and
// marks it most-recently-used. Callers must hold b.mu. When creating a new
// entry pushes the tracked-key count past maxTrackedKeys, the least-
// recently-used entry is evicted first — this is what keeps Behavioral's
// memory bounded on a long-running daemon regardless of how many distinct
// devices/hosts it observes.
func (b *Behavioral) touchLocked(key string) *hostState {
	if el, ok := b.index[key]; ok {
		b.order.MoveToFront(el)
		return el.Value.(*hostState)
	}

	st := &hostState{key: key}
	el := b.order.PushFront(st)
	b.index[key] = el

	if b.order.Len() > maxTrackedKeys {
		oldest := b.order.Back()
		if oldest != nil {
			evicted := oldest.Value.(*hostState)
			delete(b.index, evicted.key)
			b.order.Remove(oldest)
		}
	}

	return st
}

// deltaStats returns the coefficient of variation (stddev/mean) and the mean
// of the consecutive inter-arrival deltas in times. times must have at least
// two entries; deltaStats does not allocate a separate deltas slice — it
// streams over times directly (two passes: mean, then variance).
func deltaStats(times []int64) (cv float64, mean float64) {
	n := len(times) - 1
	if n <= 0 {
		return math.Inf(1), 0
	}

	var sum float64
	for i := 1; i < len(times); i++ {
		sum += float64(times[i] - times[i-1])
	}
	mean = sum / float64(n)
	if mean <= 0 {
		return math.Inf(1), mean
	}

	var variance float64
	for i := 1; i < len(times); i++ {
		d := float64(times[i]-times[i-1]) - mean
		variance += d * d
	}
	variance /= float64(n)

	return math.Sqrt(variance) / mean, mean
}

// checkOneTimeLink inspects m's URL for a high-entropy one-time-token last
// path segment. This heuristic is stateless (it needs no history), so it is
// evaluated fresh on every message — nothing here touches the LRU timing
// state used by checkBeaconing.
func (b *Behavioral) checkOneTimeLink(m MirrorMsg) *Verdict {
	raw := m.Meta.URL
	if raw == "" {
		return nil
	}

	seg := lastPathSegment(raw)
	if !looksLikeOneTimeToken(seg) {
		return nil
	}

	return &Verdict{
		Class:      ClassZeroClick,
		Severity:   60,
		Confidence: 60,
		Action:     ActionReport, // heuristic delivery signal — NEVER auto-block
		Evidence: map[string]string{
			"pattern": "one_time_link",
			"url":     raw,
		},
		MacHash: m.Meta.MacHash,
		TS:      m.TS,
	}
}

// lastPathSegment returns the final non-empty "/"-delimited segment of
// rawURL's path. It tries a proper URL parse first (so query strings and
// fragments never leak into the segment) and falls back to treating rawURL
// itself as a path if parsing fails, so a malformed value degrades to "no
// match" rather than panicking.
func lastPathSegment(rawURL string) string {
	path := rawURL
	if u, err := url.Parse(rawURL); err == nil {
		path = u.Path
	}
	path = strings.TrimRight(path, "/")
	if idx := strings.LastIndexByte(path, '/'); idx >= 0 {
		path = path[idx+1:]
	}
	return path
}

// looksLikeOneTimeToken reports whether seg has the shape of a random
// single-use token: long enough, a mix of upper-case, lower-case AND digit
// characters (a plain English word or slug practically never has all
// three), and high own-distribution Shannon entropy (a genuinely random
// token rarely repeats characters, so its entropy sits well above ordinary
// text of the same length).
func looksLikeOneTimeToken(seg string) bool {
	if len(seg) < oneTimeMinLen {
		return false
	}

	var hasUpper, hasLower, hasDigit bool
	for _, r := range seg {
		switch {
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= '0' && r <= '9':
			hasDigit = true
		}
	}
	if !hasUpper || !hasLower || !hasDigit {
		return false
	}

	return shannonEntropy(seg) >= oneTimeMinEntropy
}

// shannonEntropy returns the own-distribution Shannon entropy of s, in
// bits/character: -sum(p_i * log2(p_i)) over s's character (rune)
// frequencies.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	freq := make(map[rune]int, len(s))
	var total int
	for _, r := range s {
		freq[r]++
		total++
	}

	n := float64(total)
	var h float64
	for _, c := range freq {
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}
