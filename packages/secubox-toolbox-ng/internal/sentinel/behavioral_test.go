// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package sentinel

import (
	"fmt"
	"testing"
)

// beaconMsg builds a MirrorMsg for a request from mac to host at unix time ts.
func beaconMsg(mac, host string, ts int64) MirrorMsg {
	return MirrorMsg{
		Meta: FlowMeta{Host: host, MacHash: mac, URL: "https://" + host + "/"},
		TS:   ts,
	}
}

// TestBehavioralBeaconingDetected feeds beaconMinHits (6) requests from one
// device to one host at exactly-equal 30s intervals (zero jitter) and
// asserts exactly one ClassBotnetC2 report verdict fires — on the message
// that reaches the threshold, not before and not again after.
func TestBehavioralBeaconingDetected(t *testing.T) {
	b := NewBehavioral()

	var all []*Verdict
	base := int64(1_700_000_000)
	for i := 0; i < beaconMinHits; i++ {
		msg := beaconMsg("mac-A", "c2.example", base+int64(i)*30)
		all = append(all, b.Analyze(msg)...)
	}

	var beacons []*Verdict
	for _, v := range all {
		if v.Class == ClassBotnetC2 {
			beacons = append(beacons, v)
		}
	}
	if len(beacons) != 1 {
		t.Fatalf("got %d ClassBotnetC2 verdicts, want exactly 1 (all: %+v)", len(beacons), all)
	}

	v := beacons[0]
	if v.Action != ActionReport {
		t.Fatalf("beaconing verdict Action = %q, want %q (heuristic must never auto-block)", v.Action, ActionReport)
	}
	if v.Evidence["pattern"] != "beaconing" {
		t.Fatalf("Evidence[pattern] = %q, want %q", v.Evidence["pattern"], "beaconing")
	}
	if v.Evidence["host"] != "c2.example" {
		t.Fatalf("Evidence[host] = %q, want %q", v.Evidence["host"], "c2.example")
	}
	if v.MacHash != "mac-A" {
		t.Fatalf("MacHash = %q, want %q", v.MacHash, "mac-A")
	}

	// One more hit at the same cadence must NOT re-fire (latched).
	extra := b.Analyze(beaconMsg("mac-A", "c2.example", base+int64(beaconMinHits)*30))
	for _, v := range extra {
		if v.Class == ClassBotnetC2 {
			t.Fatalf("beaconing re-fired on a 7th hit, want latched (no repeat verdict): %+v", v)
		}
	}
}

// TestBehavioralNoBeaconWhenJittery feeds beaconMinHits requests to the same
// host with highly irregular (human-browsing-like) inter-arrival times and
// asserts no beaconing verdict fires — the heuristic must not flag ordinary
// bursty traffic just because it hit a request-count threshold.
func TestBehavioralNoBeaconWhenJittery(t *testing.T) {
	b := NewBehavioral()
	base := int64(1_700_000_000)
	deltas := []int64{2, 900, 15, 4000, 1, 600}

	var all []*Verdict
	ts := base
	for i := 0; i < beaconMinHits; i++ {
		all = append(all, b.Analyze(beaconMsg("mac-B", "news.example", ts))...)
		ts += deltas[i]
	}

	for _, v := range all {
		if v.Class == ClassBotnetC2 {
			t.Fatalf("unexpected beaconing verdict on jittery traffic: %+v", v)
		}
	}
}

// TestBehavioralOneTimeLinkDetected feeds a single message whose URL's last
// path segment is a long, mixed-case+digit, high-entropy token and asserts
// exactly one ClassZeroClick report verdict fires.
func TestBehavioralOneTimeLinkDetected(t *testing.T) {
	b := NewBehavioral()

	token := "aZ9kQ2xM7vT4rP1nW8fL" // 20 distinct chars: upper+lower+digit, high entropy
	url := "https://deliver.example/dl/" + token
	msg := MirrorMsg{
		Meta: FlowMeta{Host: "deliver.example", MacHash: "mac-C", URL: url},
		TS:   1_700_000_000,
	}

	verdicts := b.Analyze(msg)

	var zeroClicks []*Verdict
	for _, v := range verdicts {
		if v.Class == ClassZeroClick {
			zeroClicks = append(zeroClicks, v)
		}
	}
	if len(zeroClicks) != 1 {
		t.Fatalf("got %d ClassZeroClick verdicts, want exactly 1 (all: %+v)", len(zeroClicks), verdicts)
	}

	v := zeroClicks[0]
	if v.Action != ActionReport {
		t.Fatalf("one-time-link verdict Action = %q, want %q (heuristic must never auto-block)", v.Action, ActionReport)
	}
	if v.Evidence["pattern"] != "one_time_link" {
		t.Fatalf("Evidence[pattern] = %q, want %q", v.Evidence["pattern"], "one_time_link")
	}
	if v.Evidence["url"] != url {
		t.Fatalf("Evidence[url] = %q, want %q", v.Evidence["url"], url)
	}
	if v.MacHash != "mac-C" {
		t.Fatalf("MacHash = %q, want %q", v.MacHash, "mac-C")
	}
}

// TestBehavioralAllVerdictsAreReportOnly is the safety-critical assertion
// the plan's Global Constraints demand: no matter which heuristic fires
// (beaconing or one-time-link), the emitted Action is ALWAYS ActionReport —
// a behavioral heuristic must never auto-block.
func TestBehavioralAllVerdictsAreReportOnly(t *testing.T) {
	b := NewBehavioral()
	base := int64(1_700_000_000)

	var all []*Verdict
	for i := 0; i < beaconMinHits; i++ {
		all = append(all, b.Analyze(beaconMsg("mac-D", "beacon.example", base+int64(i)*10))...)
	}
	all = append(all, b.Analyze(MirrorMsg{
		Meta: FlowMeta{Host: "deliver.example", MacHash: "mac-D", URL: "https://deliver.example/l/aZ9kQ2xM7vT4rP1nW8fL"},
		TS:   base,
	})...)

	if len(all) == 0 {
		t.Fatal("expected at least the beaconing + one-time-link verdicts to have fired")
	}
	for _, v := range all {
		if v.Action != ActionReport {
			t.Fatalf("verdict Class=%q Action=%q, want Action=%q for every behavioral verdict", v.Class, v.Action, ActionReport)
		}
	}
}

// TestBehavioralUnrelatedSingleRequestsNoVerdict asserts that ordinary,
// unrelated single requests (one hit per distinct host, ordinary URLs) never
// produce a verdict.
func TestBehavioralUnrelatedSingleRequestsNoVerdict(t *testing.T) {
	b := NewBehavioral()

	hosts := []string{"a.example", "b.example", "c.example", "d.example"}
	for i, h := range hosts {
		msg := MirrorMsg{
			Meta: FlowMeta{Host: h, MacHash: "mac-E", URL: "https://" + h + "/index.html"},
			TS:   int64(1_700_000_000 + i*3600),
		}
		if v := b.Analyze(msg); len(v) != 0 {
			t.Fatalf("Analyze(%q) = %+v, want no verdicts", h, v)
		}
	}
}

// TestLooksLikeOneTimeTokenRejectsOrdinaryPaths directly exercises the
// token-shape helper against common, non-token path segments to guard
// against over-eager false positives.
func TestLooksLikeOneTimeTokenRejectsOrdinaryPaths(t *testing.T) {
	ordinary := []string{
		"",
		"index.html",
		"photos",
		"about-us",
		"api/v1/status",
		"short1A",              // too short
		"aaaaaaaaaaaaaaaaaaaa", // long but zero entropy, no digit/mixed-case
	}
	for _, seg := range ordinary {
		last := lastPathSegment("https://example.com/" + seg)
		if looksLikeOneTimeToken(last) {
			t.Fatalf("looksLikeOneTimeToken(%q) = true, want false", last)
		}
	}

	if !looksLikeOneTimeToken("aZ9kQ2xM7vT4rP1nW8fL") {
		t.Fatal("looksLikeOneTimeToken(<random 20-char mixed token>) = false, want true")
	}
}

// TestLooksLikeOneTimeTokenExcludesMediaAndBase64Shapes is the regression
// test for the false-positive review: ordinary timestamped camera filenames,
// base64-encoded blobs, and CDN asset URLs must NOT be flagged as one-time
// tokens even though they can otherwise clear the length/charset/entropy
// gates — only a genuinely extension-less, non-base64 random token should
// still fire, so the heuristic isn't over-tightened into uselessness either.
func TestLooksLikeOneTimeTokenExcludesMediaAndBase64Shapes(t *testing.T) {
	notTokens := []string{
		"IMG_20260704_142233.jpg",      // ordinary camera filename (has an extension)
		"MzE0NTY3ODkwMTIzNDU2Nzg5MA==", // base64 blob with padding
		"app.4f8a9c2b.js",              // ordinary CDN asset (has an extension)
	}
	for _, seg := range notTokens {
		if looksLikeOneTimeToken(seg) {
			t.Errorf("looksLikeOneTimeToken(%q) = true, want false (ordinary media/asset shape, not a one-time token)", seg)
		}
	}

	genuine := "k7Qm2Xp9Rt4Wz8Bn1Lv6Yc3Ha5Fd0Jg" // 31-char mixed-case+digit, no extension, no padding
	if !looksLikeOneTimeToken(genuine) {
		t.Errorf("looksLikeOneTimeToken(%q) = false, want true (genuine one-time-token shape must still fire)", genuine)
	}
}

// TestBehavioralLRUBounded feeds far more than maxTrackedKeys distinct
// (macHash,host) pairs — one message each — and asserts the internal timing
// state never grows past the cap: Behavioral must evict least-recently-used
// entries, not grow unbounded, on a long-running daemon.
func TestBehavioralLRUBounded(t *testing.T) {
	b := NewBehavioral()

	const extra = 500
	total := maxTrackedKeys + extra
	for i := 0; i < total; i++ {
		host := fmt.Sprintf("host-%d.example", i)
		msg := MirrorMsg{
			Meta: FlowMeta{Host: host, MacHash: "mac-F", URL: "https://" + host + "/"},
			TS:   int64(1_700_000_000 + i),
		}
		b.Analyze(msg)
	}

	b.mu.Lock()
	indexLen := len(b.index)
	orderLen := b.order.Len()
	b.mu.Unlock()

	if indexLen > maxTrackedKeys {
		t.Fatalf("tracked-key index size = %d, want <= %d", indexLen, maxTrackedKeys)
	}
	if orderLen > maxTrackedKeys {
		t.Fatalf("tracked-key LRU list size = %d, want <= %d", orderLen, maxTrackedKeys)
	}
	if indexLen != orderLen {
		t.Fatalf("index/order size mismatch: index=%d order=%d", indexLen, orderLen)
	}
}
