// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package sentinel

import (
	"path/filepath"
	"testing"
)

func c2TestLearner(t *testing.T) *C2Learner {
	t.Helper()
	dir := t.TempDir()
	return NewC2Learner(NewBehavioral(), C2Config{
		AllowFile:   filepath.Join(dir, "allow.txt"),
		CandFile:    filepath.Join(dir, "cand.json"),
		LearnedFile: filepath.Join(dir, "learned.json"),
		BrowserJA4:  []string{"t13d1516h2_browserfp"},
	})
}

// A DGA host with a non-browser JA4, beaconed at a steady interval across
// enough windows/span, is learned; and re-contact then yields a botnet_c2
// verdict.
func TestC2LearnerPromotesRealC2(t *testing.T) {
	l := c2TestLearner(t)
	host := "x7f3q9zk2vw8plmn.example"
	mac := "devhashaa"
	// feed >= beaconMinHits at a constant 300s interval to trip Behavioral,
	// repeated across >= c2MinWindows spanning >= c2MinSpanSec.
	ts := int64(1_000_000)
	learned := false
	for w := 0; w < 4; w++ {
		for i := 0; i < 7; i++ {
			l.Analyze(MirrorMsg{Meta: FlowMeta{Host: host, MacHash: mac, JA4: "botfp99"}, TS: ts})
			ts += 300
		}
		if len(l.Learned()) > 0 {
			learned = true
		}
		// reset Behavioral's latch is not needed: new windows advance ts; the
		// learner records a candidate window each time Behavioral fires.
	}
	if !learned {
		t.Fatalf("expected host to be learned; learned=%v candidates=%v", l.Learned(), l.Candidates())
	}
	// re-contact a learned host → botnet_c2 report verdict
	vs := l.Analyze(MirrorMsg{Meta: FlowMeta{Host: host, MacHash: mac, JA4: "botfp99"}, TS: ts})
	found := false
	for _, v := range vs {
		if v.Class == ClassBotnetC2 && v.Action == ActionReport {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a report-only botnet_c2 verdict on re-contact, got %+v", vs)
	}
}

// An allowlisted host (box vhost / mail) beaconing with a browser JA4 is never
// learned.
func TestC2LearnerSuppressesAllowlisted(t *testing.T) {
	l := c2TestLearner(t)
	_ = l.Allow("mail.example.com") // operator/seed allow
	ts := int64(3_000_000)
	for w := 0; w < 5; w++ {
		for i := 0; i < 7; i++ {
			l.Analyze(MirrorMsg{Meta: FlowMeta{Host: "imap.mail.example.com", MacHash: "devB", JA4: "t13d1516h2_browserfp"}, TS: ts})
			ts += 300
		}
	}
	if len(l.Learned()) != 0 {
		t.Errorf("allowlisted host must never be learned, got %v", l.Learned())
	}
}

// A periodic host with a BROWSER JA4 and a common word domain (no corroborating
// signal) is never learned — periodicity alone is insufficient.
func TestC2LearnerNoSignalNoPromote(t *testing.T) {
	l := c2TestLearner(t)
	host := "dashboard.example.com"
	// make it "not rare": observe many times first
	for i := 0; i < 60; i++ {
		l.Analyze(MirrorMsg{Meta: FlowMeta{Host: host, MacHash: "devC", JA4: "t13d1516h2_browserfp"}, TS: int64(4_000_000 + i)})
	}
	ts := int64(5_000_000)
	for w := 0; w < 5; w++ {
		for i := 0; i < 7; i++ {
			l.Analyze(MirrorMsg{Meta: FlowMeta{Host: host, MacHash: "devC", JA4: "t13d1516h2_browserfp"}, TS: ts})
			ts += 300
		}
	}
	if len(l.Learned()) != 0 {
		t.Errorf("browser-JA4 common-word host must not be learned, got %v", l.Learned())
	}
}

// TestC2LearnerWindowAdvanceOwnTiming proves the core design point directly:
// Behavioral.checkBeaconing fires a ClassBotnetC2 "beaconing" verdict at most
// ONCE per (mac,host) — after the first fire, every later Analyze call for
// that host returns no NEW beacon verdict from Behavioral (the latch). Yet
// C2Learner must still keep accumulating candidate windows on ITS OWN timing
// (tickWindow), reaching c2MinWindows across c2MinSpanSec and promoting —
// proving promotion does not depend on Behavioral firing again.
func TestC2LearnerWindowAdvanceOwnTiming(t *testing.T) {
	l := c2TestLearner(t)
	host := "q9zx4kmw7plr2vnh.example" // DGA-shaped, non-browser JA4 → 2 signals
	mac := "devhashbb"
	const interval = int64(300)
	ts := int64(2_000_000)

	beaconFires := 0
	firstFireSeen := false
	for i := 0; i < 40; i++ {
		vs := l.Analyze(MirrorMsg{Meta: FlowMeta{Host: host, MacHash: mac, JA4: "botfp77"}, TS: ts})
		for _, v := range vs {
			if v.Class == ClassBotnetC2 && v.Evidence["pattern"] == "beaconing" {
				beaconFires++
				firstFireSeen = true
			}
		}
		ts += interval

		if firstFireSeen {
			// After the first Behavioral fire, candidate windows must still
			// be climbing on the learner's own timing even though Behavioral
			// itself will never fire "beaconing" for this key again.
			cds := l.Candidates()
			if len(cds) == 0 {
				t.Fatalf("iteration %d: expected a tracked candidate after first beacon fire", i)
			}
		}
	}

	if beaconFires != 1 {
		t.Fatalf("expected Behavioral's beacon verdict to latch (fire exactly once), got %d fires", beaconFires)
	}
	if len(l.Learned()) == 0 {
		t.Fatalf("expected sustained own-timing window-advance to promote the host; candidates=%v", l.Candidates())
	}
}
