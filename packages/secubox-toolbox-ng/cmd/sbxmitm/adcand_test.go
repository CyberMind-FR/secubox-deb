// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: ad-candidate learning-feed tests (#662)
//
// The Go cutover blocked from STATIC lists but never emitted LEARNING
// candidates, so a brand-new adware (acotedemoi.com) was never observed → never
// promoted → slipped through forever. These tests prove the engine now ports
// ad_ghost's _AD_PATH heuristic and records a candidate (host,site) for every
// 3rd-party ad-path request on the allow/mitm path — the feed autolearn promotes.
package main

import (
	"path/filepath"
	"testing"
)

func TestAdPathRegex(t *testing.T) {
	hit := []string{
		"/ad/1.gif", "/ads/x", "/adserver/req", "/pagead/conversion",
		"/gampad/ads", "/doubleclick/x", "/beacon", "/pixel.gif",
		"/collect", "/track", "/tracking/p", "/telemetry/v2", "/metric",
		"/PAGEAD/Upper", // case-insensitive
	}
	for _, p := range hit {
		if !adPathRE.MatchString(p) {
			t.Errorf("adPathRE should MATCH %q", p)
		}
	}
	miss := []string{"/", "/index.html", "/api/users", "/static/app.js", "/cart", "/headline"}
	for _, p := range miss {
		if adPathRE.MatchString(p) {
			t.Errorf("adPathRE should NOT match %q", p)
		}
	}
}

// newAdCandTestPolicy builds a Policy with doubleclick.net allowlisted (so the
// allowlist-skip branch is exercised) and nothing learned.
func newAdCandTestPolicy(t *testing.T) *Policy {
	t.Helper()
	pol, err := LoadPolicy(PolicyOpts{
		AllowPath:        writeTemp(t, "doubleclick.net\n"),
		LearnedPath:      writeTemp(t, ""),
		SpliceSeedPath:   writeTemp(t, ""),
		SpliceLearnPath:  writeTemp(t, ""),
		PureTrackersPath: writeTemp(t, ""),
		SelfDomains:      []string{"secubox.in"},
	})
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	return pol
}

func TestMaybeRecordAdCandidate(t *testing.T) {
	pol := newAdCandTestPolicy(t)

	cases := []struct {
		name   string
		host   string // request host
		site   string // referer site (registrable)
		path   string
		want   bool // candidate recorded?
		wantHK string
	}{
		{"3rd-party ad-path → candidate", "metrics.acotedemoi.com", "lemonde.fr", "/collect", true, "metrics.acotedemoi.com"},
		{"3rd-party ad-path /pagead", "ads.foo.io", "news.example", "/pagead/x", true, "ads.foo.io"},
		{"1st-party (same registrable) → no candidate", "static.lemonde.fr", "lemonde.fr", "/ads/x", false, ""},
		{"3rd-party non-ad-path → no candidate", "cdn.acotedemoi.com", "lemonde.fr", "/app.js", false, ""},
		{"no site (no Referer) → no candidate", "metrics.acotedemoi.com", "", "/collect", false, ""},
		{"allowlisted host → no candidate", "ads.doubleclick.net", "lemonde.fr", "/pagead/x", false, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cand := newAdCandidates()
			px := &Proxy{pol: pol, cand: cand, analysisRelay: true}
			px.maybeRecordAdCandidate(tc.host, tc.site, tc.path)
			snap := cand.snapshot()
			if tc.want {
				if len(snap) != 1 {
					t.Fatalf("want 1 candidate, got %d (%+v)", len(snap), snap)
				}
				if snap[0].Host != tc.wantHK {
					t.Fatalf("candidate host = %q, want %q", snap[0].Host, tc.wantHK)
				}
				if snap[0].Site != tc.site {
					t.Fatalf("candidate site = %q, want %q", snap[0].Site, tc.site)
				}
				if snap[0].Hits != 1 {
					t.Fatalf("candidate hits = %d, want 1", snap[0].Hits)
				}
			} else if len(snap) != 0 {
				t.Fatalf("want 0 candidates, got %d (%+v)", len(snap), snap)
			}
		})
	}
}

// TestAdCandidateGatedByRelay proves the feed is gated behind the analysis/ad
// relay flag: with the gate off, nothing is recorded even on a textbook hit.
func TestAdCandidateGatedByRelay(t *testing.T) {
	pol := newAdCandTestPolicy(t)
	cand := newAdCandidates()
	px := &Proxy{pol: pol, cand: cand, analysisRelay: false}
	px.maybeRecordAdCandidate("metrics.acotedemoi.com", "lemonde.fr", "/collect")
	if n := len(cand.snapshot()); n != 0 {
		t.Fatalf("relay off: want 0 candidates, got %d", n)
	}
}

// TestAdCandidateHitsAccumulate proves repeated (host,site) hits coalesce.
func TestAdCandidateHitsAccumulate(t *testing.T) {
	cand := newAdCandidates()
	for i := 0; i < 5; i++ {
		cand.record("x.tracker.io", "site.example")
	}
	snap := cand.snapshot()
	if len(snap) != 1 || snap[0].Hits != 5 {
		t.Fatalf("want 1 row hits=5, got %+v", snap)
	}
	// snapshot clears.
	if n := len(cand.snapshot()); n != 0 {
		t.Fatalf("snapshot should clear: got %d", n)
	}
}

// TestAdCandidatePayloadShape proves the candidates list serialises into the
// extended ad-event payload (host/site/hits keys).
func TestAdCandidatePayloadShape(t *testing.T) {
	cand := newAdCandidates()
	cand.record("x.tracker.io", "site.example")
	rows := cand.snapshot()
	p := adEventPayload{Candidates: rows}
	if p.empty() {
		t.Fatal("payload with candidates must not be empty()")
	}
}

// writeTemp writes content to a fresh temp file and returns its path.
func writeTemp(t *testing.T, content string) string {
	t.Helper()
	f := filepath.Join(t.TempDir(), "list.txt")
	writeFile(t, f, content)
	return f
}
