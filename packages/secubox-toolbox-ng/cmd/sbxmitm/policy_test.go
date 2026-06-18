// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// Cross-engine parity harness — Go side (#662 Phase 3).
//
// Loads testdata/parity-fixtures.json + the testdata/config snapshot, runs
// Policy.Decide on each host, and asserts == the fixture's expect. The Python
// side (../secubox-toolbox/tests/test_engine_parity.py) loads the SAME files
// and drives the SAME decision; both must agree → parity proven.
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type parityConfig struct {
	AdAllowlist     string   `json:"ad_allowlist"`
	LearnedTrackers string   `json:"learned_trackers"`
	SpliceSeed      string   `json:"splice_seed"`
	SpliceLearned   string   `json:"splice_learned"`
	PureTrackers    string   `json:"pure_trackers"`
	SelfDomains     []string `json:"self_domains"`
	FortknoxSites   []string `json:"fortknox_sites"`
}

type parityFixture struct {
	Host   string `json:"host"`
	Expect string `json:"expect"`
	Why    string `json:"why"`
}

type parityFile struct {
	Config   parityConfig    `json:"config"`
	Fixtures []parityFixture `json:"fixtures"`
}

// testdataDir resolves the testdata/ dir relative to this package
// (cmd/sbxmitm → ../../testdata).
func testdataDir(t *testing.T) string {
	t.Helper()
	d, err := filepath.Abs(filepath.Join("..", "..", "testdata"))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func loadParityFile(t *testing.T) (parityFile, string) {
	t.Helper()
	dir := testdataDir(t)
	raw, err := os.ReadFile(filepath.Join(dir, "parity-fixtures.json"))
	if err != nil {
		t.Fatalf("read fixtures: %v", err)
	}
	var pf parityFile
	if err := json.Unmarshal(raw, &pf); err != nil {
		t.Fatalf("parse fixtures: %v", err)
	}
	if len(pf.Fixtures) == 0 {
		t.Fatal("no fixtures")
	}
	return pf, dir
}

func TestParityDecide(t *testing.T) {
	pf, dir := loadParityFile(t)
	cfgPath := func(rel string) string { return filepath.Join(dir, filepath.FromSlash(rel)) }

	pol, err := LoadPolicy(PolicyOpts{
		AllowPath:        cfgPath(pf.Config.AdAllowlist),
		LearnedPath:      cfgPath(pf.Config.LearnedTrackers),
		SpliceSeedPath:   cfgPath(pf.Config.SpliceSeed),
		SpliceLearnPath:  cfgPath(pf.Config.SpliceLearned),
		PureTrackersPath: cfgPath(pf.Config.PureTrackers),
		FortknoxSites:    pf.Config.FortknoxSites,
		SelfDomains:      pf.Config.SelfDomains,
	})
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}

	for _, fx := range pf.Fixtures {
		got := pol.Decide(fx.Host, fx.Host)
		if got != fx.Expect {
			t.Errorf("Decide(%q)=%q want %q  (%s)", fx.Host, got, fx.Expect, fx.Why)
		}
	}
}

// TestPolicyActionVerbs checks the legacy 3-verb action() surface still wired
// into the PoC CONNECT path: allow collapses to mitm; block/splice preserved.
func TestPolicyActionVerbs(t *testing.T) {
	pf, dir := loadParityFile(t)
	cfgPath := func(rel string) string { return filepath.Join(dir, filepath.FromSlash(rel)) }
	pol, err := LoadPolicy(PolicyOpts{
		AllowPath:        cfgPath(pf.Config.AdAllowlist),
		LearnedPath:      cfgPath(pf.Config.LearnedTrackers),
		SpliceSeedPath:   cfgPath(pf.Config.SpliceSeed),
		SpliceLearnPath:  cfgPath(pf.Config.SpliceLearned),
		PureTrackersPath: cfgPath(pf.Config.PureTrackers),
		FortknoxSites:    pf.Config.FortknoxSites,
		SelfDomains:      pf.Config.SelfDomains,
	})
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"ads.doubleclick.net":          "block",
		"r1.googlevideo.com":           "splice",
		"news.example.com":             "mitm",
		"notdoubleclick.net":           "mitm",
		"analytics.example-allowed.com": "mitm", // allow → normal interception (mitm verb)
		"hub.secubox.in":               "mitm", // own-infra → normal interception
	}
	for host, want := range cases {
		if got := pol.action(host); got != want {
			t.Errorf("action(%q)=%q want %q", host, got, want)
		}
	}
}

// TestRegistrable exercises the _registrable port incl. the 2-level TLD list.
func TestRegistrable(t *testing.T) {
	cases := map[string]string{
		"a.b.example.com":    "example.com",
		"example.com":        "example.com",
		"com":                "com",
		"a.b.example.co.uk":  "example.co.uk",
		"example.co.uk":      "example.co.uk", // 2 labels → returned as-is
		"x.y.z.example.com":  "example.com",
		"1.2.3.4":            "",
		"":                   "",
	}
	for in, want := range cases {
		if got := registrable(in); got != want {
			t.Errorf("registrable(%q)=%q want %q", in, got, want)
		}
	}
}
