// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// Gate tests for the poison emission (#662 Phase 5-prep, Part A): poison only
// fires on MITM'd TRACKER flows, never on allow/own-infra flows. This is the
// same safety envelope as anti-track — own-infra/allowlist flows stay clean.
package main

import (
	"path/filepath"
	"testing"
)

// TestShouldPoisonGate: a tracker host MITM'd → poison; an own-infra/allowlisted
// host → never poison (even though both are intercepted = "mitm" verb).
func TestShouldPoisonGate(t *testing.T) {
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

	cases := map[string]bool{
		// tracker hosts → poison eligible (a tracker we'd otherwise block, but
		// once MITM'd we poison rather than blunt-block).
		"ads.doubleclick.net": true,
		"adnxs.com":           true,
		// own-infra + allowlisted + benign → NEVER poison.
		"hub.secubox.in":                false,
		"analytics.example-allowed.com": false,
		"news.example.com":              false,
	}
	for host, want := range cases {
		if got := pol.shouldPoison(host); got != want {
			t.Errorf("shouldPoison(%q)=%v want %v", host, got, want)
		}
	}
}
