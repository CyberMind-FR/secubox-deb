// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: R-level per-peer wiring (#rlevel-per-peer Task 3)
//
// Proves decideForPeer — the single helper both accept paths (CONNECT/
// handleConnect and transparent/handleTransparent) call — actually clamps
// px.pol.Decide's verdict to the calling peer's R-level, and that a Proxy
// built without a PeerPolicy (px.rlevel == nil, every pre-existing test/PoC)
// keeps today's exact behavior.
package main

import (
	"path/filepath"
	"testing"
)

// wireTestPeerRlevelJSON pins three peers to fixed, explicit modes via
// "forced" so the test is independent of defaults/floor clamping semantics
// (already covered by TestPeerPolicyModeForIP in rlevel_test.go).
const wireTestPeerRlevelJSON = `{
	"defaults": {"mode": "passive", "floor": "passive"},
	"peers": {
		"PKPASSIVE": {"forced": "passive"},
		"PKACTIVE": {"forced": "active"},
		"PKREEL": {"forced": "reel"}
	}
}`

const wireTestWgPeersJSON = `{
	"peers": {
		"PKPASSIVE": {"ip": "10.60.0.1"},
		"PKACTIVE": {"ip": "10.60.0.2"},
		"PKREEL": {"ip": "10.60.0.3"}
	}
}`

const (
	wirePassiveIP = "10.60.0.1"
	wireActiveIP  = "10.60.0.2"
	wireReelIP    = "10.60.0.3"
	wireUnknownIP = "10.60.0.99"
)

// newWireTestPolicy builds a real Policy (LoadPolicy, like policy_test.go/
// reload_test.go) with two hosts of known, deterministic verdicts:
//   - mitmHost   : not in any list → Decide == "mitm" (the engine's default
//     for an unmatched host, per TestMaybeReloadPicksUpAppendedLearnedTracker).
//   - blockHost  : appended to learned-trackers.txt → Decide == "block".
func newWireTestPolicy(t *testing.T) (pol *Policy, mitmHost, blockHost string) {
	t.Helper()
	dir := t.TempDir()
	mitmHost = "mitm-would-be.example"
	blockHost = "block-would-be.example"

	learned := filepath.Join(dir, "learned-trackers.txt")
	allow := filepath.Join(dir, "ad-allowlist.txt")
	writeFile(t, learned, blockHost+"\n")
	writeFile(t, allow, "")

	p, err := LoadPolicy(PolicyOpts{
		LearnedPath:      learned,
		AllowPath:        allow,
		SpliceSeedPath:   filepath.Join(dir, "splice-seed.conf"),
		SpliceLearnPath:  filepath.Join(dir, "splice-learned.txt"),
		PureTrackersPath: filepath.Join(dir, "pure-trackers.txt"),
		SelfDomains:      []string{"secubox.in"},
	})
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	return p, mitmHost, blockHost
}

// newWireTestPeerPolicy loads the three-peer fixture (passive/active/reel).
func newWireTestPeerPolicy(t *testing.T) *PeerPolicy {
	t.Helper()
	rlevelPath, wgPath := writePeerFixtures(t, wireTestPeerRlevelJSON, wireTestWgPeersJSON)
	pp, err := LoadPeerPolicy(rlevelPath, wgPath)
	if err != nil {
		t.Fatalf("LoadPeerPolicy: %v", err)
	}
	return pp
}

// TestDecideForPeerPassiveClampsToSplice: a passive IP always gets "splice",
// even for a host whose bare policy verdict would be "mitm".
func TestDecideForPeerPassiveClampsToSplice(t *testing.T) {
	pol, mitmHost, _ := newWireTestPolicy(t)
	// sanity: prove the unclamped verdict really is "mitm" first.
	if got := pol.Decide(mitmHost, mitmHost); got != "mitm" {
		t.Fatalf("sanity: pol.Decide(%q) = %q, want mitm", mitmHost, got)
	}
	px := &Proxy{pol: pol, rlevel: newWireTestPeerPolicy(t)}

	if got := px.decideForPeer(wirePassiveIP, mitmHost, mitmHost); got != "splice" {
		t.Fatalf("passive peer: decideForPeer(%q) = %q, want splice (would-be mitm host)", mitmHost, got)
	}
}

// TestDecideForPeerActiveDowngradesBlockToMitm: an active IP gets "mitm" for
// a host whose bare policy verdict would be "block" (visibility, no enforce).
func TestDecideForPeerActiveDowngradesBlockToMitm(t *testing.T) {
	pol, _, blockHost := newWireTestPolicy(t)
	if got := pol.Decide(blockHost, blockHost); got != "block" {
		t.Fatalf("sanity: pol.Decide(%q) = %q, want block", blockHost, got)
	}
	px := &Proxy{pol: pol, rlevel: newWireTestPeerPolicy(t)}

	if got := px.decideForPeer(wireActiveIP, blockHost, blockHost); got != "mitm" {
		t.Fatalf("active peer: decideForPeer(%q) = %q, want mitm (would-be block host)", blockHost, got)
	}
}

// TestDecideForPeerReelPreservesBlock: a reel (full enforcement) IP keeps the
// underlying "block" verdict unchanged.
func TestDecideForPeerReelPreservesBlock(t *testing.T) {
	pol, _, blockHost := newWireTestPolicy(t)
	px := &Proxy{pol: pol, rlevel: newWireTestPeerPolicy(t)}

	if got := px.decideForPeer(wireReelIP, blockHost, blockHost); got != "block" {
		t.Fatalf("reel peer: decideForPeer(%q) = %q, want block (preserved)", blockHost, got)
	}
}

// TestDecideForPeerNilRlevelIsNoop: px.rlevel == nil (every Proxy built by the
// existing suite / the CONNECT PoC before this task) must behave EXACTLY like
// calling px.pol.Decide directly — the wiring must never change behavior for
// a Proxy that doesn't opt in.
func TestDecideForPeerNilRlevelIsNoop(t *testing.T) {
	pol, mitmHost, blockHost := newWireTestPolicy(t)
	px := &Proxy{pol: pol} // rlevel left at its zero value: nil

	for _, host := range []string{mitmHost, blockHost} {
		want := pol.Decide(host, host)
		// Any clientIP — including one that would resolve to Passive/Active in
		// the fixture used above — must have zero effect when rlevel is nil.
		if got := px.decideForPeer(wirePassiveIP, host, host); got != want {
			t.Fatalf("nil rlevel: decideForPeer(%q) = %q, want %q (== pol.Decide, no-op)", host, got, want)
		}
	}
}
