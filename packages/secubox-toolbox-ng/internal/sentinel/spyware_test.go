// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package sentinel

import (
	"path/filepath"
	"testing"
)

// basePackDir is the shipped base pack directory relative to this package
// (packages/secubox-toolbox-ng/internal/sentinel -> packages/secubox-toolbox-ng/packs/base).
const basePackDir = "../../packs/base"

// loadAllBasePackIOCs parses every *.json file in the shipped base pack
// directory and returns every IOC entry found across all of them. It fails
// the test (not just returns an error) on any parse failure or an empty
// pack directory — a base pack that doesn't even load is a packaging bug,
// not a soft condition callers should have to handle.
func loadAllBasePackIOCs(t *testing.T) []IOC {
	t.Helper()

	files, err := filepath.Glob(filepath.Join(basePackDir, "*.json"))
	if err != nil {
		t.Fatalf("glob %s: %v", basePackDir, err)
	}
	if len(files) == 0 {
		t.Fatalf("no base pack files found in %s", basePackDir)
	}

	var all []IOC
	for _, f := range files {
		pk, err := LoadBasePack(f)
		if err != nil {
			t.Fatalf("load base pack %s: %v", f, err)
		}
		all = append(all, pk.IOCs...)
	}
	return all
}

// TestBasePackZeroClickIsReportOnly is the shipped-content safety invariant:
// every IOC in every base pack file whose Class is heuristic (per
// scorer.go's IsHeuristicClass — today just ClassZeroClick, but the check is
// written against the allow-list function rather than hardcoding the class,
// so it automatically covers any future addition to heuristicClasses) MUST
// declare Action == ActionReport. A base pack that ships a zero_click (or
// any other heuristic-class) entry as "block" is a shipped false-positive
// waiting to auto-block legitimate traffic, and must fail this test.
func TestBasePackZeroClickIsReportOnly(t *testing.T) {
	iocs := loadAllBasePackIOCs(t)

	var checked int
	for _, ioc := range iocs {
		if !IsHeuristicClass(ioc.Class) {
			continue
		}
		checked++
		if ioc.Action != ActionReport {
			t.Errorf("base pack IOC %+v has heuristic class %q but Action=%q, want %q — a shipped heuristic/zero-click entry must NEVER auto-block",
				ioc, ioc.Class, ioc.Action, ActionReport)
		}
	}

	if checked == 0 {
		t.Fatal("no heuristic-class (e.g. zero_click) IOCs found across the base packs — this test would otherwise pass vacuously; spyware.json must ship at least one zero_click delivery-URL entry")
	}
}

// TestBasePackKnownInfraIsHighSeverity backs the confidence guarantee
// spyware.go's spywareVerdict doc comment relies on: every shipped
// known-infra spyware IOC (Pegasus/Predator/Intellexa) must carry Severity
// >= HighConfidenceThreshold, since Spyware.Analyze sets Confidence directly
// from Severity for a direct indicator hit — a low-severity "known infra"
// entry would silently fail to survive FinalizeAction.
func TestBasePackKnownInfraIsHighSeverity(t *testing.T) {
	iocs := loadAllBasePackIOCs(t)

	knownInfra := map[ThreatClass]bool{
		ClassSpywarePegasus:   true,
		ClassSpywarePredator:  true,
		ClassSpywareIntellexa: true,
	}

	var checked int
	for _, ioc := range iocs {
		if !knownInfra[ioc.Class] {
			continue
		}
		checked++
		if ioc.Severity < HighConfidenceThreshold {
			t.Errorf("base pack known-infra IOC %+v has Severity=%d, want >= %d (HighConfidenceThreshold) so it survives FinalizeAction",
				ioc, ioc.Severity, HighConfidenceThreshold)
		}
		if ioc.Action != ActionBlock {
			t.Errorf("base pack known-infra IOC %+v has Action=%q, want %q", ioc, ioc.Action, ActionBlock)
		}
	}
	if checked == 0 {
		t.Fatal("no known-infra spyware IOCs (Pegasus/Predator/Intellexa) found in base packs")
	}
}

// TestBasePackIOCsHaveSource asserts every base pack IOC declares a
// non-empty Source (e.g. "amnesty-mvt", "citizen-lab", "abuse.ch") —
// provenance is required for a defensive detection pack shipped to
// operators, per the plan's brief.
func TestBasePackIOCsHaveSource(t *testing.T) {
	iocs := loadAllBasePackIOCs(t)
	for _, ioc := range iocs {
		if ioc.Source == "" {
			t.Errorf("base pack IOC %+v has empty Source", ioc)
		}
	}
}

// TestBasePackDeclaredBlockIsHighSeverity is the general form of the guard
// TestBasePackKnownInfraIsHighSeverity enforces only for the known-infra
// spyware classes: ANY base pack IOC that declares an auto-neutralize action
// (block, strip, or sinkhole) must carry Severity >= HighConfidenceThreshold.
// scorer.go's FinalizeAction silently downgrades a Confidence below that
// threshold to report-only regardless of the declared Action — so a shipped
// "block" entry with too-low severity never actually blocks anything, the
// exact footgun previously found in the YARA Confidence=80 bug and, before
// this fix, in three base-pack IOCs (malware.json ip/cert_sha1, botnet.json
// ja3) that shipped Severity=80 < HighConfidenceThreshold=85. This test
// covers every current and future base pack file/entry generically rather
// than re-deriving the offending list by hand.
func TestBasePackDeclaredBlockIsHighSeverity(t *testing.T) {
	iocs := loadAllBasePackIOCs(t)

	autoNeutralize := map[Action]bool{
		ActionBlock:    true,
		ActionStrip:    true,
		ActionSinkhole: true,
	}

	var checked int
	for _, ioc := range iocs {
		if !autoNeutralize[ioc.Action] {
			continue
		}
		checked++
		if ioc.Severity < HighConfidenceThreshold {
			t.Errorf("base pack IOC %+v declares auto-neutralize Action=%q but Severity=%d < %d (HighConfidenceThreshold) — FinalizeAction will silently downgrade this to report-only and it will never actually %s",
				ioc, ioc.Action, ioc.Severity, HighConfidenceThreshold, ioc.Action)
		}
	}
	if checked == 0 {
		t.Fatal("no auto-neutralize (block/strip/sinkhole) IOCs found across the base packs — this test would otherwise pass vacuously")
	}
}

// TestSpywareKnownInfraDomainBlocks exercises the brief's Step-1 scenario
// against the REAL shipped base pack: a MirrorMsg whose FlowMeta.Host equals
// a shipped Pegasus domain IOC must produce a ClassSpywarePegasus verdict
// with Action block and Confidence high enough to survive FinalizeAction.
func TestSpywareKnownInfraDomainBlocks(t *testing.T) {
	l, err := NewLoader(basePackDir, "")
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}

	iocs := loadAllBasePackIOCs(t)
	var target *IOC
	for i := range iocs {
		if iocs[i].Type == IOCDomain && iocs[i].Class == ClassSpywarePegasus {
			target = &iocs[i]
			break
		}
	}
	if target == nil {
		t.Fatal("no shipped domain IOC with class spyware_pegasus found — cannot exercise the known-infra path")
	}

	sp := NewSpyware(l)
	verdicts := sp.Analyze(MirrorMsg{Meta: FlowMeta{Host: target.Value}, TS: 1})
	if len(verdicts) == 0 {
		t.Fatalf("Analyze returned no verdicts for shipped Pegasus domain %q", target.Value)
	}

	var got *Verdict
	for _, v := range verdicts {
		if v.Class == ClassSpywarePegasus {
			got = v
		}
	}
	if got == nil {
		t.Fatalf("no ClassSpywarePegasus verdict among %+v", verdicts)
	}
	if got.Action != ActionBlock {
		t.Fatalf("Action = %q, want %q", got.Action, ActionBlock)
	}
	if got.Confidence < HighConfidenceThreshold {
		t.Fatalf("Confidence = %d, want >= %d", got.Confidence, HighConfidenceThreshold)
	}
	if fa := FinalizeAction(got); fa != ActionBlock {
		t.Fatalf("FinalizeAction(got) = %q, want %q — a high-confidence known-infra verdict must survive the scorer", fa, ActionBlock)
	}
}

// TestSpywareZeroClickURLReportOnly loads the real shipped base pack and
// finds a zero_click url_regex IOC, then feeds Analyze a URL crafted to
// match it, asserting the resulting verdict is report-only end to end.
func TestSpywareZeroClickURLReportOnly(t *testing.T) {
	l, err := NewLoader(basePackDir, "")
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}

	iocs := loadAllBasePackIOCs(t)
	var target *IOC
	for i := range iocs {
		if iocs[i].Type == IOCURLRegex && iocs[i].Class == ClassZeroClick {
			target = &iocs[i]
			break
		}
	}
	if target == nil {
		t.Fatal("no shipped url_regex IOC with class zero_click found — cannot exercise the zero-click delivery path")
	}

	url := sampleURLForRegex(t, target.Value)

	sp := NewSpyware(l)
	verdicts := sp.Analyze(MirrorMsg{Meta: FlowMeta{URL: url}, TS: 1})
	if len(verdicts) == 0 {
		t.Fatalf("Analyze returned no verdicts for zero-click URL %q (pattern %q)", url, target.Value)
	}

	var got *Verdict
	for _, v := range verdicts {
		if v.Class == ClassZeroClick {
			got = v
		}
	}
	if got == nil {
		t.Fatalf("no ClassZeroClick verdict among %+v", verdicts)
	}
	if got.Action != ActionReport {
		t.Fatalf("Action = %q, want %q — zero-click must never auto-block", got.Action, ActionReport)
	}
	if fa := FinalizeAction(got); fa != ActionReport {
		t.Fatalf("FinalizeAction(got) = %q, want %q", fa, ActionReport)
	}
}

// TestSpywareZeroClickForcedReportEvenIfPackSaysBlock is the defense-in-depth
// unit test for spywareVerdict's own override: even a (synthetic,
// non-shipped) pack that mis-declares a zero_click IOC's Action as "block"
// must still come out of Analyze as ActionReport — the base-pack content
// invariant (TestBasePackZeroClickIsReportOnly) is one guard; this is the
// independent code-level guard so a future bad overlay/live-feed pack can't
// slip a block action through this engine either.
func TestSpywareZeroClickForcedReportEvenIfPackSaysBlock(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "test.json"), `{
		"version": "1",
		"iocs": [
			{"type":"url_regex","value":"https://[a-z0-9]+\\.evil-delivery\\.example/x/[A-Za-z0-9]{16}","class":"zero_click","severity":70,"source":"test","action":"block"}
		]
	}`)

	l, err := NewLoader(dir, "")
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}
	sp := NewSpyware(l)

	verdicts := sp.Analyze(MirrorMsg{Meta: FlowMeta{URL: "https://x1.evil-delivery.example/x/ABCDEFGHIJKLMNOP"}, TS: 1})
	if len(verdicts) != 1 {
		t.Fatalf("got %d verdicts, want 1: %+v", len(verdicts), verdicts)
	}
	if verdicts[0].Action != ActionReport {
		t.Fatalf("Action = %q, want %q even though the (bad) pack declared block", verdicts[0].Action, ActionReport)
	}
}

// TestSpywareIgnoresNonSpywareClassHits asserts Spyware.Analyze only reports
// on the spyware-relevant classes — a matched IOC of an unrelated class
// (e.g. generic botnet_c2) must produce no verdict here; that class is the
// inline gate's / other analyzers' concern.
func TestSpywareIgnoresNonSpywareClassHits(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "test.json"), `{
		"version": "1",
		"iocs": [
			{"type":"domain","value":"c2.example","class":"botnet_c2","severity":90,"source":"test","action":"block"}
		]
	}`)

	l, err := NewLoader(dir, "")
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}
	sp := NewSpyware(l)

	verdicts := sp.Analyze(MirrorMsg{Meta: FlowMeta{Host: "c2.example"}, TS: 1})
	if len(verdicts) != 0 {
		t.Fatalf("expected no verdicts for a non-spyware-class hit, got %+v", verdicts)
	}
}

// TestSpywareNoMatchReturnsNil asserts a flow matching nothing produces no
// verdicts (and no error).
func TestSpywareNoMatchReturnsNil(t *testing.T) {
	l, err := NewLoader(basePackDir, "")
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}
	sp := NewSpyware(l)

	verdicts := sp.Analyze(MirrorMsg{Meta: FlowMeta{Host: "totally-benign.example"}, TS: 1})
	if len(verdicts) != 0 {
		t.Fatalf("expected no verdicts for a benign flow, got %+v", verdicts)
	}
}

// TestSpywareAnalyzeNilLoaderFailsOpen mirrors gate_test.go's equivalent
// guard: a Spyware backed by a nil Loader (or any other internal failure)
// must never panic the caller — Analyze recovers and returns nil.
func TestSpywareAnalyzeNilLoaderFailsOpen(t *testing.T) {
	sp := &Spyware{loader: nil}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Analyze panicked instead of failing open: %v", r)
		}
	}()

	verdicts := sp.Analyze(MirrorMsg{Meta: FlowMeta{Host: "whatever.example"}, TS: 1})
	if verdicts != nil {
		t.Fatalf("expected nil verdicts from a broken Spyware (nil loader), got %+v", verdicts)
	}
}

// sampleURLForRegex builds a concrete URL string designed to satisfy the
// commercial-spyware zero-click delivery patterns this package's base pack
// ships (a single lowercase-alnum subdomain label followed by a long
// mixed-case/digit token path segment). This intentionally does not attempt
// to be a general regex-to-string generator — it only needs to satisfy the
// specific shapes authored into packs/base/spyware.json.
func sampleURLForRegex(t *testing.T, pattern string) string {
	t.Helper()
	switch pattern {
	case `https://[a-z0-9]+\.notif-push\.example/t/[A-Za-z0-9]{16,32}`:
		return "https://x1.notif-push.example/t/ABCDEFGHIJKLMNOP12"
	case `https://[a-z0-9]+\.short-verify\.example/s/[A-Za-z0-9]{10,24}`:
		return "https://a1.short-verify.example/s/ABCDEFGHIJ1234"
	default:
		t.Fatalf("sampleURLForRegex: no sample crafted for pattern %q — update this test helper to match packs/base/spyware.json", pattern)
		return ""
	}
}
