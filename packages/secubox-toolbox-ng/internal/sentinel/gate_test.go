// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package sentinel

import (
	"path/filepath"
	"testing"
)

const gateBasePackJSON = `{
  "version": "1",
  "iocs": [
    {"type": "domain", "value": "c2.example", "class": "botnet_c2", "severity": 90, "action": "block"},
    {"type": "url_regex", "value": "/beacon\\?id=", "class": "zero_click", "severity": 40, "action": "report"}
  ]
}`

const gateSeverityPackJSON = `{
  "version": "1",
  "iocs": [
    {"type": "domain", "value": "shared.example", "class": "malware", "severity": 50, "action": "report", "source": "feed-a"},
    {"type": "ja4", "value": "j4hash", "class": "botnet_c2", "severity": 90, "action": "block", "source": "feed-b"}
  ]
}`

func newTestGate(t *testing.T, packJSON string) *Gate {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "base.json"), packJSON)
	l, err := NewLoader(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	return NewGate(l)
}

func TestGateMatchBlockDomain(t *testing.T) {
	g := newTestGate(t, gateBasePackJSON)

	v := g.Match(FlowMeta{Host: "c2.example", MacHash: "mh-1"})
	if v == nil {
		t.Fatal("expected a verdict for a known-bad domain, got nil")
	}
	if v.Action != ActionBlock {
		t.Fatalf("Action = %q, want %q", v.Action, ActionBlock)
	}
	if v.Class != ClassBotnetC2 {
		t.Fatalf("Class = %q, want %q", v.Class, ClassBotnetC2)
	}
	if v.Severity != 90 || v.Confidence != 90 {
		t.Fatalf("Severity/Confidence = %d/%d, want 90/90", v.Severity, v.Confidence)
	}
	if v.MacHash != "mh-1" {
		t.Fatalf("MacHash = %q, want %q", v.MacHash, "mh-1")
	}
	if v.Evidence["ioc_type"] != string(IOCDomain) || v.Evidence["ioc_value"] != "c2.example" {
		t.Fatalf("unexpected evidence: %+v", v.Evidence)
	}
	if v.TS == 0 {
		t.Fatal("expected TS to be set")
	}
}

func TestGateMatchBenign(t *testing.T) {
	g := newTestGate(t, gateBasePackJSON)

	v := g.Match(FlowMeta{Host: "good.example", URL: "https://good.example/"})
	if v != nil {
		t.Fatalf("expected nil verdict for a benign flow, got %+v", v)
	}
}

// TestGateMatchNilLoaderNoPanic asserts the fail-open contract: a Gate whose
// loader is unusable (nil) must never panic the caller — a Sentinel bug must
// never break browsing. Match recovers internally and returns nil.
func TestGateMatchNilLoaderNoPanic(t *testing.T) {
	g := &Gate{loader: nil}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Match panicked instead of failing open: %v", r)
		}
	}()

	v := g.Match(FlowMeta{Host: "anything.example"})
	if v != nil {
		t.Fatalf("expected nil verdict from a broken gate, got %+v", v)
	}
}

// TestGateMatchHighestSeverityWins builds a flow that matches two different
// IOC types (domain severity 50, ja4 severity 90) and asserts the gate keeps
// the higher-severity hit rather than the first (cheaper) one it checks.
func TestGateMatchHighestSeverityWins(t *testing.T) {
	g := newTestGate(t, gateSeverityPackJSON)

	v := g.Match(FlowMeta{Host: "shared.example", JA4: "j4hash"})
	if v == nil {
		t.Fatal("expected a verdict, got nil")
	}
	if v.Severity != 90 {
		t.Fatalf("Severity = %d, want 90 (the ja4 hit, not the domain hit)", v.Severity)
	}
	if v.Class != ClassBotnetC2 {
		t.Fatalf("Class = %q, want %q", v.Class, ClassBotnetC2)
	}
	if v.Action != ActionBlock {
		t.Fatalf("Action = %q, want %q", v.Action, ActionBlock)
	}
	if v.Evidence["ioc_type"] != string(IOCJA4) || v.Evidence["ioc_value"] != "j4hash" || v.Evidence["source"] != "feed-b" {
		t.Fatalf("unexpected evidence: %+v", v.Evidence)
	}
}
