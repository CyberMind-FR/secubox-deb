// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/sentinel"
)

// TestBuildAnalyzersReturnsThree asserts the production analyzer construction
// wires exactly the three real engines (spyware, the behavioral engine
// wrapped in the #826 C2 auto-learn orchestrator, YARA) — this is the path
// defaultConfig()/main() use, distinct from the tests' injected stubAnalyzer
// path.
func TestBuildAnalyzersReturnsThree(t *testing.T) {
	// Empty/missing dirs are best-effort (no error) — NewLoader tolerates
	// them — so the happy path returns all three analyzers with no error.
	analyzers, err := buildAnalyzers("", "", nil)
	if err != nil {
		t.Fatalf("buildAnalyzers returned error on empty dirs: %v", err)
	}
	if len(analyzers) != 3 {
		t.Fatalf("expected 3 analyzers, got %d", len(analyzers))
	}

	var haveSpyware, haveC2Learner, haveYara bool
	for _, a := range analyzers {
		switch a.(type) {
		case *sentinel.Spyware:
			haveSpyware = true
		case *sentinel.C2Learner:
			haveC2Learner = true
		case *sentinel.YaraEngine:
			haveYara = true
		}
	}
	if !haveSpyware || !haveC2Learner || !haveYara {
		t.Fatalf("missing an analyzer type: spyware=%v c2learner=%v yara=%v", haveSpyware, haveC2Learner, haveYara)
	}
}

// TestBuildAnalyzersLoadsBasePack asserts buildAnalyzers actually wires a
// working pack Loader into the spyware analyzer: a base pack on disk with a
// known spyware domain produces a verdict for a matching mirrored flow.
func TestBuildAnalyzersLoadsBasePack(t *testing.T) {
	dir := t.TempDir()
	pack := `{"version":"1","iocs":[{"type":"domain","value":"pegasus.example","class":"spyware_pegasus","severity":95,"source":"amnesty-mvt","action":"block"}]}`
	if err := os.WriteFile(filepath.Join(dir, "base.json"), []byte(pack), 0o644); err != nil {
		t.Fatal(err)
	}

	analyzers, err := buildAnalyzers(dir, "", nil)
	if err != nil {
		t.Fatalf("buildAnalyzers: %v", err)
	}

	msg := sentinel.MirrorMsg{Meta: sentinel.FlowMeta{Host: "pegasus.example", MacHash: "dev1"}}
	var got *sentinel.Verdict
	for _, a := range analyzers {
		if vs := a.Analyze(msg); len(vs) > 0 {
			got = vs[0]
			break
		}
	}
	if got == nil {
		t.Fatal("expected a verdict from the spyware analyzer for a known base-pack domain")
	}
	if got.Class != sentinel.ClassSpywarePegasus {
		t.Fatalf("unexpected class: %v", got.Class)
	}
}

// TestDefaultConfigWiresPipeline asserts defaultConfig() (the main() path)
// produces a runnable Config with the analyzer pipeline populated.
func TestDefaultConfigWiresPipeline(t *testing.T) {
	// Point the pack dir at a temp (empty) dir so we don't depend on the
	// installed /usr/share path in a CI sandbox.
	t.Setenv("SENTINEL_PACK_DIR", t.TempDir())
	t.Setenv("SENTINEL_OVERLAY_DIR", t.TempDir())
	t.Setenv("SENTINEL_TTL", "24h")

	cfg := defaultConfig()
	if len(cfg.Analyzers) != 3 {
		t.Fatalf("expected 3 analyzers wired, got %d", len(cfg.Analyzers))
	}
	if cfg.TTL.Hours() != 24 {
		t.Fatalf("expected TTL 24h from env, got %s", cfg.TTL)
	}
	if cfg.SocketPath == "" || cfg.DBPath == "" {
		t.Fatal("expected socket + db paths defaulted")
	}
}
