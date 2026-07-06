// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package sentinel

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

const basePackJSON = `{
  "version": "1",
  "iocs": [
    {"type": "domain", "value": "c2.example", "class": "botnet_c2", "severity": 90, "action": "block"}
  ]
}`

const overlayPackJSON = `{
  "version": "live-1",
  "iocs": [
    {"type": "domain", "value": "pegasus.example", "class": "spyware_pegasus", "severity": 100, "action": "block"}
  ]
}`

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// touch bumps a file's mtime forward so a subsequent MaybeReload detects the
// change even when the filesystem's mtime resolution is coarse.
func touch(t *testing.T, path string, delta time.Duration) {
	t.Helper()
	newTime := time.Now().Add(delta)
	if err := os.Chtimes(path, newTime, newTime); err != nil {
		t.Fatal(err)
	}
}

func TestLoadBasePack(t *testing.T) {
	dir := t.TempDir()
	basePath := filepath.Join(dir, "base.json")
	writeFile(t, basePath, basePackJSON)

	pk, err := LoadBasePack(basePath)
	if err != nil {
		t.Fatal(err)
	}
	if pk.Version != "1" {
		t.Fatalf("version = %q, want %q", pk.Version, "1")
	}
	if len(pk.IOCs) != 1 || pk.IOCs[0].Value != "c2.example" {
		t.Fatalf("unexpected IOCs: %+v", pk.IOCs)
	}
}

func TestLoadBasePackMissingFile(t *testing.T) {
	if _, err := LoadBasePack("/nonexistent/path/pack.json"); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadBasePackCorruptJSON(t *testing.T) {
	dir := t.TempDir()
	badPath := filepath.Join(dir, "bad.json")
	writeFile(t, badPath, `{not valid json`)

	if _, err := LoadBasePack(badPath); err == nil {
		t.Fatal("expected error for corrupt JSON")
	}
}

func TestMergePacksOverridesByTypeAndValue(t *testing.T) {
	base := &Pack{
		IOCs: []IOC{
			{Type: IOCDomain, Value: "c2.example", Class: ClassBotnetC2, Severity: 90, Action: ActionBlock},
		},
	}
	overlay := &Pack{
		IOCs: []IOC{
			// Same (Type,Value) as base — overlay must win.
			{Type: IOCDomain, Value: "c2.example", Class: ClassSpywarePegasus, Severity: 100, Action: ActionReport},
			{Type: IOCDomain, Value: "pegasus.example", Class: ClassSpywarePegasus, Severity: 100, Action: ActionBlock},
		},
	}

	set := MergePacks(base, overlay)
	m, ok := set.MatchDomain("c2.example")
	if !ok || m.Class != ClassSpywarePegasus || m.Action != ActionReport {
		t.Fatalf("overlay did not override base: %+v", m)
	}
	if _, ok := set.MatchDomain("pegasus.example"); !ok {
		t.Fatal("overlay-only entry missing")
	}
}

func TestMergePacksNilSafe(t *testing.T) {
	set := MergePacks(nil, nil, &Pack{IOCs: []IOC{
		{Type: IOCDomain, Value: "x.example", Class: ClassMalware, Action: ActionBlock},
	}}, nil)
	if _, ok := set.MatchDomain("x.example"); !ok {
		t.Fatal("expected entry from the one non-nil overlay")
	}
}

// TestLoaderBaseOnly covers the brief's Step 1 scenario: a base pack loads
// and matches with no overlay directory configured.
func TestLoaderBaseOnly(t *testing.T) {
	baseDir := t.TempDir()
	writeFile(t, filepath.Join(baseDir, "base.json"), basePackJSON)

	l, err := NewLoader(baseDir, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := l.Set().MatchDomain("c2.example"); !ok {
		t.Fatal("base pack IOC did not load")
	}
}

// TestLoaderOverlayHotReload: adding an overlay pack file and calling
// MaybeReload picks it up without disturbing the base pack's entries.
func TestLoaderOverlayHotReload(t *testing.T) {
	baseDir := t.TempDir()
	overlayDir := t.TempDir()
	writeFile(t, filepath.Join(baseDir, "base.json"), basePackJSON)

	l, err := NewLoader(baseDir, overlayDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := l.Set().MatchDomain("c2.example"); !ok {
		t.Fatal("base pack IOC missing before overlay")
	}
	if _, ok := l.Set().MatchDomain("pegasus.example"); ok {
		t.Fatal("overlay IOC present before it was even written")
	}

	overlayPath := filepath.Join(overlayDir, "live.json")
	writeFile(t, overlayPath, overlayPackJSON)
	touch(t, overlayPath, time.Second)

	l.MaybeReload()

	if _, ok := l.Set().MatchDomain("c2.example"); !ok {
		t.Fatal("base pack IOC lost after reload")
	}
	if _, ok := l.Set().MatchDomain("pegasus.example"); !ok {
		t.Fatal("overlay pack IOC not picked up by MaybeReload")
	}
}

// TestLoaderCorruptOverlayIgnored: a corrupt overlay file must never panic
// MaybeReload and must never wipe out the previously-good merged set (base +
// any still-valid overlays).
func TestLoaderCorruptOverlayIgnored(t *testing.T) {
	baseDir := t.TempDir()
	overlayDir := t.TempDir()
	writeFile(t, filepath.Join(baseDir, "base.json"), basePackJSON)

	overlayPath := filepath.Join(overlayDir, "live.json")
	writeFile(t, overlayPath, overlayPackJSON)

	l, err := NewLoader(baseDir, overlayDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := l.Set().MatchDomain("pegasus.example"); !ok {
		t.Fatal("overlay pack IOC did not load at construction")
	}

	corruptPath := filepath.Join(overlayDir, "corrupt.json")
	writeFile(t, corruptPath, `{ this is not json`)
	touch(t, corruptPath, time.Second)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("MaybeReload panicked on corrupt overlay: %v", r)
		}
	}()
	l.MaybeReload()

	if _, ok := l.Set().MatchDomain("c2.example"); !ok {
		t.Fatal("base pack IOC lost after corrupt overlay reload")
	}
	if _, ok := l.Set().MatchDomain("pegasus.example"); !ok {
		t.Fatal("prior-good overlay IOC lost after corrupt overlay reload")
	}
}

// TestLoaderMaybeReloadNoopWhenUnchanged: calling MaybeReload with nothing on
// disk changed must be a cheap no-op — the returned set stays functionally
// identical (same pointer is not required, but content must be stable).
func TestLoaderMaybeReloadNoopWhenUnchanged(t *testing.T) {
	baseDir := t.TempDir()
	overlayDir := t.TempDir()
	writeFile(t, filepath.Join(baseDir, "base.json"), basePackJSON)

	l, err := NewLoader(baseDir, overlayDir)
	if err != nil {
		t.Fatal(err)
	}
	before := l.Set()
	l.MaybeReload()
	l.MaybeReload()
	after := l.Set()
	if before != after {
		t.Fatal("MaybeReload swapped the set even though nothing on disk changed")
	}
}

func TestLoaderYaraRules(t *testing.T) {
	baseDir := t.TempDir()
	overlayDir := t.TempDir()
	writeFile(t, filepath.Join(baseDir, "base.json"), `{
		"version": "1",
		"iocs": [],
		"yara_rules": ["rule base_rule { condition: true }"]
	}`)
	writeFile(t, filepath.Join(overlayDir, "live.json"), `{
		"version": "live-1",
		"iocs": [],
		"yara_rules": ["rule overlay_rule { condition: true }"]
	}`)

	l, err := NewLoader(baseDir, overlayDir)
	if err != nil {
		t.Fatal(err)
	}
	rules := l.YaraRules()
	if len(rules) != 2 {
		t.Fatalf("YaraRules() = %v, want 2 entries", rules)
	}
}

func TestNewLoaderMissingBaseDirIsNotFatal(t *testing.T) {
	// An empty/non-existent base directory is best-effort (fail-safe), not a
	// hard error — mirrors LoadPolicy's best-effort philosophy for missing
	// backing files.
	dir := t.TempDir()
	l, err := NewLoader(filepath.Join(dir, "does-not-exist"), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := l.Set().MatchDomain("anything.example"); ok {
		t.Fatal("expected empty set")
	}
}

func TestNewLoaderCorruptBaseFails(t *testing.T) {
	baseDir := t.TempDir()
	writeFile(t, filepath.Join(baseDir, "base.json"), `{ not json`)

	if _, err := NewLoader(baseDir, ""); err == nil {
		t.Fatal("expected error constructing Loader from a corrupt base pack")
	}
}
