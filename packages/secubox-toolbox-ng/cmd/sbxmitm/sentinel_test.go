// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/sentinel"
)

// writeSentinelPack writes a base pack with a block-domain + a strip-hash IOC to
// a fresh temp dir and returns the dir.
func writeSentinelPack(t testing.TB) string {
	t.Helper()
	dir := t.TempDir()
	pack := `{"version":"1","iocs":[
		{"type":"domain","value":"c2.example","class":"botnet_c2","severity":95,"action":"block"},
		{"type":"file_sha256","value":"abc123","class":"malware","severity":90,"action":"strip"}
	]}`
	if err := os.WriteFile(filepath.Join(dir, "base.json"), []byte(pack), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// newTestHook builds an ENABLED hook over a real loader with no mirror.
func newTestHook(t testing.TB, baseDir string) *sentinelHook {
	t.Helper()
	loader, err := sentinel.NewLoader(baseDir, "")
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}
	return &sentinelHook{gate: sentinel.NewGate(loader), enabled: true}
}

func TestSentinelInspectBlock(t *testing.T) {
	h := newTestHook(t, writeSentinelPack(t))
	action, page := h.inspect(sentinel.FlowMeta{Host: "c2.example"}, nil)
	if action != sentinel.ActionBlock {
		t.Fatalf("want ActionBlock, got %q", action)
	}
	if len(page) == 0 {
		t.Fatal("block action must return a non-empty block page")
	}
	if !bytes.Contains(page, []byte("sbx-sentinel-blocked")) {
		t.Fatalf("block page missing machine-readable marker: %s", page)
	}
}

func TestSentinelInspectStrip(t *testing.T) {
	h := newTestHook(t, writeSentinelPack(t))
	action, page := h.inspect(sentinel.FlowMeta{Host: "cdn.example", FileSHA256: "abc123"}, []byte("malware-bytes"))
	if action != sentinel.ActionStrip {
		t.Fatalf("want ActionStrip, got %q", action)
	}
	if page != nil {
		t.Fatal("strip action must not return a block page (caller drops the body)")
	}
}

func TestSentinelInspectBenign(t *testing.T) {
	h := newTestHook(t, writeSentinelPack(t))
	action, page := h.inspect(sentinel.FlowMeta{Host: "good.example", URL: "https://good.example/p"}, nil)
	if action != sentinel.ActionReport {
		t.Fatalf("benign flow must be ActionReport, got %q", action)
	}
	if page != nil {
		t.Fatal("benign flow must not be blocked")
	}
}

func TestSentinelDisabledNoop(t *testing.T) {
	// A disabled hook is a transparent passthrough even for a would-be-blocked host.
	h := &sentinelHook{} // enabled == false
	action, page := h.inspect(sentinel.FlowMeta{Host: "c2.example"}, nil)
	if action != sentinel.ActionReport || page != nil {
		t.Fatalf("disabled hook must no-op passthrough, got action=%q page=%v", action, page)
	}

	// A nil hook (Proxy constructed without a sentinel) must also be safe.
	var nh *sentinelHook
	action, page = nh.inspect(sentinel.FlowMeta{Host: "c2.example"}, nil)
	if action != sentinel.ActionReport || page != nil {
		t.Fatalf("nil hook must no-op passthrough, got action=%q page=%v", action, page)
	}
}

func TestNewSentinelHookDisabledByDefault(t *testing.T) {
	t.Setenv("SENTINEL_ENABLED", "")
	h := newSentinelHook()
	if h.enabled {
		t.Fatal("SENTINEL_ENABLED unset must yield a disabled hook")
	}
	// Must be a safe no-op even though it holds no gate.
	if a, p := h.inspect(sentinel.FlowMeta{Host: "c2.example"}, nil); a != sentinel.ActionReport || p != nil {
		t.Fatal("disabled newSentinelHook must no-op")
	}
}

func TestNewSentinelHookFailOpenOnBadPack(t *testing.T) {
	// Enabled but the base pack is corrupt → NewLoader errors → fail-open disabled.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "base.json"), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SENTINEL_ENABLED", "1")
	t.Setenv("SENTINEL_PACK_DIR", dir)
	t.Setenv("SENTINEL_OVERLAY_DIR", "")
	t.Setenv("SENTINEL_MIRROR_SOCK", "")
	h := newSentinelHook()
	if h.enabled {
		t.Fatal("a corrupt base pack must fail-open to a disabled hook, not enable")
	}
}

// BenchmarkSentinelInspectMiss measures the hot-path cost of inspect() on the
// common benign flow (no IOC match, no mirror configured). Hot-path budget: a
// throttled loader MaybeReload (a time comparison after the first call) plus a
// handful of O(1)/O(log n) IOCSet map lookups; target single-digit µs and very
// low allocs. A configured mirror adds one bounded, non-blocking channel send.
func BenchmarkSentinelInspectMiss(b *testing.B) {
	h := newTestHook(b, writeSentinelPack(b))
	meta := sentinel.FlowMeta{
		Host:     "benign.example.com",
		URL:      "https://benign.example.com/index.html",
		ClientIP: "10.99.1.5",
		MacHash:  "deadbeefcafebabe",
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, page := h.inspect(meta, nil); page != nil {
			b.Fatal("benign flow unexpectedly blocked")
		}
	}
}
