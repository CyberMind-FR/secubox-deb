// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: sbxwaf — WAF decision parity harness
//
// TestWAFParity loads the production waf-rules.json (copied to testdata/) and
// the fixture corpus (testdata/waf-parity-fixtures.json), then replays each
// fixture through the exact decision path the production handler uses:
//
//  1. privateCIDR(ip) → verdict "skip"
//  2. staticAsset(path) → verdict "skip"
//  3. ncBypass(path) → verdict "skip"
//  4. Rules.Match(method, rawPath, rawQuery, body, ua)
//     → no hit → verdict "allow"
//     → hit → ban.Record(ip, now) → count<3 → "warn" / count>=3 → "ban"
//
// Each fixture's "expect" field must equal the computed verdict. Mismatches
// FAIL the test immediately with fixture name, expected, and got.
//
// Fixtures flagged "known_gap": true are EXPECTED to return "allow" (the Go
// engine skips the null-byte RE2 patterns that Python would catch). These rows
// are asserted against their documented gap behaviour AND log a visible
// "KNOWN GAP" line so coverage loss is never silent.
//
// Ban sequencing: fixtures sharing the same client_ip are processed in JSON
// order; the ban counter accumulates across all fixture rows for that IP.
// Fixtures with "_ban_sequence" > 1 rely on prior fixture rows having already
// been processed for the same client_ip.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// parityFixture is one row in waf-parity-fixtures.json.
type parityFixture struct {
	// Fixture identity
	Name string `json:"name"`

	// HTTP request parameters (raw, not decoded)
	Method   string `json:"method"`
	Path     string `json:"path"`
	Query    string `json:"query"`
	Body     string `json:"body"`
	UA       string `json:"ua"`
	ClientIP string `json:"client_ip"`

	// Expected verdict: "allow" | "warn" | "ban" | "skip"
	Expect string `json:"expect"`

	// KnownGap marks this fixture as a documented gap (RE2 null-byte patterns
	// that Python catches but Go cannot compile). The test asserts the current
	// (gap) behaviour and logs a visible KNOWN GAP line.
	KnownGap bool `json:"known_gap"`
}

// testdataPath returns the absolute path to testdata/ relative to this test
// file, so the test works regardless of the working directory go test uses.
func testdataPath(name string) string {
	_, file, _, _ := runtime.Caller(0)
	dir := filepath.Dir(file)
	return filepath.Join(dir, "..", "..", "testdata", name)
}

// TestWAFParity is the decision parity harness:
//   - Loads the production waf-rules.json from testdata/
//   - Loads testdata/waf-parity-fixtures.json
//   - Replays each fixture through the real decision path
//   - Fails the test on any unexpected mismatch
//   - Logs KNOWN GAP lines for documented gaps without failing
func TestWAFParity(t *testing.T) {
	// Load production WAF rules.
	rulesPath := testdataPath("waf-rules.json")
	rules := LoadRules(rulesPath)

	// Load fixture corpus.
	fixturesPath := testdataPath("waf-parity-fixtures.json")
	fixtureData, err := os.ReadFile(fixturesPath)
	if err != nil {
		t.Fatalf("read fixtures %q: %v", fixturesPath, err)
	}
	var fixtures []parityFixture
	if err := json.Unmarshal(fixtureData, &fixtures); err != nil {
		t.Fatalf("parse fixtures %q: %v", fixturesPath, err)
	}
	if len(fixtures) == 0 {
		t.Fatal("fixture corpus is empty — check testdata/waf-parity-fixtures.json")
	}
	t.Logf("Loaded %d fixtures from %s", len(fixtures), fixturesPath)

	// Shared ban state: accumulates across the entire test run so that
	// ban-sequence fixtures (hit1 → hit2 → hit3 for the same IP) correctly
	// drive the ban counter to threshold.
	ban := NewBan(300*time.Second, 3)

	// Counters for summary.
	var (
		pass     int
		fail     int
		skip     int
		gapCount int
	)

	// Fixed timestamp for all Ban.Record calls so the sliding window never
	// expires mid-test. Using a constant avoids flakiness on slow CI.
	now := time.Now().Unix()

	for _, fx := range fixtures {
		fx := fx // capture for t.Run closure
		t.Run(fx.Name, func(t *testing.T) {
			got := runDecision(rules, ban, fx, now)

			if fx.KnownGap {
				// Document the gap but do NOT fail.
				gapCount++
				t.Logf("KNOWN GAP [%s]: expect=%q (gap behaviour), got=%q", fx.Name, fx.Expect, got)
				if got != fx.Expect {
					// The gap behaviour changed — surface it as a failure so we notice
					// if the gap is accidentally fixed or accidentally regressed.
					t.Errorf("KNOWN GAP [%s]: gap behaviour changed — expected gap result %q, got %q; "+
						"if the pattern now compiles under RE2, remove known_gap:true from the fixture",
						fx.Name, fx.Expect, got)
					fail++
				} else {
					pass++
				}
				return
			}

			if got == "skip" && fx.Expect == "skip" {
				skip++
				pass++
				return
			}

			if got != fx.Expect {
				fail++
				t.Errorf("PARITY MISMATCH [%s]: expected=%q got=%q (method=%q path=%q query=%q ip=%q ua=%q)",
					fx.Name, fx.Expect, got,
					fx.Method, fx.Path, fx.Query, fx.ClientIP, fx.UA)
				if fx.Expect == "warn" && got == "allow" {
					t.Logf("  → BLOCKING: Go engine MISSED a payload Python WAF would catch — "+
						"check rules.go / waf-rules.json pattern for this fixture")
				}
				return
			}
			pass++
		})
	}

	// Summary log.
	t.Logf("WAFParity summary: %d fixtures, %d pass, %d fail, %d skip, %d known-gap",
		len(fixtures), pass, fail, skip, gapCount)

	if fail > 0 {
		t.Errorf("WAFParity: %d fixtures failed — see individual test output above", fail)
	}
}

// runDecision runs the exact same decision path as the production handler
// (inspect.go + rules.go + ban.go) and returns a verdict string:
//
//	"skip"  — privateCIDR / staticAsset / ncBypass fired
//	"allow" — WAF miss (no pattern matched)
//	"warn"  — WAF hit, ban count below threshold (< 3)
//	"ban"   — WAF hit, ban count reached threshold (>= 3)
//
// The function is called in fixture order so ban state accumulates across
// fixtures sharing the same client_ip.
func runDecision(rules *Rules, ban *Ban, fx parityFixture, now int64) string {
	// Step 1: private CIDR bypass (mirrors Python _is_whitelisted / _WL_NETS).
	if privateCIDR(fx.ClientIP) {
		return "skip"
	}

	// Step 2: static asset skip.
	if staticAsset(fx.Path) {
		return "skip"
	}

	// Step 3: Nextcloud mobile auth bypass.
	if ncBypass(fx.Path) {
		return "skip"
	}

	// Step 4: WAF rule matching.
	// rawPath and rawQuery are passed as-is; Rules.Match applies unquote_plus
	// internally (matches Python urllib.parse.unquote_plus in check_request).
	_, _, hit := rules.Match(fx.Method, fx.Path, fx.Query, fx.Body, fx.UA)
	if !hit {
		return "allow"
	}

	// Step 5: graduated ban (mirrors Python BAN_THRESHOLD=3 / BAN_WINDOW=300s).
	count, banned := ban.Record(fx.ClientIP, now)
	_ = count
	if banned {
		return "ban"
	}
	return "warn"
}

// TestWAFParityFixtureCount is a lightweight sanity check: the fixture corpus
// must have at least 30 rows and cover all expected categories.
func TestWAFParityFixtureCount(t *testing.T) {
	fixturesPath := testdataPath("waf-parity-fixtures.json")
	data, err := os.ReadFile(fixturesPath)
	if err != nil {
		t.Fatalf("read fixtures: %v", err)
	}
	var fixtures []parityFixture
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatalf("parse fixtures: %v", err)
	}

	const minFixtures = 30
	if len(fixtures) < minFixtures {
		t.Errorf("fixture corpus has %d rows, want at least %d", len(fixtures), minFixtures)
	}

	// Verify all expects are valid values.
	validExpects := map[string]bool{"allow": true, "warn": true, "ban": true, "skip": true}
	for _, fx := range fixtures {
		if fx.Name == "" {
			t.Errorf("fixture missing name field")
		}
		if !validExpects[fx.Expect] {
			t.Errorf("fixture %q has invalid expect value %q", fx.Name, fx.Expect)
		}
	}

	// Verify category coverage.
	wantExpects := map[string]int{"allow": 0, "warn": 0, "ban": 0, "skip": 0}
	knownGaps := 0
	for _, fx := range fixtures {
		wantExpects[fx.Expect]++
		if fx.KnownGap {
			knownGaps++
		}
	}

	t.Logf("Fixture breakdown: allow=%d warn=%d ban=%d skip=%d known_gap=%d total=%d",
		wantExpects["allow"], wantExpects["warn"], wantExpects["ban"],
		wantExpects["skip"], knownGaps, len(fixtures))

	for verdict, count := range wantExpects {
		if count == 0 {
			t.Errorf("no fixtures for expect=%q — corpus must cover all verdict types", verdict)
		}
	}
	if knownGaps == 0 {
		t.Errorf("no known_gap fixtures — must document the RE2 null-byte gap from cve_voip/cve_xmpp")
	}

	t.Logf("WAFParityFixtureCount: OK — %d fixtures", len(fixtures))
}

// TestWAFParityRulesLoad verifies the production rules file loads without error
// and compiles all non-gap patterns. This catches regressions in rules.go or
// changes to waf-rules.json that break compilation.
func TestWAFParityRulesLoad(t *testing.T) {
	rulesPath := testdataPath("waf-rules.json")
	rules := LoadRules(rulesPath)

	// Probe with a known-good payload to confirm the rules are live.
	_, _, hit := rules.Match("GET", "/search", "q=union+select+1,2,3", "", "")
	if !hit {
		t.Errorf("rules loaded from %q but union+select did not match — check waf-rules.json", rulesPath)
	}

	// Probe with a benign request to confirm no false positive on load.
	_, _, fp := rules.Match("GET", "/", "q=hello+world", "", "Mozilla/5.0")
	if fp {
		t.Errorf("false positive on benign request after loading %q", rulesPath)
	}

	t.Logf("WAFParityRulesLoad: production rules from %q loaded and functional", rulesPath)
}

// BenchmarkWAFParityDecision benchmarks the runDecision hot path to catch
// performance regressions in the rule engine.
func BenchmarkWAFParityDecision(b *testing.B) {
	rulesPath := testdataPath("waf-rules.json")
	rules := LoadRules(rulesPath)
	ban := NewBan(300*time.Second, 3)
	now := time.Now().Unix()

	// Use a representative attack fixture.
	fx := parityFixture{
		Method:   "GET",
		Path:     "/search",
		Query:    "q=1+union+select+1,2,3",
		Body:     "",
		UA:       "Mozilla/5.0",
		ClientIP: fmt.Sprintf("bench-%d", b.N), // unique IP per bench run to avoid ban state
		Expect:   "warn",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fx.ClientIP = fmt.Sprintf("bench-%d", i) // fresh IP per iteration
		_ = runDecision(rules, ban, fx, now)
	}
}
