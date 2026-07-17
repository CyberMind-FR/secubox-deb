// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: sbxwaf — WAF rule engine tests
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeRulesJSON writes a waf-rules.json to a temp file and returns the path.
// The caller is responsible for os.Remove (handled by t.TempDir).
func writeRulesJSON(t *testing.T, content any) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "waf-rules*.json")
	if err != nil {
		t.Fatalf("create temp: %v", err)
	}
	if err := json.NewEncoder(f).Encode(content); err != nil {
		t.Fatalf("encode rules: %v", err)
	}
	f.Close()
	return f.Name()
}

// buildRulesDoc constructs the canonical waf-rules.json shape used in tests.
// shape: {"categories": {"<cat_id>": {"name":..., "severity":..., "enabled":..., "patterns":[...]}}}
func buildRulesDoc(cats map[string]any) map[string]any {
	return map[string]any{"categories": cats}
}

// TestRulesMatchSQLi is the primary TDD test: a minimal SQLi category must fire
// on a UNION SELECT in the query and be silent for benign traffic.
func TestRulesMatchSQLi(t *testing.T) {
	doc := buildRulesDoc(map[string]any{
		"sqli": map[string]any{
			"name":     "SQL Injection",
			"severity": "high",
			"enabled":  true,
			"patterns": []any{
				map[string]any{"id": "sqli1", "pattern": `union\s+select`, "desc": "UNION SELECT"},
			},
		},
	})
	path := writeRulesJSON(t, doc)
	r := LoadRules(path)

	// Hit: query contains "union select" (Match decodes raw inputs internally)
	cat, sev, _, hit := r.Match("GET", "/x", "id=1+union+select", "", "")
	if !hit {
		t.Fatal("expected hit for UNION SELECT in query, got miss")
	}
	if cat != "sqli" {
		t.Fatalf("expected cat='sqli', got %q", cat)
	}
	if sev != "high" {
		t.Fatalf("expected sev='high', got %q", sev)
	}

	// Hit: uppercase variant (case-insensitive)
	_, _, _, hit = r.Match("GET", "/x", "id=1+UNION+SELECT", "", "")
	if !hit {
		t.Fatal("expected hit for uppercase UNION SELECT")
	}

	// Miss: benign request
	cat, sev, _, hit = r.Match("GET", "/", "q=hello", "", "Mozilla/5.0")
	if hit {
		t.Fatalf("expected miss for benign request, got hit cat=%q sev=%q", cat, sev)
	}
}

// TestRulesDisabledCategory ensures that a disabled category never fires.
func TestRulesDisabledCategory(t *testing.T) {
	doc := buildRulesDoc(map[string]any{
		"sqli": map[string]any{
			"name":     "SQL Injection",
			"severity": "high",
			"enabled":  false, // disabled
			"patterns": []any{
				map[string]any{"id": "sqli1", "pattern": `union\s+select`, "desc": "UNION SELECT"},
			},
		},
	})
	path := writeRulesJSON(t, doc)
	r := LoadRules(path)

	_, _, _, hit := r.Match("GET", "/x", "id=1 union select", "", "")
	if hit {
		t.Fatal("disabled category must never match")
	}
}

// TestRulesUncompilablePatternSkipped ensures a bad regex is skipped gracefully.
func TestRulesUncompilablePatternSkipped(t *testing.T) {
	doc := buildRulesDoc(map[string]any{
		"sqli": map[string]any{
			"name":     "SQL Injection",
			"severity": "high",
			"enabled":  true,
			"patterns": []any{
				// bad regex: unclosed group — RE2 will reject this
				map[string]any{"id": "bad1", "pattern": `(unclosed`, "desc": "bad"},
				// good regex that must still work after skipping the bad one
				map[string]any{"id": "sqli1", "pattern": `union\s+select`, "desc": "UNION SELECT"},
			},
		},
	})
	path := writeRulesJSON(t, doc)

	// Must not panic or crash
	r := LoadRules(path)

	// Good pattern must still fire
	_, _, _, hit := r.Match("GET", "/x", "id=1 union select", "", "")
	if !hit {
		t.Fatal("good pattern after a skipped bad one must still match")
	}
}

// TestRulesMatchInPath ensures match works in the decoded path (unquote_plus semantics).
func TestRulesMatchInPath(t *testing.T) {
	doc := buildRulesDoc(map[string]any{
		"lfi": map[string]any{
			"name":     "LFI",
			"severity": "critical",
			"enabled":  true,
			"patterns": []any{
				map[string]any{"id": "lfi1", "pattern": `etc/passwd`, "desc": "passwd access"},
			},
		},
	})
	path := writeRulesJSON(t, doc)
	r := LoadRules(path)

	// URL-encoded path: /..%2Fetc%2Fpasswd — after unquote_plus → /../etc/passwd
	_, _, _, hit := r.Match("GET", "/..%2Fetc%2Fpasswd", "", "", "")
	if !hit {
		t.Fatal("expected hit for URL-encoded etc/passwd in path")
	}
}

// TestRulesMatchInBody ensures match works against the request body.
func TestRulesMatchInBody(t *testing.T) {
	doc := buildRulesDoc(map[string]any{
		"rce": map[string]any{
			"name":     "RCE",
			"severity": "critical",
			"enabled":  true,
			"patterns": []any{
				map[string]any{"id": "rce1", "pattern": `\beval\s*\(`, "desc": "eval"},
			},
		},
	})
	path := writeRulesJSON(t, doc)
	r := LoadRules(path)

	_, _, _, hit := r.Match("POST", "/submit", "", "data=eval(base64_decode(xyz))", "")
	if !hit {
		t.Fatal("expected hit for eval( in body")
	}
}

// TestRulesMatchInUA ensures match works against the User-Agent string.
func TestRulesMatchInUA(t *testing.T) {
	doc := buildRulesDoc(map[string]any{
		"scanners": map[string]any{
			"name":     "Scanner UA",
			"severity": "medium",
			"enabled":  true,
			"patterns": []any{
				map[string]any{"id": "scan1", "pattern": `sqlmap`, "desc": "sqlmap scanner"},
			},
		},
	})
	path := writeRulesJSON(t, doc)
	r := LoadRules(path)

	_, _, _, hit := r.Match("GET", "/", "", "", "sqlmap/1.7")
	if !hit {
		t.Fatal("expected hit for sqlmap in User-Agent")
	}
}

// TestRulesDefaultEnabledTrue ensures that a category without an explicit
// "enabled" field is treated as enabled (Python: enabled = cat_data.get("enabled", True)).
func TestRulesDefaultEnabledTrue(t *testing.T) {
	doc := buildRulesDoc(map[string]any{
		"sqli": map[string]any{
			"name":     "SQL Injection",
			"severity": "high",
			// no "enabled" field — defaults to true
			"patterns": []any{
				map[string]any{"id": "sqli1", "pattern": `union\s+select`, "desc": "UNION SELECT"},
			},
		},
	})
	path := writeRulesJSON(t, doc)
	r := LoadRules(path)

	_, _, _, hit := r.Match("GET", "/x", "id=1 union select", "", "")
	if !hit {
		t.Fatal("category without explicit 'enabled' must default to enabled=true")
	}
}

// TestRulesDefaultSeverityMedium ensures that a category without "severity" defaults to "medium".
func TestRulesDefaultSeverityMedium(t *testing.T) {
	doc := buildRulesDoc(map[string]any{
		"custom": map[string]any{
			"name": "Custom",
			// no "severity" — defaults to "medium"
			"patterns": []any{
				map[string]any{"id": "c1", "pattern": `evil`, "desc": "evil keyword"},
			},
		},
	})
	path := writeRulesJSON(t, doc)
	r := LoadRules(path)

	_, sev, _, hit := r.Match("GET", "/evil", "", "", "")
	if !hit {
		t.Fatal("expected hit")
	}
	if sev != "medium" {
		t.Fatalf("expected default severity 'medium', got %q", sev)
	}
}

// TestRulesEmptyFile ensures that an empty/missing file does not crash and
// produces a functional (always-miss) Rules.
func TestRulesEmptyFile(t *testing.T) {
	r := LoadRules("/tmp/nonexistent-waf-rules-12345.json")

	// Must not panic; must return miss for everything.
	_, _, _, hit := r.Match("GET", "/", "id=1 union select 1,2,3", "", "")
	if hit {
		t.Fatal("LoadRules on missing file: Match should always miss")
	}
}

// TestRulesHotReload verifies that an mtime change triggers reload of new patterns.
func TestRulesHotReload(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/waf-rules.json"

	// Initial: no sqli rules (only xss), so a union select must miss.
	initial := buildRulesDoc(map[string]any{
		"xss": map[string]any{
			"name":     "XSS",
			"severity": "high",
			"enabled":  true,
			"patterns": []any{
				map[string]any{"id": "xss1", "pattern": `<script`, "desc": "script tag"},
			},
		},
	})
	data, _ := json.Marshal(initial)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write initial: %v", err)
	}

	r := LoadRules(path)

	// SQLi should miss before reload.
	_, _, _, hit := r.Match("GET", "/", "id=1 union select", "", "")
	if hit {
		t.Fatal("before reload: union select should miss (no sqli rules loaded)")
	}

	// XSS should fire.
	_, _, _, hit = r.Match("GET", "/<script>", "", "", "")
	if !hit {
		t.Fatal("before reload: script tag in path should hit xss")
	}

	// Write updated file that adds sqli rules.
	updated := buildRulesDoc(map[string]any{
		"xss": map[string]any{
			"name":     "XSS",
			"severity": "high",
			"enabled":  true,
			"patterns": []any{
				map[string]any{"id": "xss1", "pattern": `<script`, "desc": "script tag"},
			},
		},
		"sqli": map[string]any{
			"name":     "SQL Injection",
			"severity": "critical",
			"enabled":  true,
			"patterns": []any{
				map[string]any{"id": "sqli1", "pattern": `union\s+select`, "desc": "UNION SELECT"},
			},
		},
	})
	data, _ = json.Marshal(updated)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write updated: %v", err)
	}

	// Bump mtime so the watcher detects the change (filesystem granularity can be 1s).
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	// Trigger reload — throttle=0 so Maybe() fires immediately.
	r.Maybe()

	// Now sqli should fire.
	cat, sev, _, hit := r.Match("GET", "/", "id=1 union select", "", "")
	if !hit {
		t.Fatal("after reload: union select should hit sqli")
	}
	if cat != "sqli" {
		t.Fatalf("after reload: expected cat='sqli', got %q", cat)
	}
	if sev != "critical" {
		t.Fatalf("after reload: expected sev='critical', got %q", sev)
	}
}

// writeRulesFile writes a waf-rules.json with the given categories body and returns its path.
func writeRulesFile(t *testing.T, categories string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "waf-rules.json")
	body := `{"_meta":{"version":"test"},"categories":` + categories + `}`
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatalf("write rules: %v", err)
	}
	return p
}

// catMode returns the compiled mode for category id, or "" if absent.
func catMode(r *Rules, id string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, c := range r.current.cats {
		if c.id == id {
			return c.data.mode
		}
	}
	return ""
}

// A category with no "mode" MUST block. This is the most important test in the
// file: a detect default would silently disarm all 17 existing categories.
func TestModeAbsentDefaultsToBlock(t *testing.T) {
	p := writeRulesFile(t, `{"sqli":{"name":"SQLi","severity":"critical",
		"patterns":[{"id":"sqli-001","pattern":"union select","desc":"x"}]}}`)
	r := LoadRules(p)
	if got := catMode(r, "sqli"); got != modeBlock {
		t.Fatalf("absent mode: got %q, want %q", got, modeBlock)
	}
}

func TestModeBlockExplicit(t *testing.T) {
	p := writeRulesFile(t, `{"sqli":{"name":"SQLi","mode":"block",
		"patterns":[{"id":"sqli-001","pattern":"union select","desc":"x"}]}}`)
	if got := catMode(LoadRules(p), "sqli"); got != modeBlock {
		t.Fatalf("got %q, want %q", got, modeBlock)
	}
}

func TestModeDetectIsParsed(t *testing.T) {
	p := writeRulesFile(t, `{"cve_2024":{"name":"CVE","mode":"detect",
		"patterns":[{"id":"cve-1","pattern":"/mgmt/tm/util/bash","desc":"x"}]}}`)
	if got := catMode(LoadRules(p), "cve_2024"); got != modeDetect {
		t.Fatalf("got %q, want %q", got, modeDetect)
	}
}

// A typo must NOT disarm the category and must NOT become detect: fail closed.
func TestModeUnknownFailsClosedToBlock(t *testing.T) {
	for _, bad := range []string{"monitor", "dryrun", "BLOCK ", "xyz"} {
		p := writeRulesFile(t, `{"sqli":{"name":"SQLi","mode":"`+bad+`",
			"patterns":[{"id":"sqli-001","pattern":"union select","desc":"x"}]}}`)
		r := LoadRules(p)
		if got := catMode(r, "sqli"); got != modeBlock {
			t.Fatalf("mode %q: got %q, want %q (must fail closed)", bad, got, modeBlock)
		}
		// And the category must still be evaluated — a typo must not remove protection.
		if _, _, _, hit := r.Match("GET", "/x", "q=union+select", "", ""); !hit {
			t.Fatalf("mode %q: category was dropped; a typo must not disable a rule", bad)
		}
	}
}

// "" and null are "absent", not errors.
func TestModeEmptyAndNullDefaultToBlock(t *testing.T) {
	for _, body := range []string{`"mode":"",`, `"mode":null,`} {
		p := writeRulesFile(t, `{"sqli":{"name":"SQLi",`+body+`
			"patterns":[{"id":"sqli-001","pattern":"union select","desc":"x"}]}}`)
		if got := catMode(LoadRules(p), "sqli"); got != modeBlock {
			t.Fatalf("%s got %q, want %q", body, got, modeBlock)
		}
	}
}

// enabled:false wins over mode — the category is not evaluated at all.
func TestEnabledFalseWinsOverMode(t *testing.T) {
	p := writeRulesFile(t, `{"sqli":{"name":"SQLi","enabled":false,"mode":"detect",
		"patterns":[{"id":"sqli-001","pattern":"union select","desc":"x"}]}}`)
	r := LoadRules(p)
	if got := catMode(r, "sqli"); got != "" {
		t.Fatalf("disabled category should not be loaded at all, got mode %q", got)
	}
	if _, _, _, hit := r.Match("GET", "/x", "q=union+select", "", ""); hit {
		t.Fatal("disabled category must not match")
	}
}
