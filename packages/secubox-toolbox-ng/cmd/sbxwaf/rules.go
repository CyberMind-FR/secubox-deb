// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: sbxwaf — WAF rule engine (waf-rules.json)
//
// Ported from packages/secubox-mitmproxy/addons/secubox_waf.py:
//   - load_rules (~line 727): parse categories, compile patterns case-insensitively
//   - check_request (~line 758): match against decoded path / query / body / UA
//
// JSON shape (packages/secubox-waf/config/waf-rules.json):
//
//	{
//	  "categories": {
//	    "<cat_id>": {
//	      "name":     string,
//	      "severity": "low"|"medium"|"high"|"critical",   // default "medium"
//	      "enabled":  bool,                                // default true
//	      "patterns": [{"id": string, "pattern": string, "desc": string}, ...]
//	    }
//	  }
//	}
//
// Loading semantics (mirrors Python):
//   - A category where enabled == false is skipped entirely.
//   - Each "pattern" string is compiled as "(?i)"+pattern (case-insensitive).
//     Go uses RE2; patterns that fail to compile (e.g., lookaheads, backrefs)
//     are SKIPPED with a log.Printf — not fatal (mirrors Python's except re.error: pass).
//   - Severity is per-category; every pattern in the category inherits it.
//
// Match semantics (mirrors Python check_request):
//   - Match(method, rawPath, rawQuery, body, ua) accepts RAW (URL-encoded)
//     path and query strings; it applies unquote_plus-equivalent decoding
//     internally before scanning, matching Python's urllib.parse.unquote_plus
//     behaviour ('+' → space, then percent-unescape).
//   - The scan target is: decoded(path) + " " + decoded(query) + " " + body + " " + ua,
//     all lowercased, concatenated with spaces (mirrors Python's scan_text).
//   - Pattern iteration: categories in insertion order, patterns within each
//     category in insertion order. First match wins; returns cat, sev, hit=true.
//     No match → "", "", false.
//
// Hot-reload: mirrors routes.go — reload.NewWatcher(throttle=0, target) with
// throttle=0 so tests that call Maybe() trigger an immediate reload.  Production
// code can layer its own rate gate (same pattern as Routes.Maybe()).
//
// RE2 vs Python regex gap (checked against packages/secubox-waf/config/waf-rules.json):
//
//	All 50+ patterns in the production rules file compile under RE2 without
//	errors — none use lookaheads, lookbehinds, or backreferences.  The
//	skip-on-compile-error path is a safety net; it does not suppress any
//	production rule.  If future rules add unsupported syntax, they will be
//	skipped and logged.
package main

import (
	"encoding/json"
	"log"
	"net/url"
	"os"
	"strings"
	"sync"

	"regexp"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/reload"
)

// Rule evaluation modes for a category.
//
//	modeBlock  — a match blocks the request (the historical, only behaviour).
//	modeDetect — a match is counted and logged, the request PASSES, and nothing
//	             is banned. Lets an operator try a rule against real traffic
//	             before arming it.
//	modeEscalate — a match is observed first; after N occurrences from the same
//	              source within a time window, the source is banned. Intermediate
//	              protection: observe persistent scanners, block them, but allow
//	              transient false positives.
//
// A category with no "mode" is modeBlock. A detect default would silently turn
// the whole WAF into an observer — a mute security outage.
const (
	modeBlock    = "block"
	modeDetect   = "detect"
	modeEscalate = "escalate"
)

// compiledPattern holds a compiled regex and its metadata.
type compiledPattern struct {
	id   string
	re   *regexp.Regexp
	desc string
	// severity is inherited from the parent category at compile time.
	severity string
}

// compiledCategory is one loaded WAF category with all its compiled patterns.
type compiledCategory struct {
	name     string
	severity string
	mode     string // modeBlock | modeDetect — never empty after loadFile
	patterns []compiledPattern
}

// rulesData is the hot-swappable payload — a slice of categories in the order
// they were loaded from JSON (Go 1.22+ map iteration is random, so we preserve
// order via a separate ordered slice rather than a map, matching Python which
// iterates dict items in insertion order).
type rulesData struct {
	// ordered list of (cat_id, compiledCategory) pairs.
	cats []struct {
		id   string
		data compiledCategory
	}
}

// Rules is a hot-reloadable, RW-locked WAF rule set.
// Create with LoadRules; call Match on the hot path; call Maybe() to pick up
// on-disk changes (throttle=0 → eager, same as Routes).
type Rules struct {
	mu      sync.RWMutex
	current *rulesData

	// watcher handles mtime tracking + Apply callbacks.
	watcher *reload.Watcher
}

// loadRulesJSON parses waf-rules.json and compiles all enabled patterns.
// Returns an empty (never-matching) rulesData on any parse/file error.
// Individual patterns that fail to compile are skipped with a log.Printf.
func loadRulesJSON(path string) *rulesData {
	data := &rulesData{}

	raw, err := os.ReadFile(path)
	if err != nil {
		// Missing file is best-effort — return empty rules (always-miss).
		return data
	}

	// Parse outer wrapper: expect {"categories": {...}}.
	// We use a two-level decode: outer is map[string]json.RawMessage so we can
	// handle the optional "_meta" key without failing.
	var outer map[string]json.RawMessage
	if err := json.Unmarshal(raw, &outer); err != nil {
		log.Printf("sbxwaf/rules: parse %s outer: %v", path, err)
		return data
	}

	catRaw, ok := outer["categories"]
	if !ok {
		// No "categories" key — treat as empty.
		return data
	}

	// Parse categories as map[string]json.RawMessage to preserve per-category
	// raw bytes while we iterate.  Order is randomised by Go's map; to preserve
	// deterministic ordering (and match Python's dict insertion order on >=3.7),
	// we use a json.Decoder to iterate tokens in order.
	type patternJSON struct {
		ID      string `json:"id"`
		Pattern string `json:"pattern"`
		Desc    string `json:"desc"`
	}
	type categoryJSON struct {
		Name     string        `json:"name"`
		Severity string        `json:"severity"`
		Enabled  *bool         `json:"enabled"` // pointer: nil means absent (default true)
		Mode     *string       `json:"mode"`    // pointer: nil means absent (default block)
		Patterns []patternJSON `json:"patterns"`
	}

	// Use a simple ordered parse: json.Decoder over the categories object,
	// reading key-value pairs in order.
	dec := json.NewDecoder(strings.NewReader(string(catRaw)))

	// Consume the opening '{'.
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		log.Printf("sbxwaf/rules: categories is not a JSON object in %s", path)
		return data
	}

	total := 0
	for dec.More() {
		// Read category ID key.
		keyTok, err := dec.Token()
		if err != nil {
			break
		}
		catID, ok := keyTok.(string)
		if !ok {
			continue
		}

		// Decode the category value.
		var cat categoryJSON
		if err := dec.Decode(&cat); err != nil {
			log.Printf("sbxwaf/rules: skipping category %q: %v", catID, err)
			continue
		}

		// Default: enabled=true when the field is absent.
		if cat.Enabled != nil && !*cat.Enabled {
			continue
		}

		// Default severity.
		sev := cat.Severity
		if sev == "" {
			sev = "medium"
		}

		// Resolve the evaluation mode. Absent, null or "" ⇒ block: the 17
		// shipped categories carry no "mode" and must keep blocking.
		//
		// An UNKNOWN value also ⇒ block, loudly. Fail closed: a typo like
		// "monitor" must never silently drop a protection nor downgrade it to
		// observation. This is the same instinct as Enabled's pointer default.
		mode := modeBlock
		if cat.Mode != nil && *cat.Mode != "" {
			switch *cat.Mode {
			case modeBlock, modeDetect, modeEscalate:
				mode = *cat.Mode
			default:
				log.Printf("sbxwaf/rules: category %q has unknown mode %q — falling back to %q (known modes: %q, %q, %q)",
					catID, *cat.Mode, modeBlock, modeBlock, modeDetect, modeEscalate)
			}
		}

		cc := compiledCategory{
			name:     cat.Name,
			severity: sev,
			mode:     mode,
		}
		if cc.name == "" {
			cc.name = catID
		}

		for _, p := range cat.Patterns {
			if p.Pattern == "" {
				continue
			}
			// Case-insensitive prefix, matching Python re.compile(pat, re.IGNORECASE).
			re, err := regexp.Compile("(?i)" + p.Pattern)
			if err != nil {
				log.Printf("sbxwaf/rules: category %q pattern %q failed to compile (skipped): %v", catID, p.ID, err)
				continue
			}
			cc.patterns = append(cc.patterns, compiledPattern{
				id:       p.ID,
				re:       re,
				desc:     p.Desc,
				severity: sev,
			})
			total++
		}

		data.cats = append(data.cats, struct {
			id   string
			data compiledCategory
		}{id: catID, data: cc})
	}

	log.Printf("sbxwaf/rules: loaded %d patterns in %d categories from %s", total, len(data.cats), path)
	return data
}

// LoadRules parses path as a waf-rules.json file and returns a *Rules ready
// for Match.  A missing or unreadable file yields an empty (always-miss) Rules —
// the caller will get hit=false until a valid file appears and Maybe() reloads it.
func LoadRules(path string) *Rules {
	r := &Rules{}

	// Initial load.
	r.current = loadRulesJSON(path)

	// Register hot-reload target.  throttle=0 so Maybe() fires immediately in
	// tests; production can wrap with its own rate gate (mirrors Routes.Maybe()).
	target := reload.Target{
		Path:      path,
		LastMtime: reload.StatMtime(path),
		Load: func(p string) any {
			return loadRulesJSON(p)
		},
		Apply: func(v any) {
			newData := v.(*rulesData)
			r.mu.Lock()
			r.current = newData
			r.mu.Unlock()
		},
	}
	r.watcher = reload.NewWatcher(0, target)
	return r
}

// Maybe triggers a hot-reload check — stats the rules file and atomically
// swaps the compiled rule set if the mtime changed.  Cheap when nothing
// changed (one stat + one time compare).  Call from the request hot path or
// from a ticker.  Mirrors Routes.Maybe().
func (r *Rules) Maybe() {
	r.watcher.Maybe()
}

// unquotePlus mirrors Python's urllib.parse.unquote_plus:
// replace '+' with ' ', then percent-unescape.
// We apply this to both path and query before scanning.
func unquotePlus(s string) string {
	// Replace '+' with space first (unquote_plus semantic).
	s = strings.ReplaceAll(s, "+", " ")
	// Then percent-unescape. url.PathUnescape handles %XX sequences; it is
	// equivalent to urllib.parse.unquote for the remaining percent-encoded chars.
	decoded, err := url.PathUnescape(s)
	if err != nil {
		// On malformed percent-encoding, return best-effort (as-is after + swap).
		return s
	}
	return decoded
}

// Match checks the request against all compiled WAF rules (all modes). See the
// package doc for scan-target and iteration semantics. Equivalent to
// MatchModes(..., includeBlock=true).
func (r *Rules) Match(method, rawPath, rawQuery, body, ua string) (cat, sev, mode string, hit bool) {
	return r.MatchModes(method, rawPath, rawQuery, body, ua, true)
}

// MatchModes is Match with a category-mode filter. When includeBlock is false,
// categories in modeBlock are skipped entirely — used by the static-asset fast
// path, where only detect/escalate (path-fingerprint) categories run so a
// legitimate static asset can never be newly blocked. Otherwise identical to
// Match (same decoding, same scan target, first-match-wins in category order).
func (r *Rules) MatchModes(method, rawPath, rawQuery, body, ua string, includeBlock bool) (cat, sev, mode string, hit bool) {
	decodedPath := unquotePlus(rawPath)
	decodedQuery := unquotePlus(rawQuery)
	scanParts := []string{decodedPath, decodedQuery, body, ua}
	scanText := strings.ToLower(strings.Join(scanParts, " "))

	r.mu.RLock()
	cur := r.current
	r.mu.RUnlock()

	if cur == nil {
		return "", "", "", false
	}

	for _, c := range cur.cats {
		if !includeBlock && c.data.mode == modeBlock {
			continue
		}
		for _, p := range c.data.patterns {
			if p.re.MatchString(scanText) {
				return c.id, p.severity, c.data.mode, true
			}
		}
	}
	return "", "", "", false
}
