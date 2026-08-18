<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# sbxwaf static-asset detect/escalate — Plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** A scanner probing a static-asset PATH (e.g. `/global-protect/portal/css/bootstrap.min.css` on a box with no PAN-OS) must still be fingerprinted. On static-asset paths, run only `detect`/`escalate` categories (path+query+ua, no body); keep skipping `block` categories + body inspection so a legitimate asset is never newly blocked.

**Architecture:** `rules.go` gains `MatchModes(..., includeBlock bool)`; `Match` delegates to it with `true`. The `main.go` handler drops `staticAsset` from the full-skip set and, for static paths, calls `MatchModes(..., includeBlock=false)` with an empty body. The three downstream mode branches are unchanged.

**Tech Stack:** Go 1.22 (RE2), offline vendored build. Tests run on host: `go test ./cmd/sbxwaf/`.

## Global Constraints

- Package `packages/secubox-toolbox-ng`, module `cmd/sbxwaf`. SPDX 2-line `//` header preserved on every file. Copyright `Gérald Kerma <devel@cybermind.fr>`.
- `Match(method, rawPath, rawQuery, body, ua) (cat, sev, mode string, hit bool)` public signature and behaviour MUST stay identical (many tests + call sites depend on it). Achieve this by making `Match` delegate to the new `MatchModes(..., true)`.
- Option B invariant: on a static-asset path, `block`-mode categories are NOT evaluated (no new blocks on legit assets). Only `detect`/`escalate` run, on `path+query+ua` (no body read).
- Non-static, private-IP, ncBypass, trusted-host behaviour all UNCHANGED. The existing `TestInspectStaticAssetSkip` (a block SQLi rule on `/app.js?...union select...` must pass, no 403) MUST still pass — it is the proof Option B preserves block-skip on static.
- Tests: `GOFLAGS=-mod=vendor go test ./cmd/sbxwaf/` from `packages/secubox-toolbox-ng`. No network. Commit messages end `Co-Authored-By: Gerald KERMA <devel@cybermind.fr>`, NO Claude reference.

---

### Task 1: `rules.go` — `MatchModes(includeBlock)` + `Match` delegates

**Files:**
- Modify: `packages/secubox-toolbox-ng/cmd/sbxwaf/rules.go`
- Test: `packages/secubox-toolbox-ng/cmd/sbxwaf/rules_test.go`

**Interfaces:**
- Produces: `func (r *Rules) MatchModes(method, rawPath, rawQuery, body, ua string, includeBlock bool) (cat, sev, mode string, hit bool)`. `Match` unchanged externally (now delegates).

- [ ] **Step 1: Write the failing test**

Add to `rules_test.go` (reuse the file's existing helper that writes a rules JSON + `LoadRules`; if the helpers differ, follow the file's established pattern). The test builds a rules file with one `block` category and one `detect` category, both whose pattern matches a probe path, and asserts the filter:

```go
func TestMatchModesSkipsBlockWhenExcluded(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "waf-rules.json")
	// A block category and a detect category, each matching a distinct path.
	os.WriteFile(path, []byte(`{"categories":{
		"blk":{"mode":"block","patterns":[{"id":"b","pattern":"/mgmt/tm/util/bash"}]},
		"det":{"mode":"detect","patterns":[{"id":"d","pattern":"/global-protect/portal/css/bootstrap\\.min\\.css"}]}
	}}`), 0o644)
	r := LoadRules(path)

	// includeBlock=false: the block category is skipped → a path only the block
	// category covers does NOT hit.
	if _, _, _, hit := r.MatchModes("GET", "/mgmt/tm/util/bash", "", "", "", false); hit {
		t.Fatalf("block category must be skipped when includeBlock=false")
	}
	// includeBlock=false: the detect category still fires.
	cat, _, mode, hit := r.MatchModes("GET", "/global-protect/portal/css/bootstrap.min.css", "", "", "", false)
	if !hit || cat != "det" || mode != "detect" {
		t.Fatalf("detect category must fire when includeBlock=false; got cat=%q mode=%q hit=%v", cat, mode, hit)
	}
	// includeBlock=true: block category fires (parity with Match).
	if _, _, mode, hit := r.MatchModes("GET", "/mgmt/tm/util/bash", "", "", "", true); !hit || mode != "block" {
		t.Fatalf("block category must fire when includeBlock=true")
	}
	// Match delegates to includeBlock=true.
	if _, _, _, hit := r.Match("GET", "/mgmt/tm/util/bash", "", "", ""); !hit {
		t.Fatalf("Match must still see block categories")
	}
}
```

- [ ] **Step 2: Run — must fail** (`r.MatchModes` undefined).

Run: `cd packages/secubox-toolbox-ng && GOFLAGS=-mod=vendor go test ./cmd/sbxwaf/ -run TestMatchModes`

- [ ] **Step 3: Implement**

In `rules.go`, replace the existing `func (r *Rules) Match(...)` with a thin delegate plus the new `MatchModes`. Keep the decoding/scan-text logic identical — move it into `MatchModes`, add the block filter:

```go
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
```

- [ ] **Step 4: Run — must pass**

Run: `cd packages/secubox-toolbox-ng && GOFLAGS=-mod=vendor go test ./cmd/sbxwaf/`
Expected: all pass (new test + all existing — `Match` behaviour is preserved via delegation).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-toolbox-ng/cmd/sbxwaf/rules.go packages/secubox-toolbox-ng/cmd/sbxwaf/rules_test.go
git commit -m "feat(sbxwaf): MatchModes(includeBlock) — filter block-mode categories

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

### Task 2: `main.go` handler — fingerprint static-asset paths

**Files:**
- Modify: `packages/secubox-toolbox-ng/cmd/sbxwaf/main.go`
- Test: `packages/secubox-toolbox-ng/cmd/sbxwaf/inspect_test.go`
- Modify: `packages/secubox-toolbox-ng/debian/changelog`

**Interfaces:**
- Consumes: `Rules.MatchModes` (Task 1), `staticAsset`, `privateCIDR`, `ncBypass`.

- [ ] **Step 1: Write the failing tests**

Add to `inspect_test.go`. Reuse the existing `newInspectServer` helper and the pattern of `buildSQLiRulesFile`. Add a helper that writes a **detect** rule on a static-extension path, and a test proving it now fires; plus a test proving a static path under a **block** rule still passes (Option B); plus a legit-static-no-match passthrough.

```go
// buildDetectStaticRulesFile writes a rules file with a detect category whose
// pattern matches a static-asset probe path.
func buildDetectStaticRulesFile(t *testing.T) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "waf-rules*.json")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString(`{"categories":{"probe":{"mode":"detect","severity":"high",` +
		`"patterns":[{"id":"panos","pattern":"/global-protect/portal/css/bootstrap\\.min\\.css"}]}}}`)
	f.Close()
	return f.Name()
}

// A detect rule on a static-asset path now fires (logged) and the request still
// passes through — the core of the fix. Before Option B the .css path skipped
// inspection entirely.
func TestInspectStaticAssetDetectFires(t *testing.T) {
	const wantBody = "css ok"
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, wantBody)
	}))
	defer backend.Close()

	rulesPath := buildDetectStaticRulesFile(t)
	srv := newInspectServer(t, rulesPath, backend.URL[len("http://"):])
	// Route a threat log to a temp file so we can assert the detect record.
	logPath := filepath.Join(t.TempDir(), "threats.log")
	srv.threatLog = NewThreatLog(logPath)

	handler := srv.handler()
	req := httptest.NewRequest(http.MethodGet,
		"http://app.example.com/global-protect/portal/css/bootstrap.min.css", nil)
	req.Host = "app.example.com"
	req.RemoteAddr = "1.2.3.4:12345" // public IP
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// detect = observe: request passes through to backend, NOT blocked.
	if rec.Code == http.StatusForbidden {
		t.Fatalf("detect must not block; got 403")
	}
	body, _ := io.ReadAll(rec.Result().Body)
	if string(body) != wantBody {
		t.Fatalf("expected backend body %q, got %q", wantBody, string(body))
	}
	// And it was logged as action=detect.
	logged, _ := os.ReadFile(logPath)
	if !strings.Contains(string(logged), `"action":"detect"`) ||
		!strings.Contains(string(logged), `"category":"probe"`) {
		t.Fatalf("expected a detect record for category probe; log=%s", logged)
	}
}

// A legit static asset that matches NO rule still passes with no detect log.
func TestInspectStaticAssetNoMatchPassthrough(t *testing.T) {
	const wantBody = "css ok"
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, wantBody)
	}))
	defer backend.Close()

	rulesPath := buildDetectStaticRulesFile(t)
	srv := newInspectServer(t, rulesPath, backend.URL[len("http://"):])
	logPath := filepath.Join(t.TempDir(), "threats.log")
	srv.threatLog = NewThreatLog(logPath)

	handler := srv.handler()
	req := httptest.NewRequest(http.MethodGet,
		"http://app.example.com/static/css/site.min.css", nil) // different path
	req.Host = "app.example.com"
	req.RemoteAddr = "1.2.3.4:12345"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("legit static asset should pass; got %d", rec.Code)
	}
	logged, _ := os.ReadFile(logPath)
	if strings.Contains(string(logged), `"action":"detect"`) {
		t.Fatalf("no detect record expected for a non-matching static asset; log=%s", logged)
	}
}
```

Note: if `NewThreatLog`'s constructor name/signature differs, use whatever `inspect_test.go`/`threatlog.go` already expose (read them first). If wiring a threat log into the test server is awkward, assert the pass-through (`rec.Code != 403`, backend body) for both tests and drop the log-content assertion — but PREFER asserting the detect record so the test is not vacuous.

- [ ] **Step 2: Run — must fail**

Run: `cd packages/secubox-toolbox-ng && GOFLAGS=-mod=vendor go test ./cmd/sbxwaf/ -run TestInspectStaticAsset`
Expected: `TestInspectStaticAssetDetectFires` FAILS (the .css path currently skips inspection → no detect log). `TestInspectStaticAssetSkip` (existing) still passes.

- [ ] **Step 3: Implement the handler change in `main.go`**

Find the block that starts at `skip := privateCIDR(ip) || staticAsset(rawPath) || ncBypass(rawPath)` (currently ~line 334). Replace from that line through the `cat, sev, mode, hit := s.rules.Match(...)` call with the following. **Leave the three downstream branches (detect at ~396, escalate at ~416, block at ~446) UNCHANGED.**

```go
			// Static-asset PATHS are NOT fully skipped: a scanner probing a
			// static-extension path (e.g. /global-protect/.../bootstrap.min.css on
			// a box with no PAN-OS) must still be fingerprinted. On a static asset
			// we run only detect/escalate categories on path+query+ua (no body);
			// block categories stay skipped so a legit asset is never newly blocked
			// (preserves the old fast-path's zero-FP property — see
			// TestInspectStaticAssetSkip). Private-IP / NC-bypass / trusted-host
			// remain FULL skips (LAN + NC mobile tokens are never fingerprinted).
			skip := privateCIDR(ip) || ncBypass(rawPath)

			if !skip && s.isTrustedHost(r.Host) {
				skip = true
			}

			isStatic := staticAsset(rawPath)

			if !skip {
				var bodyBytes []byte
				includeBlock := true
				if isStatic {
					// Fingerprint-only pass: detect/escalate on path+query+ua, no
					// body read, no block evaluation.
					includeBlock = false
				} else {
					// Read up to s.maxBodyInspect bytes for WAF inspection, then
					// restore the FULL body (prefix + remaining stream) so the
					// upstream proxy receives every byte intact. PARITY GAP: only
					// the first maxBodyInspect bytes are inspected; a payload
					// appended after that offset is NOT detected (see docs/CUTOVER.md).
					cap := s.maxBodyInspect
					if cap <= 0 {
						cap = defaultMaxBodyInspect
					}
					if r.Body != nil {
						prefix, _ := io.ReadAll(io.LimitReader(r.Body, cap))
						bodyBytes = prefix
						r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(prefix), r.Body))

						if int64(len(prefix)) == cap {
							if s.threatLog != nil {
								s.threatLog.Record(ThreatRecord{
									ClientIP: ip,
									Host:     r.Host,
									Method:   r.Method,
									Path:     rawPath,
									Category: "body-inspect-truncated",
									Severity: "audit",
									Action:   "body-inspect-truncated",
									UA:       r.Header.Get("User-Agent"),
								})
							}
							log.Printf("sbxwaf: AUDIT body-inspect-truncated host=%s path=%s ip=%s cap=%d",
								r.Host, rawPath, ip, cap)
						}
					}
				}

				cat, sev, mode, hit := s.rules.MatchModes(
					r.Method,
					rawPath,
					r.URL.RawQuery,
					string(bodyBytes),
					r.Header.Get("User-Agent"),
					includeBlock,
				)
```

Everything from `if hit && mode == modeDetect {` onward is unchanged. Ensure the braces still balance (the `if !skip {` block and its enclosing `if s.rules != nil {` close where they did before).

- [ ] **Step 4: Run — must pass**

Run: `cd packages/secubox-toolbox-ng && GOFLAGS=-mod=vendor go test ./cmd/sbxwaf/`
Expected: all pass — the two new tests, the unchanged `TestInspectStaticAssetSkip` (block SQLi on `.js` still passes), and every other existing test.

- [ ] **Step 5: `go vet` + build sanity**

Run: `cd packages/secubox-toolbox-ng && GOFLAGS=-mod=vendor go vet ./cmd/sbxwaf/ && GOFLAGS=-mod=vendor go build -o /dev/null ./cmd/sbxwaf`
Expected: clean.

- [ ] **Step 6: Changelog + commit**

Prepend to `packages/secubox-toolbox-ng/debian/changelog`:

```
secubox-toolbox-ng (0.1.37-1~bookworm1) bookworm; urgency=medium

  * sbxwaf: fingerprint scanners on static-asset paths. Previously any path
    ending in .js/.css/.png/... fully skipped WAF inspection, so a probe for an
    absent product served on a static-asset path (e.g. the PAN-OS
    /global-protect/.../bootstrap.min.css) evaded detection entirely. Now
    static-asset paths run detect/escalate categories (path+query+ua, no body);
    block categories stay skipped so a legitimate asset is never newly blocked.

 -- Gerald KERMA <devel@cybermind.fr>  Sat, 19 Jul 2026 10:00:00 +0200

```

```bash
git add packages/secubox-toolbox-ng/cmd/sbxwaf/main.go packages/secubox-toolbox-ng/cmd/sbxwaf/inspect_test.go packages/secubox-toolbox-ng/debian/changelog
git commit -m "feat(sbxwaf): run detect/escalate on static-asset paths (0.1.37)

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

## Auto-revue du plan

- **Couverture** : filtre block (Task 1 MatchModes) ; câblage handler + tests + changelog (Task 2). ✓
- **Parité** : `Match` délègue à `MatchModes(true)` → tous les appels/tests existants intacts.
- **Option B** : sur statique, `includeBlock=false` → block jamais évalué ; `TestInspectStaticAssetSkip` (block SQLi sur .js) reste vert = preuve.
- **Sûreté** : detect/escalate seulement sur statiques ; privateCIDR/ncBypass/trusted-host = skips complets inchangés ; body non lu sur statique.
- **Types** : `MatchModes(method, rawPath, rawQuery, body, ua, includeBlock)` défini Task 1, consommé Task 2.
