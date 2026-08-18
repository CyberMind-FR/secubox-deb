<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Targeted SW-neuter for the R3 banner — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the R3 transparency banner appear on Service-Worker PWA sites (leparisien, cnn…) by serving a self-unregistering SW for an operator-curated allow-list of hosts, with an auto-learn proposal feed.

**Architecture:** A new `SWNeuter` in sbxmitm intercepts the `Service-Worker: script` fetch; for allow-listed hosts it answers with a passive self-unregistering SW (next navigation reaches the MITM → banner); off the list it records the host as an auto-learn candidate flushed to the portal for operator review.

**Tech Stack:** Go (sbxmitm, `golang.org/x/...` stdlib + internal/reload), Python/FastAPI (portal endpoint), pytest + `go test`.

## Global Constraints

- New Go files carry the SPDX header: `// SPDX-License-Identifier: LicenseRef-CMSD-1.0` + the CyberMind copyright line (copy from any sibling, e.g. `cmd/sbxmitm/csp.go`).
- **Targeted-strict:** ONLY hosts on the allow-list are neutered. An empty/missing list (`reload.LoadLines` → empty set) is a complete no-op. Nothing global.
- **Passive:** the neuter SW must NOT call `client.navigate()` / force a reload. It unregisters + clears caches only; the banner returns on the next navigation.
- Reuse existing package helpers: `hostMatches(host, patterns)` (policy.go), `reload.LoadLines`/`reload.Target`/`reload.NewWatcher`/`reload.StatMtime`, `writeRaw`, `portalTargetURL`, `adEventClient`.
- Allow-list path default: `/var/lib/secubox/toolbox/sw-neuter-hosts.txt`. Candidates file: `/var/lib/secubox/toolbox/sw-neuter-candidates.txt`.
- Detection signal: the spec-mandated `Service-Worker: script` request header — never trigger on normal traffic.
- Commits reference `(ref #753)`. No "Claude Code"/"Generated with" strings.
- Build: `cd packages/secubox-toolbox-ng && GOFLAGS=-mod=vendor go build ./...` ; test: `GOFLAGS=-mod=vendor go test ./cmd/sbxmitm/`.

## File Structure
- Create `packages/secubox-toolbox-ng/cmd/sbxmitm/swneuter.go` — the SWNeuter unit (allow-list, match, detection, neuter body, candidate feed, flush).
- Create `packages/secubox-toolbox-ng/cmd/sbxmitm/swneuter_test.go` — unit tests.
- Modify `packages/secubox-toolbox-ng/cmd/sbxmitm/main.go` — flag, Proxy field, construction, flusher launch, mitmPipeline insertion.
- Modify `packages/secubox-toolbox/secubox_toolbox/api.py` — the `/__toolbox/sw-candidate` portal endpoint.
- Test `packages/secubox-toolbox/tests/test_sw_candidate_api.py` — the portal endpoint.

---

### Task 1: SWNeuter core (allow-list, match, detection, neuter body, candidates)

**Files:**
- Create: `packages/secubox-toolbox-ng/cmd/sbxmitm/swneuter.go`
- Test: `packages/secubox-toolbox-ng/cmd/sbxmitm/swneuter_test.go`

**Interfaces:**
- Consumes: `hostMatches(host string, patterns map[string]bool) bool` (policy.go); `reload.LoadLines/Target/NewWatcher/StatMtime` (internal/reload).
- Produces:
  - `type SWNeuter struct{...}` with `newSWNeuter(path string) *SWNeuter`, `(*SWNeuter) Maybe()`, `(*SWNeuter) Match(host string) bool`, `(*SWNeuter) RecordCandidate(host string)`, `(*SWNeuter) snapshotCandidates() []string`.
  - `isSWScriptRequest(req *http.Request) bool`.
  - `const NeuterSW string`.

- [ ] **Step 1: Write the failing tests**

Create `packages/secubox-toolbox-ng/cmd/sbxmitm/swneuter_test.go`:

```go
// SPDX-License-Identifier: LicenseRef-CMSD-1.0
package main

import (
	"net/http"
	"strings"
	"testing"
)

func TestSWMatchSuffix(t *testing.T) {
	s := &SWNeuter{hosts: map[string]bool{"leparisien.fr": true, "cnn.com": true}}
	for _, h := range []string{"leparisien.fr", "www.leparisien.fr", "m.cnn.com", "CNN.COM"} {
		if !s.Match(h) {
			t.Fatalf("%q should match the allow-list", h)
		}
	}
	for _, h := range []string{"notleparisien.fr", "evil.com", "leparisien.fr.evil.com", ""} {
		if s.Match(h) {
			t.Fatalf("%q must NOT match", h)
		}
	}
}

func TestSWEmptyListNoOp(t *testing.T) {
	s := &SWNeuter{hosts: map[string]bool{}}
	if s.Match("www.leparisien.fr") {
		t.Fatal("empty allow-list must match nothing (targeted-strict no-op)")
	}
}

func TestSWIsScriptRequest(t *testing.T) {
	r1, _ := http.NewRequest("GET", "https://x/sw.js", nil)
	r1.Header.Set("Service-Worker", "script")
	if !isSWScriptRequest(r1) {
		t.Fatal("Service-Worker: script must be detected")
	}
	r2, _ := http.NewRequest("GET", "https://x/sw.js", nil)
	if isSWScriptRequest(r2) {
		t.Fatal("no Service-Worker header → not a SW script request")
	}
	if isSWScriptRequest(nil) {
		t.Fatal("nil request → false")
	}
}

func TestNeuterSWPassiveAndCorrect(t *testing.T) {
	if !strings.Contains(NeuterSW, "self.registration.unregister()") {
		t.Fatal("neuter SW must unregister itself")
	}
	if !strings.Contains(NeuterSW, "caches.delete") {
		t.Fatal("neuter SW must clear caches")
	}
	if strings.Contains(NeuterSW, "navigate(") {
		t.Fatal("neuter SW must be PASSIVE — no client.navigate / force reload")
	}
}

func TestSWCandidateRecordSnapshot(t *testing.T) {
	s := &SWNeuter{cand: map[string]int64{}}
	s.RecordCandidate("www.cnn.com")
	s.RecordCandidate("www.cnn.com")
	s.RecordCandidate("") // ignored
	got := s.snapshotCandidates()
	if len(got) != 1 || got[0] != "www.cnn.com" {
		t.Fatalf("snapshot = %v, want [www.cnn.com]", got)
	}
	if s.snapshotCandidates() != nil {
		t.Fatal("snapshot must read-and-CLEAR (second call → nil)")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd packages/secubox-toolbox-ng && GOFLAGS=-mod=vendor go test ./cmd/sbxmitm/ -run 'TestSW|TestNeuter' -v`
Expected: FAIL — `undefined: SWNeuter`, `undefined: isSWScriptRequest`, `undefined: NeuterSW`.

- [ ] **Step 3: Implement swneuter.go**

Create `packages/secubox-toolbox-ng/cmd/sbxmitm/swneuter.go`:

```go
// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: sbxmitm — targeted Service-Worker neuter (#753)
//
// PWA news sites (leparisien, cnn…) serve their main HTML document from a
// Service-Worker cache, so the navigation never reaches the MITM and the
// transparency banner can't be injected. For an operator-curated allow-list of
// hosts, we answer the SW SCRIPT fetch with a self-unregistering SW: the browser
// updates to it, it unregisters + drops caches, and the NEXT navigation is a
// fresh network fetch the MITM injects the banner into. PASSIVE (no forced
// reload). Targeted-strict: an empty list neuters nothing.
package main

import (
	"net/http"
	"strings"
	"sync"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/reload"
)

// NeuterSW is the self-unregistering SW body served for allow-listed hosts.
// It unregisters itself and clears all caches on activate; it NEVER calls
// client.navigate(), so the current page is not force-reloaded — the banner
// returns on the next navigation.
const NeuterSW = `self.addEventListener('install', function(e){ self.skipWaiting(); });
self.addEventListener('activate', function(e){
  e.waitUntil((async function(){
    try { var ks = await caches.keys(); await Promise.all(ks.map(function(k){ return caches.delete(k); })); } catch (_) {}
    try { await self.registration.unregister(); } catch (_) {}
  })());
});
`

// swCandMapCap bounds the candidate buffer (mirrors adCandMapCap).
const swCandMapCap = 4096

// SWNeuter holds the hot-reloadable allow-list + the auto-learn candidate buffer.
type SWNeuter struct {
	mu      sync.RWMutex
	hosts   map[string]bool // allow-list (lowercased; suffix-matched via hostMatches)
	watcher *reload.Watcher

	cmu  sync.Mutex
	cand map[string]int64 // host -> hits (SW hosts NOT yet on the allow-list)
}

// newSWNeuter loads the allow-list file and registers a hot-reload watcher.
// A missing/unreadable file yields an empty (no-op) list.
func newSWNeuter(path string) *SWNeuter {
	s := &SWNeuter{
		hosts: reload.LoadLines(path, true),
		cand:  map[string]int64{},
	}
	target := reload.Target{
		Path:      path,
		LastMtime: reload.StatMtime(path),
		Load:      func(p string) any { return reload.LoadLines(p, true) },
		Apply: func(v any) {
			m := v.(map[string]bool)
			s.mu.Lock()
			s.hosts = m
			s.mu.Unlock()
		},
	}
	s.watcher = reload.NewWatcher(0, target)
	return s
}

// Maybe triggers a hot-reload check (cheap: one stat + mtime compare).
func (s *SWNeuter) Maybe() {
	if s != nil && s.watcher != nil {
		s.watcher.Maybe()
	}
}

// Match reports whether host is on the allow-list (exact or dotted-suffix).
func (s *SWNeuter) Match(host string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return hostMatches(host, s.hosts)
}

// RecordCandidate tallies a SW host not on the allow-list (auto-learn proposal).
func (s *SWNeuter) RecordCandidate(host string) {
	h := strings.Trim(strings.ToLower(host), ".")
	if h == "" {
		return
	}
	s.cmu.Lock()
	defer s.cmu.Unlock()
	if _, ok := s.cand[h]; ok {
		s.cand[h]++
	} else if len(s.cand) < swCandMapCap {
		s.cand[h] = 1
	}
}

// snapshotCandidates atomically reads-and-clears the candidate buffer.
func (s *SWNeuter) snapshotCandidates() []string {
	s.cmu.Lock()
	defer s.cmu.Unlock()
	if len(s.cand) == 0 {
		return nil
	}
	out := make([]string, 0, len(s.cand))
	for h := range s.cand {
		out = append(out, h)
	}
	s.cand = map[string]int64{}
	return out
}

// isSWScriptRequest reports whether req is a Service-Worker SCRIPT fetch.
// Browsers send the spec-mandated `Service-Worker: script` header on the
// register() fetch and every update check — reliable and host-agnostic.
func isSWScriptRequest(req *http.Request) bool {
	return req != nil && strings.EqualFold(req.Header.Get("Service-Worker"), "script")
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd packages/secubox-toolbox-ng && GOFLAGS=-mod=vendor go test ./cmd/sbxmitm/ -run 'TestSW|TestNeuter' -v`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-toolbox-ng/cmd/sbxmitm/swneuter.go packages/secubox-toolbox-ng/cmd/sbxmitm/swneuter_test.go
git commit -m "feat(sbxmitm): SWNeuter — allow-list + self-unregistering SW body (ref #753)"
```

---

### Task 2: Wire SWNeuter into the engine (flag, Proxy, mitmPipeline)

**Files:**
- Modify: `packages/secubox-toolbox-ng/cmd/sbxmitm/main.go`

**Interfaces:**
- Consumes: `newSWNeuter`, `(*SWNeuter).Maybe/Match/RecordCandidate`, `isSWScriptRequest`, `NeuterSW` (Task 1); `writeRaw` (util.go).
- Produces: `Proxy.swNeuter *SWNeuter` field; `--sw-neuter-hosts` flag.

- [ ] **Step 1: Add the struct field**

In `main.go`, in `type Proxy struct`, after the `media *mediaCatcher` field, add:

```go
	// swNeuter (#753) is the targeted Service-Worker neuter: for allow-listed
	// hosts it answers the SW script fetch with a self-unregistering SW so PWA
	// shells stop being SW-cached and the banner can be injected on the next nav.
	swNeuter *SWNeuter
```

- [ ] **Step 2: Add the flag + construction**

In `main()`, next to the other `flag.String` defs (~line 530, after `mediaCatch`), add:

```go
	swNeuterHosts := flag.String("sw-neuter-hosts", "/var/lib/secubox/toolbox/sw-neuter-hosts.txt",
		"#753 allow-list of PWA hosts whose Service Worker is neutered (served a self-unregistering SW) so the banner can be injected; empty/missing file = no-op")
```

In the `px := &Proxy{ ... }` literal (~line 551), after `media: newMediaCatcher(*mediaCatch),`, add:

```go
		swNeuter: newSWNeuter(*swNeuterHosts),
```

- [ ] **Step 3: Insert the neuter short-circuit in mitmPipeline**

In `mitmPipeline`, immediately AFTER the `isToolboxAssetPath` short-circuit block (the `if isToolboxAssetPath(req.URL.RequestURI()) { servePortalAsset(...); return }`) and BEFORE the `if dialHost != "" && host != ""` block, insert:

```go
	// #753 — targeted SW-neuter. For an allow-listed host, answer the
	// Service-Worker script fetch with a self-unregistering SW (the next
	// navigation bypasses the now-gone SW → reaches the MITM → banner). Off the
	// list, record the host as an auto-learn candidate. Only ever fires on the
	// `Service-Worker: script` request — normal traffic is untouched.
	if px.swNeuter != nil && isSWScriptRequest(req) {
		px.swNeuter.Maybe()
		if px.swNeuter.Match(host) {
			writeRaw(tconn, 200, "OK", map[string]string{
				"Content-Type":  "application/javascript",
				"Cache-Control": "no-store",
				"X-SecuBox-Ng":  "sw-neutered",
			}, []byte(NeuterSW))
			return
		}
		px.swNeuter.RecordCandidate(host)
	}
```

- [ ] **Step 4: Build + vet + run the package tests**

Run: `cd packages/secubox-toolbox-ng && GOFLAGS=-mod=vendor go build ./... && GOFLAGS=-mod=vendor go vet ./cmd/sbxmitm/ && GOFLAGS=-mod=vendor go test ./cmd/sbxmitm/ -count=1`
Expected: build OK, vet clean, all tests PASS (Task 1 tests + the rest of the package).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-toolbox-ng/cmd/sbxmitm/main.go
git commit -m "feat(sbxmitm): wire SWNeuter into mitmPipeline + --sw-neuter-hosts (ref #753)"
```

---

### Task 3: Auto-learn flush + portal `/__toolbox/sw-candidate` endpoint

**Files:**
- Modify: `packages/secubox-toolbox-ng/cmd/sbxmitm/swneuter.go` (add the flusher)
- Modify: `packages/secubox-toolbox-ng/cmd/sbxmitm/main.go` (launch the flusher)
- Modify: `packages/secubox-toolbox/secubox_toolbox/api.py` (the endpoint)
- Test: `packages/secubox-toolbox-ng/cmd/sbxmitm/swneuter_test.go` (flush shape) + `packages/secubox-toolbox/tests/test_sw_candidate_api.py`

**Interfaces:**
- Consumes: `snapshotCandidates` (Task 1); `portalTargetURL`, `adEventClient` (adstats.go); FastAPI `router`, `Request`, `Response` (api.py).
- Produces: `(*SWNeuter) flushCandidatesOnce(portal string) []string`, `(*SWNeuter) runCandidateFlusher(portal string)`; `POST /__toolbox/sw-candidate`.

- [ ] **Step 1: Write the failing Go flush test**

Append to `swneuter_test.go`:

```go
func TestSWFlushCandidatesClears(t *testing.T) {
	s := &SWNeuter{cand: map[string]int64{}}
	s.RecordCandidate("www.cnn.com")
	// portal "" → Post fails fast (best-effort); the snapshot must still drain.
	got := s.flushCandidatesOnce("http://127.0.0.1:0")
	if len(got) != 1 || got[0] != "www.cnn.com" {
		t.Fatalf("flush returned %v, want [www.cnn.com]", got)
	}
	if s.snapshotCandidates() != nil {
		t.Fatal("flush must have drained the buffer")
	}
	if s.flushCandidatesOnce("http://127.0.0.1:0") != nil {
		t.Fatal("empty buffer → flush returns nil, no POST")
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cd packages/secubox-toolbox-ng && GOFLAGS=-mod=vendor go test ./cmd/sbxmitm/ -run TestSWFlush -v`
Expected: FAIL — `s.flushCandidatesOnce undefined`.

- [ ] **Step 3: Implement the flusher in swneuter.go**

Add these imports to `swneuter.go`'s import block: `"bytes"`, `"encoding/json"`, `"time"`. Then append:

```go
// swFlushInterval is how often pending candidates are POSTed to the portal.
const swFlushInterval = 30 * time.Second

// flushCandidatesOnce drains the candidate buffer and best-effort POSTs the host
// list to the portal's /__toolbox/sw-candidate ingest. Returns the drained hosts
// (so a test can assert the snapshot/clear); a dead/slow portal is swallowed.
func (s *SWNeuter) flushCandidatesOnce(portal string) []string {
	hosts := s.snapshotCandidates()
	if len(hosts) == 0 {
		return nil
	}
	buf, err := json.Marshal(map[string][]string{"hosts": hosts})
	if err != nil {
		return hosts
	}
	url := portalTargetURL(portal, "/__toolbox/sw-candidate")
	if resp, err := adEventClient.Post(url, "application/json", bytes.NewReader(buf)); err == nil && resp != nil {
		resp.Body.Close()
	}
	return hosts
}

// runCandidateFlusher drains the candidate buffer to the portal every
// swFlushInterval. Launched as a background goroutine from main().
func (s *SWNeuter) runCandidateFlusher(portal string) {
	for {
		time.Sleep(swFlushInterval)
		s.flushCandidatesOnce(portal)
	}
}
```

- [ ] **Step 4: Run the Go flush test (pass)**

Run: `cd packages/secubox-toolbox-ng && GOFLAGS=-mod=vendor go test ./cmd/sbxmitm/ -run TestSWFlush -v`
Expected: PASS.

- [ ] **Step 5: Launch the flusher in main()**

In `main.go`, next to `go px.ads.runAdStatsFlusher(*portal, px.cand)` (~line 579), add:

```go
	go px.swNeuter.runCandidateFlusher(*portal)
```

- [ ] **Step 6: Write the failing portal endpoint test**

Create `packages/secubox-toolbox/tests/test_sw_candidate_api.py`:

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Tests for POST /__toolbox/sw-candidate (ref #753)."""
import asyncio
import json
from secubox_toolbox import api


class _Req:
    def __init__(self, payload):
        self._payload = payload

    async def json(self):
        return self._payload


def test_sw_candidate_appends_and_dedupes(tmp_path, monkeypatch):
    f = tmp_path / "sw-neuter-candidates.txt"
    monkeypatch.setattr(api, "SW_CANDIDATES_FILE", f)
    r1 = asyncio.run(api.toolbox_sw_candidate(_Req({"hosts": ["www.cnn.com", "leparisien.fr"]})))
    assert r1.status_code == 204
    asyncio.run(api.toolbox_sw_candidate(_Req({"hosts": ["www.cnn.com", "20minutes.fr"]})))
    lines = [l.strip() for l in f.read_text().splitlines() if l.strip()]
    assert sorted(lines) == ["20minutes.fr", "leparisien.fr", "www.cnn.com"]  # deduped


def test_sw_candidate_ignores_bad_payload(tmp_path, monkeypatch):
    f = tmp_path / "sw-neuter-candidates.txt"
    monkeypatch.setattr(api, "SW_CANDIDATES_FILE", f)
    r = asyncio.run(api.toolbox_sw_candidate(_Req({"hosts": [None, 123, ""]})))
    assert r.status_code == 204
    assert not f.exists() or f.read_text().strip() == ""
```

- [ ] **Step 7: Run it to verify it fails**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_sw_candidate_api.py -v`
Expected: FAIL — `module 'secubox_toolbox.api' has no attribute 'toolbox_sw_candidate'`.

- [ ] **Step 8: Implement the portal endpoint**

In `packages/secubox-toolbox/secubox_toolbox/api.py`, near the other `/__toolbox/*` routes (e.g. after `toolbox_inline`), add (and add `from pathlib import Path` to the imports if absent):

```python
SW_CANDIDATES_FILE = Path("/var/lib/secubox/toolbox/sw-neuter-candidates.txt")


def _append_sw_candidates(hosts: list[str]) -> None:
    """Append new hosts to the sw-neuter candidates file, deduped against what is
    already there. Best-effort; never raises into the request path."""
    try:
        existing: set[str] = set()
        if SW_CANDIDATES_FILE.exists():
            existing = {l.strip() for l in SW_CANDIDATES_FILE.read_text().splitlines() if l.strip()}
        fresh = [h for h in hosts if h not in existing]
        if not fresh:
            return
        SW_CANDIDATES_FILE.parent.mkdir(parents=True, exist_ok=True)
        with SW_CANDIDATES_FILE.open("a", encoding="utf-8") as fh:
            for h in fresh:
                fh.write(h + "\n")
    except OSError as e:
        log.debug("sw-candidate append failed: %s", e)


@router.post("/__toolbox/sw-candidate")
async def toolbox_sw_candidate(request: Request) -> Response:
    """#753 — record SW-PWA hosts proposed for the sw-neuter allow-list. sbxmitm
    POSTs hosts it saw fetching a Service Worker that are NOT yet allow-listed.
    Deduped-appends to the candidates file for operator review; the operator
    promotes wanted hosts to sw-neuter-hosts.txt."""
    try:
        body = await request.json()
        hosts = [h for h in (body.get("hosts") or []) if isinstance(h, str) and h]
    except Exception:
        hosts = []
    if hosts:
        _append_sw_candidates(hosts)
    return Response(status_code=204)
```

Note: confirm `log` is the module logger name used elsewhere in api.py; if it differs, match the existing name. Confirm `Request`/`Response` are already imported (they are — other routes use them).

- [ ] **Step 9: Run both test suites**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_sw_candidate_api.py -v`
Expected: PASS (2 tests).
Run: `cd packages/secubox-toolbox-ng && GOFLAGS=-mod=vendor go build ./... && GOFLAGS=-mod=vendor go test ./cmd/sbxmitm/ -count=1`
Expected: build OK, all PASS.

- [ ] **Step 10: Commit**

```bash
git add packages/secubox-toolbox-ng/cmd/sbxmitm/swneuter.go packages/secubox-toolbox-ng/cmd/sbxmitm/swneuter_test.go packages/secubox-toolbox-ng/cmd/sbxmitm/main.go packages/secubox-toolbox/secubox_toolbox/api.py packages/secubox-toolbox/tests/test_sw_candidate_api.py
git commit -m "feat(toolbox): SW-neuter auto-learn flush + /__toolbox/sw-candidate ingest (ref #753)"
```

---

## Manual validation (after deploy — not part of the TDD loop)

Rebuild + install the `secubox-toolbox-ng` .deb (bump changelog), then:
1. `echo leparisien.fr >> /var/lib/secubox/toolbox/sw-neuter-hosts.txt`
2. Through the tunnel, hard-reload leparisien.fr → DevTools → Application → Service Workers shows it unregistered; the banner appears on the next navigation.
3. A host NOT on the list keeps its SW; after a few minutes it appears in `/var/lib/secubox/toolbox/sw-neuter-candidates.txt`.
4. Confirm a non-PWA site (lemonde, x.com) is completely unaffected.

## Self-Review notes
- **Spec coverage:** SW-script detection + neuter serve (Task 1+2) ✓; targeted allow-list, hot-reload, suffix-match (Task 1) ✓; passive neuter SW (Task 1, asserted) ✓; auto-learn candidate record + flush + operator-review file (Task 1+3) ✓; targeted-strict/empty-list no-op + fail-open (Task 1, asserted) ✓; durability via .deb (manual section + #754 flow) ✓.
- **Type consistency:** `SWNeuter` methods (`Maybe`, `Match`, `RecordCandidate`, `snapshotCandidates`, `flushCandidatesOnce`, `runCandidateFlusher`) and `isSWScriptRequest`/`NeuterSW` are referenced identically across Tasks 1-3 and the main.go wiring. The portal `SW_CANDIDATES_FILE`/`toolbox_sw_candidate`/`_append_sw_candidates` names match between the test and the endpoint.
- **Out of scope (per spec):** WebUI to review candidates / manage the list (v1 = the two files); forced reload; injecting into SW revalidation fetches.
