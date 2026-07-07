# Sentinel C2/Botnet Auto-Learning Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Auto-learn C2/botnet hosts from sustained, corroborated beaconing and surface them as report-only indicators, with a high-precision false-positive gate so mail/admin/monitoring traffic is never learned.

**Architecture:** A new `C2Learner` (Go, `internal/sentinel`) wraps the existing `Behavioral` analyzer in the `sbx-sentinel` pipeline. On every flow it updates a rarity frequency map and re-emits a throttled `botnet_c2` verdict for already-learned hosts; on a `Behavioral` beacon verdict it runs an allowlist FP gate + corroborating-signal check + candidate→confirm lifecycle, and on confirmation adds the host to its own learned set (persisted JSON) and emits a promotion verdict. **The daemon's `Spyware` analyzer filters to spyware classes, so learned `botnet_c2` entries are matched and surfaced by `C2Learner` itself, not the pack loader.** New daemon `/c2/*` HTTP endpoints + a portal proxy + a WebUI "C2 appris" sub-view expose learned/candidate hosts with a one-click allowlist ("Ignorer").

**Tech Stack:** Go (pure, CGO_ENABLED=0; `internal/sentinel` package), Python 3.11 FastAPI portal, vanilla JS. bbolt store already present; new state is plain atomic JSON files.

## Global Constraints

- **Report-only.** Every learned entry and emitted verdict uses `Action: ActionReport` and `Severity: 75` (< `HighConfidenceThreshold` 85), so `FinalizeAction` also keeps it report-only. NEVER `ActionBlock`.
- **Fail-safe.** No new code may panic or block the analyze path. Every file read (allowlist, box-domains, candidates, learned) returns empty/no-op on missing/corrupt input (log once), never fatal. Every file write is atomic (temp + rename); a write failure is logged and dropped, never corrupts live state. `C2Learner.Analyze` runs under the daemon's existing `safeAnalyze` recover, but must not rely on it.
- **High precision.** Promotion requires ALL of: (a) host passes the FP gate, (b) ≥1 corroborating signal, (c) sustained across `c2MinWindows=3` separate beacon reports spanning `≥ c2MinSpan=30m`. Periodicity alone never promotes.
- **PII floor.** Verdicts/endpoints carry `mac_hash` and destination `host` only — no other identifiers.
- **Bounded memory.** Candidate map, learned map, and frequency map are all LRU-capped (`c2MaxEntries=2000`).
- **No new Debian dependency;** pure-Go stdlib only. `go test ./...` must stay green.
- **Existing signatures (verbatim):** `Verdict{Class ThreatClass; Severity,Confidence int; Action Action; Evidence map[string]string; MacHash string; TS int64}`; `ClassBotnetC2 ThreatClass = "botnet_c2"` (ioc.go); `ActionReport`, `ActionBlock` (ioc.go); `func shannonEntropy(s string) float64` (behavioral.go, same package); `Analyzer interface { Analyze(MirrorMsg) []*Verdict }` (cmd/sbx-sentinel/main.go); `NewBehavioral() *Behavioral`; `func (b *Behavioral) Analyze(MirrorMsg) []*Verdict`; beacon verdict has `Class==ClassBotnetC2` and `Evidence["pattern"]=="beaconing"`, `Evidence["host"]`, `Evidence["interval_s"]`.
- **Go tests:** `cd packages/secubox-toolbox-ng && go test ./internal/sentinel/... ./cmd/sbx-sentinel/...`
- **Python tests:** `cd packages/secubox-toolbox && PYTHONPATH=../../common:. python3 -m pytest tests/<file> -q`
- **Commit trailer:** every commit ends with `(ref #<ISSUE>)` (the controller supplies the issue number at execution).

---

### Task 1: `c2allow.go` — false-positive allowlist gate

**Files:**
- Create: `packages/secubox-toolbox-ng/internal/sentinel/c2allow.go`
- Test: `packages/secubox-toolbox-ng/internal/sentinel/c2allow_test.go`

**Interfaces:**
- Produces: `type C2Allow struct{...}`; `func NewC2Allow(allowFile, boxDomainsFile string) *C2Allow`; `func (a *C2Allow) Allowed(host string) bool`; `func (a *C2Allow) Add(host string) error` (append to allowFile, atomic); `func (a *C2Allow) Reload()`.

- [ ] **Step 1: Write the failing test**

```go
package sentinel

import (
	"os"
	"path/filepath"
	"testing"
)

func writeLines(t *testing.T, path string, lines ...string) {
	t.Helper()
	body := ""
	for _, l := range lines {
		body += l + "\n"
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestC2AllowSuffixAndLan(t *testing.T) {
	dir := t.TempDir()
	allow := filepath.Join(dir, "c2-allow.txt")
	box := filepath.Join(dir, "haproxy-routes.json")
	writeLines(t, allow, "mail.example.com", "# comment", "", "monitoring.example.org")
	os.WriteFile(box, []byte(`{"admin.gk2.secubox.in":["127.0.0.1",9080],"dash.gk2.secubox.in":["127.0.0.1",9081]}`), 0o644)

	a := NewC2Allow(allow, box)
	cases := []struct {
		host string
		want bool
	}{
		{"mail.example.com", true},           // exact allow
		{"imap.mail.example.com", true},      // subdomain of allow entry
		{"monitoring.example.org", true},     // second allow entry
		{"admin.gk2.secubox.in", true},       // box vhost (haproxy key)
		{"api.dash.gk2.secubox.in", true},    // subdomain of box vhost
		{"192.168.1.50", true},               // RFC1918 literal
		{"127.0.0.1", true},                  // loopback literal
		{"10.10.0.2", true},                  // RFC1918 literal
		{"evil-c2-xyz.example", false},       // unknown → not allowed
		{"", true},                           // empty host → treat as allowed (never learn a blank)
	}
	for _, c := range cases {
		if got := a.Allowed(c.host); got != c.want {
			t.Errorf("Allowed(%q)=%v want %v", c.host, got, c.want)
		}
	}
}

func TestC2AllowFailSafeMissingFiles(t *testing.T) {
	a := NewC2Allow("/nonexistent/allow.txt", "/nonexistent/box.json")
	if !a.Allowed("192.168.0.1") {
		t.Error("RFC1918 must be allowed even with no files")
	}
	if a.Allowed("evil.example") {
		t.Error("unknown host must not be allowed when files are missing")
	}
}

func TestC2AllowAddAppends(t *testing.T) {
	dir := t.TempDir()
	allow := filepath.Join(dir, "c2-allow.txt")
	writeLines(t, allow, "seed.example")
	a := NewC2Allow(allow, "")
	if err := a.Add("newfp.example"); err != nil {
		t.Fatal(err)
	}
	a.Reload()
	if !a.Allowed("newfp.example") {
		t.Error("added host must be allowed after Add+Reload")
	}
	if !a.Allowed("seed.example") {
		t.Error("seed host must remain allowed")
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd packages/secubox-toolbox-ng && go test ./internal/sentinel/ -run TestC2Allow`
Expected: FAIL — `undefined: NewC2Allow`.

- [ ] **Step 3: Implement `c2allow.go`**

```go
// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package sentinel

// C2 auto-learn false-positive gate (#823 C2 autolearn): a host is "allowed"
// (never learned as C2) if it is a box-owned vhost, a private/loopback IP
// literal, or listed (suffix-matched) in the operator allowlist. Every source
// is fail-safe: a missing/corrupt file contributes no entries, never an error.

import (
	"encoding/json"
	"log"
	"net"
	"os"
	"strings"
	"sync"
)

type C2Allow struct {
	allowFile string
	boxFile   string

	mu      sync.RWMutex
	suffix  map[string]bool // host suffixes (allow entries + box vhosts), lowercased
}

// NewC2Allow builds the gate from an operator allowlist file (one host/suffix
// per line, # comments allowed) and a box-domains source (a HAProxy
// routes JSON whose KEYS are the box's own vhost domains). Either path may be
// "" or missing. Loads immediately (fail-safe).
func NewC2Allow(allowFile, boxFile string) *C2Allow {
	a := &C2Allow{allowFile: allowFile, boxFile: boxFile}
	a.Reload()
	return a
}

// Reload re-reads both sources into a fresh suffix set. Fail-safe.
func (a *C2Allow) Reload() {
	set := make(map[string]bool)
	for _, l := range readLinesSafe(a.allowFile) {
		l = strings.ToLower(strings.TrimSpace(l))
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		set[l] = true
	}
	for _, d := range readBoxDomainsSafe(a.boxFile) {
		d = strings.ToLower(strings.TrimSpace(d))
		if d != "" {
			set[d] = true
		}
	}
	a.mu.Lock()
	a.suffix = set
	a.mu.Unlock()
}

// Allowed reports whether host must NOT be learned as C2. Empty host → true
// (never learn a blank). Private/loopback/link-local IP literals → true.
// Otherwise suffix-matched against the allow set.
func (a *C2Allow) Allowed(host string) bool {
	if host == "" {
		return true
	}
	h := strings.ToLower(strings.TrimSpace(host))
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	// exact + progressive parent-suffix match: a.b.c matches entries a.b.c, b.c, c
	labels := strings.Split(h, ".")
	for i := 0; i < len(labels); i++ {
		if a.suffix[strings.Join(labels[i:], ".")] {
			return true
		}
	}
	return false
}

// Add appends host to the operator allowlist file (atomic rewrite). The
// in-memory set is refreshed by a subsequent Reload (caller's responsibility,
// so a batch of Adds costs one reload).
func (a *C2Allow) Add(host string) error {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" || a.allowFile == "" {
		return nil
	}
	existing := readLinesSafe(a.allowFile)
	for _, l := range existing {
		if strings.ToLower(strings.TrimSpace(l)) == host {
			return nil // already present
		}
	}
	existing = append(existing, host)
	return atomicWriteFile(a.allowFile, []byte(strings.Join(existing, "\n")+"\n"), 0o644)
}

// readLinesSafe returns the file's lines, or nil on any error.
func readLinesSafe(path string) []string {
	if path == "" {
		return nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return strings.Split(string(b), "\n")
}

// readBoxDomainsSafe returns the KEYS of a HAProxy-routes-style JSON object
// (the box's own vhost domains), or nil on any error.
func readBoxDomainsSafe(path string) []string {
	if path == "" {
		return nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		log.Printf("sentinel c2allow: box-domains %s unparseable (ignored): %v", path, err)
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// atomicWriteFile writes data to path via a temp file + rename in the same dir.
func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := path[:strings.LastIndex(path, "/")+1]
	f, err := os.CreateTemp(dir, ".c2tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Chmod(perm); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cd packages/secubox-toolbox-ng && go test ./internal/sentinel/ -run TestC2Allow -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-toolbox-ng/internal/sentinel/c2allow.go packages/secubox-toolbox-ng/internal/sentinel/c2allow_test.go
git commit -m "feat(sentinel): C2 autolearn false-positive allowlist gate (ref #ISSUE)"
```

---

### Task 2: `c2signal.go` — corroborating signals

**Files:**
- Create: `packages/secubox-toolbox-ng/internal/sentinel/c2signal.go`
- Test: `packages/secubox-toolbox-ng/internal/sentinel/c2signal_test.go`

**Interfaces:**
- Consumes: `shannonEntropy(string) float64` (behavioral.go, same package); `FlowMeta{Host,JA3,JA4,...}`.
- Produces: `type C2Signals struct{...}`; `func NewC2Signals(browserJA4 []string) *C2Signals`; `func (s *C2Signals) Observe(host string)` (updates rarity frequency); `func (s *C2Signals) Fired(m FlowMeta) []string` (returns the corroborating signal names that fired: subset of `"rare"`, `"non_browser_ja"`, `"dga"`).

- [ ] **Step 1: Write the failing test**

```go
package sentinel

import "testing"

func TestC2SignalsDGA(t *testing.T) {
	s := NewC2Signals([]string{"t13d1516h2_browserfp"})
	// high-entropy random-looking label → dga fires
	fired := s.Fired(FlowMeta{Host: "x7f3q9zk2vw8plmn.example", JA4: "t13d1516h2_browserfp"})
	if !contains(fired, "dga") {
		t.Errorf("dga signal expected, got %v", fired)
	}
	// ordinary word domain, browser JA4, and seen-often → no signals
	for i := 0; i < 60; i++ {
		s.Observe("news.example.com")
	}
	fired = s.Fired(FlowMeta{Host: "news.example.com", JA4: "t13d1516h2_browserfp"})
	if len(fired) != 0 {
		t.Errorf("no signals expected for common browser-JA4 word-domain, got %v", fired)
	}
}

func TestC2SignalsNonBrowserJA(t *testing.T) {
	s := NewC2Signals([]string{"t13d1516h2_browserfp"})
	for i := 0; i < 60; i++ {
		s.Observe("cdn.example.com")
	}
	// non-browser JA4 → non_browser_ja fires (host common, low entropy)
	fired := s.Fired(FlowMeta{Host: "cdn.example.com", JA4: "q99xxbotfp"})
	if !contains(fired, "non_browser_ja") {
		t.Errorf("non_browser_ja expected, got %v", fired)
	}
	// empty JA4/JA3 (unknown) must NOT count as non-browser (avoid FP on missing data)
	fired = s.Fired(FlowMeta{Host: "cdn.example.com"})
	if contains(fired, "non_browser_ja") {
		t.Errorf("empty JA must not fire non_browser_ja, got %v", fired)
	}
}

func TestC2SignalsRare(t *testing.T) {
	s := NewC2Signals(nil)
	// first-ever contact with a low-entropy word host, no JA → rare only
	fired := s.Fired(FlowMeta{Host: "portal.example.com"})
	if !contains(fired, "rare") {
		t.Errorf("rare expected for never-seen host, got %v", fired)
	}
}

func contains(ss []string, v string) bool {
	for _, s := range ss {
		if s == v {
			return true
		}
	}
	return false
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd packages/secubox-toolbox-ng && go test ./internal/sentinel/ -run TestC2Signals`
Expected: FAIL — `undefined: NewC2Signals`.

- [ ] **Step 3: Implement `c2signal.go`**

```go
// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package sentinel

// C2 auto-learn corroborating signals (#823): beaconing alone is not enough to
// learn a host — at least one of these independent signals must also fire, so a
// browser-driven periodic poll (admin dashboard) is not mistaken for a beacon.

import (
	"container/list"
	"strings"
	"sync"
)

const (
	// c2RareMaxHits: a host seen at most this many times across the daemon's
	// window counts as "rare". A real C2 destination stays rare; a CDN/portal
	// the user browses climbs past it quickly.
	c2RareMaxHits = 20
	// c2FreqCap bounds the rarity map (LRU).
	c2FreqCap = c2MaxEntries
	// c2DGAMinEntropy: Shannon entropy (bits/char) of the most-significant
	// label above which the domain looks algorithmically generated. Ordinary
	// words sit well below; a random 16-char label sits near log2(distinct).
	c2DGAMinEntropy = 3.6
	// c2DGAMinLen: don't call a short label DGA (too little signal).
	c2DGAMinLen = 10
)

type C2Signals struct {
	browser map[string]bool // known browser JA4/JA3 fingerprints

	mu    sync.Mutex
	freq  map[string]*list.Element // host → LRU element
	order *list.List               // front = most-recent
}

type freqEntry struct {
	host string
	hits int
}

func NewC2Signals(browserJA4 []string) *C2Signals {
	b := make(map[string]bool, len(browserJA4))
	for _, f := range browserJA4 {
		if f = strings.TrimSpace(f); f != "" {
			b[f] = true
		}
	}
	return &C2Signals{browser: b, freq: make(map[string]*list.Element), order: list.New()}
}

// Observe records one contact with host for the rarity estimate. Call on every
// flow (not only beacons) so "rare" reflects true global frequency.
func (s *C2Signals) Observe(host string) {
	if host == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if el, ok := s.freq[host]; ok {
		el.Value.(*freqEntry).hits++
		s.order.MoveToFront(el)
		return
	}
	el := s.order.PushFront(&freqEntry{host: host, hits: 1})
	s.freq[host] = el
	for s.order.Len() > c2FreqCap {
		back := s.order.Back()
		if back == nil {
			break
		}
		delete(s.freq, back.Value.(*freqEntry).host)
		s.order.Remove(back)
	}
}

func (s *C2Signals) hits(host string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if el, ok := s.freq[host]; ok {
		return el.Value.(*freqEntry).hits
	}
	return 0
}

// Fired returns the corroborating signal names present for m. Order-stable,
// deduped. Never panics on missing fields.
func (s *C2Signals) Fired(m FlowMeta) []string {
	var out []string
	if s.hits(m.Host) <= c2RareMaxHits {
		out = append(out, "rare")
	}
	// non-browser: only when a fingerprint is PRESENT and not a known browser.
	fp := m.JA4
	if fp == "" {
		fp = m.JA3
	}
	if fp != "" && !s.browser[fp] {
		out = append(out, "non_browser_ja")
	}
	if isDGA(m.Host) {
		out = append(out, "dga")
	}
	return out
}

// isDGA reports whether host's most-significant label looks algorithmically
// generated (long + high own-entropy). Fail-safe on empty/short input.
func isDGA(host string) bool {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "" {
		return false
	}
	labels := strings.Split(host, ".")
	// pick the longest label (the registrable label is usually the signal)
	cand := ""
	for _, l := range labels {
		if len(l) > len(cand) {
			cand = l
		}
	}
	if len(cand) < c2DGAMinLen {
		return false
	}
	return shannonEntropy(cand) >= c2DGAMinEntropy
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cd packages/secubox-toolbox-ng && go test ./internal/sentinel/ -run TestC2Signals -v`
Expected: PASS (3 tests).

> If `TestC2SignalsDGA` mis-fires on the chosen threshold, tune `c2DGAMinEntropy` so `x7f3q9zk2vw8plmn` (entropy ≈ 3.9) is DGA and `news`/`portal`/`cdn` are not — do NOT weaken the test's intent (a real word domain must never be DGA).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-toolbox-ng/internal/sentinel/c2signal.go packages/secubox-toolbox-ng/internal/sentinel/c2signal_test.go
git commit -m "feat(sentinel): C2 autolearn corroborating signals (rare/non-browser-JA/DGA) (ref #ISSUE)"
```

---

### Task 3: `c2cand.go` — candidate store + confirm + persistence

**Files:**
- Create: `packages/secubox-toolbox-ng/internal/sentinel/c2cand.go`
- Test: `packages/secubox-toolbox-ng/internal/sentinel/c2cand_test.go`

**Interfaces:**
- Produces:
  - `const c2MaxEntries = 2000`, `const c2MinWindows = 3`, `var c2MinSpanSec int64 = 1800`
  - `type C2Candidate struct { Host string; FirstSeen, LastSeen int64; Windows int; Devices map[string]bool; Signals map[string]bool; IntervalS float64 }` (JSON-tagged)
  - `type C2Cand struct{...}`; `func NewC2Cand(path string) *C2Cand` (loads persisted state, fail-safe)
  - `func (c *C2Cand) Record(host, mac string, ts int64, intervalS float64, signals []string) (promote bool, cand C2Candidate)` — updates/creates the candidate; returns `promote=true` exactly once when the promotion criteria are first met
  - `func (c *C2Cand) Snapshot() []C2Candidate`; `func (c *C2Cand) Remove(host string)`; `func (c *C2Cand) Persist() error` (atomic)

- [ ] **Step 1: Write the failing test**

```go
package sentinel

import (
	"path/filepath"
	"testing"
)

func TestC2CandPromotionRequiresSustained(t *testing.T) {
	c := NewC2Cand(filepath.Join(t.TempDir(), "cand.json"))
	base := int64(1_000_000)
	// window 1
	if p, _ := c.Record("c2.example", "devA", base, 60, []string{"rare", "dga"}); p {
		t.Fatal("must not promote on window 1")
	}
	// window 2 (still < c2MinWindows)
	if p, _ := c.Record("c2.example", "devA", base+900, 60, []string{"rare"}); p {
		t.Fatal("must not promote on window 2")
	}
	// window 3, span now 1800s (>= c2MinSpanSec) → promote once
	p, cand := c.Record("c2.example", "devA", base+1800, 60, []string{"rare"})
	if !p {
		t.Fatal("must promote on window 3 with span met")
	}
	if cand.Windows < c2MinWindows || cand.Host != "c2.example" {
		t.Errorf("bad candidate on promote: %+v", cand)
	}
	// subsequent records must NOT re-promote (latched)
	if p, _ := c.Record("c2.example", "devA", base+2700, 60, []string{"rare"}); p {
		t.Error("must not re-promote after first promotion")
	}
}

func TestC2CandSpanGuard(t *testing.T) {
	c := NewC2Cand(filepath.Join(t.TempDir(), "cand.json"))
	base := int64(2_000_000)
	// 3 windows but all within 10s → span not met → no promote
	c.Record("burst.example", "devA", base, 5, []string{"rare"})
	c.Record("burst.example", "devA", base+3, 5, []string{"rare"})
	p, _ := c.Record("burst.example", "devA", base+9, 5, []string{"rare"})
	if p {
		t.Error("must not promote a tight burst (span < c2MinSpanSec)")
	}
}

func TestC2CandPersistRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cand.json")
	c := NewC2Cand(path)
	c.Record("x.example", "devA", 100, 30, []string{"rare"})
	if err := c.Persist(); err != nil {
		t.Fatal(err)
	}
	c2 := NewC2Cand(path)
	if len(c2.Snapshot()) != 1 {
		t.Errorf("expected 1 candidate after reload, got %d", len(c2.Snapshot()))
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd packages/secubox-toolbox-ng && go test ./internal/sentinel/ -run TestC2Cand`
Expected: FAIL — `undefined: NewC2Cand`.

- [ ] **Step 3: Implement `c2cand.go`**

```go
// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package sentinel

// C2 auto-learn candidate lifecycle (#823): a beaconing host that passed the FP
// gate and carries >=1 corroborating signal becomes a candidate. It is promoted
// only when sustained across c2MinWindows separate beacon reports spanning at
// least c2MinSpanSec — never on a single burst.

import (
	"encoding/json"
	"os"
	"sync"
)

const (
	c2MaxEntries = 2000
	c2MinWindows = 3
)

var c2MinSpanSec int64 = 1800 // 30 min; var so tests/config can adjust

type C2Candidate struct {
	Host      string          `json:"host"`
	FirstSeen int64           `json:"first_seen"`
	LastSeen  int64           `json:"last_seen"`
	Windows   int             `json:"windows"`
	Devices   map[string]bool `json:"devices"`
	Signals   map[string]bool `json:"signals"`
	IntervalS float64         `json:"interval_s"`
	Promoted  bool            `json:"promoted"`
}

type C2Cand struct {
	path string
	mu   sync.Mutex
	m    map[string]*C2Candidate
}

// NewC2Cand loads persisted candidates from path (fail-safe: missing/corrupt →
// empty).
func NewC2Cand(path string) *C2Cand {
	c := &C2Cand{path: path, m: make(map[string]*C2Candidate)}
	if b, err := os.ReadFile(path); err == nil {
		var list []*C2Candidate
		if json.Unmarshal(b, &list) == nil {
			for _, cd := range list {
				if cd != nil && cd.Host != "" {
					if cd.Devices == nil {
						cd.Devices = map[string]bool{}
					}
					if cd.Signals == nil {
						cd.Signals = map[string]bool{}
					}
					c.m[cd.Host] = cd
				}
			}
		}
	}
	return c
}

// Record folds one beacon observation into host's candidate and reports whether
// this call is the FIRST to satisfy the promotion criteria (sustained across
// >=c2MinWindows spanning >=c2MinSpanSec). Latched: returns true at most once.
func (c *C2Cand) Record(host, mac string, ts int64, intervalS float64, signals []string) (bool, C2Candidate) {
	c.mu.Lock()
	defer c.mu.Unlock()

	cd := c.m[host]
	if cd == nil {
		cd = &C2Candidate{Host: host, FirstSeen: ts, Devices: map[string]bool{}, Signals: map[string]bool{}}
		c.m[host] = cd
		c.evictLocked()
	}
	cd.LastSeen = ts
	cd.Windows++
	cd.IntervalS = intervalS
	if mac != "" {
		cd.Devices[mac] = true
	}
	for _, s := range signals {
		cd.Signals[s] = true
	}

	promote := false
	if !cd.Promoted &&
		cd.Windows >= c2MinWindows &&
		(cd.LastSeen-cd.FirstSeen) >= c2MinSpanSec &&
		len(cd.Signals) >= 1 {
		cd.Promoted = true
		promote = true
	}
	return promote, *cd
}

// evictLocked keeps the map under c2MaxEntries by dropping the oldest-seen
// non-promoted candidate. Caller holds the lock.
func (c *C2Cand) evictLocked() {
	if len(c.m) <= c2MaxEntries {
		return
	}
	var victim string
	var oldest int64
	for h, cd := range c.m {
		if cd.Promoted {
			continue
		}
		if victim == "" || cd.LastSeen < oldest {
			victim, oldest = h, cd.LastSeen
		}
	}
	if victim != "" {
		delete(c.m, victim)
	}
}

func (c *C2Cand) Snapshot() []C2Candidate {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]C2Candidate, 0, len(c.m))
	for _, cd := range c.m {
		out = append(out, *cd)
	}
	return out
}

func (c *C2Cand) Remove(host string) {
	c.mu.Lock()
	delete(c.m, host)
	c.mu.Unlock()
}

// Persist atomically writes the candidate set to path.
func (c *C2Cand) Persist() error {
	c.mu.Lock()
	list := make([]*C2Candidate, 0, len(c.m))
	for _, cd := range c.m {
		list = append(list, cd)
	}
	c.mu.Unlock()
	b, err := json.Marshal(list)
	if err != nil {
		return err
	}
	if c.path == "" {
		return nil
	}
	return atomicWriteFile(c.path, b, 0o640)
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cd packages/secubox-toolbox-ng && go test ./internal/sentinel/ -run TestC2Cand -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-toolbox-ng/internal/sentinel/c2cand.go packages/secubox-toolbox-ng/internal/sentinel/c2cand_test.go
git commit -m "feat(sentinel): C2 autolearn candidate lifecycle + persistence (ref #ISSUE)"
```

---

### Task 4: `c2learn.go` — orchestrator + learned set + verdicts

**Files:**
- Create: `packages/secubox-toolbox-ng/internal/sentinel/c2learn.go`
- Test: `packages/secubox-toolbox-ng/internal/sentinel/c2learn_test.go`

**Interfaces:**
- Consumes: `NewBehavioral()`, `(*Behavioral).Analyze`, `C2Allow`, `C2Signals`, `C2Cand`, `Verdict`, `ClassBotnetC2`, `ActionReport`, `atomicWriteFile`.
- Produces:
  - `type C2Config struct { AllowFile, BoxFile, CandFile, LearnedFile string; BrowserJA4 []string }`
  - `type LearnedC2 struct { Host string; Signals []string; IntervalS float64; Devices int; FirstSeen, LastSeen int64 }` (JSON-tagged)
  - `func NewC2Learner(b *Behavioral, cfg C2Config) *C2Learner`
  - `func (l *C2Learner) Analyze(m MirrorMsg) []*Verdict` — satisfies the daemon `Analyzer` interface
  - `func (l *C2Learner) Learned() []LearnedC2`; `func (l *C2Learner) Candidates() []C2Candidate`; `func (l *C2Learner) Allow(host string) error` (allowlist + drop from learned/candidate)

- [ ] **Step 1: Write the failing test**

```go
package sentinel

import (
	"path/filepath"
	"testing"
)

func c2TestLearner(t *testing.T) *C2Learner {
	t.Helper()
	dir := t.TempDir()
	return NewC2Learner(NewBehavioral(), C2Config{
		AllowFile:   filepath.Join(dir, "allow.txt"),
		CandFile:    filepath.Join(dir, "cand.json"),
		LearnedFile: filepath.Join(dir, "learned.json"),
		BrowserJA4:  []string{"t13d1516h2_browserfp"},
	})
}

// A DGA host with a non-browser JA4, beaconed at a steady interval across
// enough windows/span, is learned; and re-contact then yields a botnet_c2
// verdict.
func TestC2LearnerPromotesRealC2(t *testing.T) {
	l := c2TestLearner(t)
	host := "x7f3q9zk2vw8plmn.example"
	mac := "devhashaa"
	// feed >= beaconMinHits at a constant 300s interval to trip Behavioral,
	// repeated across >= c2MinWindows spanning >= c2MinSpanSec.
	ts := int64(1_000_000)
	learned := false
	for w := 0; w < 4; w++ {
		for i := 0; i < 7; i++ {
			l.Analyze(MirrorMsg{Meta: FlowMeta{Host: host, MacHash: mac, JA4: "botfp99"}, TS: ts})
			ts += 300
		}
		if len(l.Learned()) > 0 {
			learned = true
		}
		// reset Behavioral's latch is not needed: new windows advance ts; the
		// learner records a candidate window each time Behavioral fires.
	}
	if !learned {
		t.Fatalf("expected host to be learned; learned=%v candidates=%v", l.Learned(), l.Candidates())
	}
	// re-contact a learned host → botnet_c2 report verdict
	vs := l.Analyze(MirrorMsg{Meta: FlowMeta{Host: host, MacHash: mac, JA4: "botfp99"}, TS: ts})
	found := false
	for _, v := range vs {
		if v.Class == ClassBotnetC2 && v.Action == ActionReport {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a report-only botnet_c2 verdict on re-contact, got %+v", vs)
	}
}

// An allowlisted host (box vhost / mail) beaconing with a browser JA4 is never
// learned.
func TestC2LearnerSuppressesAllowlisted(t *testing.T) {
	l := c2TestLearner(t)
	_ = l.Allow("mail.example.com") // operator/seed allow
	ts := int64(3_000_000)
	for w := 0; w < 5; w++ {
		for i := 0; i < 7; i++ {
			l.Analyze(MirrorMsg{Meta: FlowMeta{Host: "imap.mail.example.com", MacHash: "devB", JA4: "t13d1516h2_browserfp"}, TS: ts})
			ts += 300
		}
	}
	if len(l.Learned()) != 0 {
		t.Errorf("allowlisted host must never be learned, got %v", l.Learned())
	}
}

// A periodic host with a BROWSER JA4 and a common word domain (no corroborating
// signal) is never learned — periodicity alone is insufficient.
func TestC2LearnerNoSignalNoPromote(t *testing.T) {
	l := c2TestLearner(t)
	host := "dashboard.example.com"
	// make it "not rare": observe many times first
	for i := 0; i < 60; i++ {
		l.Analyze(MirrorMsg{Meta: FlowMeta{Host: host, MacHash: "devC", JA4: "t13d1516h2_browserfp"}, TS: int64(4_000_000 + i)})
	}
	ts := int64(5_000_000)
	for w := 0; w < 5; w++ {
		for i := 0; i < 7; i++ {
			l.Analyze(MirrorMsg{Meta: FlowMeta{Host: host, MacHash: "devC", JA4: "t13d1516h2_browserfp"}, TS: ts})
			ts += 300
		}
	}
	if len(l.Learned()) != 0 {
		t.Errorf("browser-JA4 common-word host must not be learned, got %v", l.Learned())
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd packages/secubox-toolbox-ng && go test ./internal/sentinel/ -run TestC2Learner`
Expected: FAIL — `undefined: NewC2Learner`.

- [ ] **Step 3: Implement `c2learn.go`**

```go
// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package sentinel

// C2 auto-learn orchestrator (#823): wraps the Behavioral beacon detector, and
// for each beacon runs the FP gate + corroborating signals + candidate lifecycle.
// A confirmed host joins the learned set (persisted, report-only) and re-contact
// with a learned host yields a botnet_c2 report verdict. All report-only.

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

const c2LearnedTTLSec int64 = 30 * 24 * 3600 // 30d; a quiet host ages out

type LearnedC2 struct {
	Host      string   `json:"host"`
	Signals   []string `json:"signals"`
	IntervalS float64  `json:"interval_s"`
	Devices   int      `json:"devices"`
	FirstSeen int64    `json:"first_seen"`
	LastSeen  int64    `json:"last_seen"`
}

type C2Config struct {
	AllowFile   string
	BoxFile     string
	CandFile    string
	LearnedFile string
	BrowserJA4  []string
}

type C2Learner struct {
	behavioral *Behavioral
	allow      *C2Allow
	signals    *C2Signals
	cand       *C2Cand
	learnedFN  string

	mu       sync.Mutex
	learned  map[string]*LearnedC2
	reported map[string]int64 // host → last re-contact verdict TS (throttle)
}

const c2RecontactThrottleSec int64 = 3600 // at most one re-contact verdict/host/hour

func NewC2Learner(b *Behavioral, cfg C2Config) *C2Learner {
	l := &C2Learner{
		behavioral: b,
		allow:      NewC2Allow(cfg.AllowFile, cfg.BoxFile),
		signals:    NewC2Signals(cfg.BrowserJA4),
		cand:       NewC2Cand(cfg.CandFile),
		learnedFN:  cfg.LearnedFile,
		learned:    make(map[string]*LearnedC2),
		reported:   make(map[string]int64),
	}
	l.loadLearned()
	return l
}

// Analyze satisfies the daemon Analyzer interface. It always runs Behavioral,
// updates the rarity estimate, learns from beacons, and re-emits for learned
// hosts. Never blocks; never auto-blocks.
func (l *C2Learner) Analyze(m MirrorMsg) []*Verdict {
	// rarity reflects ALL traffic, not only beacons.
	l.signals.Observe(m.Meta.Host)

	verdicts := l.behavioral.Analyze(m)

	// learned re-contact → throttled report verdict
	if v := l.recontact(m); v != nil {
		verdicts = append(verdicts, v)
	}

	// learn from any beacon verdict Behavioral produced
	for _, v := range verdicts {
		if v == nil || v.Class != ClassBotnetC2 || v.Evidence["pattern"] != "beaconing" {
			continue
		}
		l.observeBeacon(m, v)
	}
	return verdicts
}

func (l *C2Learner) observeBeacon(m MirrorMsg, beacon *Verdict) {
	host := m.Meta.Host
	if host == "" || l.allow.Allowed(host) {
		return
	}
	fired := l.signals.Fired(m.Meta)
	if len(fired) == 0 {
		return // no corroboration — periodicity alone never promotes
	}
	var interval float64
	if s := beacon.Evidence["interval_s"]; s != "" {
		// best-effort parse; 0 on failure (non-fatal)
		_, _ = fmtSscan(s, &interval)
	}
	promote, cd := l.cand.Record(host, m.Meta.MacHash, m.TS, interval, fired)
	_ = l.cand.Persist()
	if promote {
		l.promote(cd)
	}
}

func (l *C2Learner) promote(cd C2Candidate) {
	sigs := make([]string, 0, len(cd.Signals))
	for s := range cd.Signals {
		sigs = append(sigs, s)
	}
	l.mu.Lock()
	l.learned[cd.Host] = &LearnedC2{
		Host: cd.Host, Signals: sigs, IntervalS: cd.IntervalS,
		Devices: len(cd.Devices), FirstSeen: cd.FirstSeen, LastSeen: cd.LastSeen,
	}
	l.mu.Unlock()
	l.persistLearned()
}

// recontact returns a throttled report-only botnet_c2 verdict when m hits a
// host already in the learned set.
func (l *C2Learner) recontact(m MirrorMsg) *Verdict {
	host := m.Meta.Host
	if host == "" {
		return nil
	}
	l.mu.Lock()
	le, ok := l.learned[host]
	if !ok {
		l.mu.Unlock()
		return nil
	}
	if m.TS-l.reported[host] < c2RecontactThrottleSec {
		l.mu.Unlock()
		return nil
	}
	l.reported[host] = m.TS
	le.LastSeen = m.TS
	interval := le.IntervalS
	l.mu.Unlock()

	return &Verdict{
		Class:      ClassBotnetC2,
		Severity:   75,
		Confidence: 75,
		Action:     ActionReport, // learned behavioral — NEVER auto-block
		Evidence: map[string]string{
			"pattern": "learned_c2",
			"host":    host,
			"source":  "autolearn",
		},
		MacHash: m.Meta.MacHash,
		TS:      m.TS,
	}
}

func (l *C2Learner) Learned() []LearnedC2 {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]LearnedC2, 0, len(l.learned))
	for _, le := range l.learned {
		out = append(out, *le)
	}
	return out
}

func (l *C2Learner) Candidates() []C2Candidate { return l.cand.Snapshot() }

// Allow adds host to the operator allowlist and removes it from the learned set
// and candidate store (the "Ignorer" safety valve).
func (l *C2Learner) Allow(host string) error {
	if err := l.allow.Add(host); err != nil {
		return err
	}
	l.allow.Reload()
	l.mu.Lock()
	delete(l.learned, host)
	l.mu.Unlock()
	l.cand.Remove(host)
	l.persistLearned()
	_ = l.cand.Persist()
	return nil
}

func (l *C2Learner) loadLearned() {
	b, err := os.ReadFile(l.learnedFN)
	if err != nil {
		return
	}
	var list []*LearnedC2
	if json.Unmarshal(b, &list) != nil {
		return
	}
	now := time.Now
	_ = now
	l.mu.Lock()
	for _, le := range list {
		if le != nil && le.Host != "" {
			l.learned[le.Host] = le
		}
	}
	l.mu.Unlock()
}

// persistLearned atomically writes the learned set, dropping TTL-expired hosts.
// TTL is evaluated against the newest LastSeen in the set (monotonic-free — the
// daemon has no wall clock guarantee across restarts, so decay is relative).
func (l *C2Learner) persistLearned() {
	if l.learnedFN == "" {
		return
	}
	l.mu.Lock()
	var newest int64
	for _, le := range l.learned {
		if le.LastSeen > newest {
			newest = le.LastSeen
		}
	}
	list := make([]*LearnedC2, 0, len(l.learned))
	for h, le := range l.learned {
		if newest-le.LastSeen > c2LearnedTTLSec {
			delete(l.learned, h)
			continue
		}
		list = append(list, le)
	}
	l.mu.Unlock()
	if b, err := json.Marshal(list); err == nil {
		_ = atomicWriteFile(l.learnedFN, b, 0o640)
	}
}
```

Also add a tiny helper (same file) to avoid importing `fmt` twice via a named call — put at the bottom:

```go
// fmtSscan is a thin wrapper so the interval parse stays fail-safe + testable.
func fmtSscan(s string, f *float64) (int, error) {
	return sscanFloat(s, f)
}
```

And add to the top imports `"fmt"` and define `sscanFloat`:

```go
func sscanFloat(s string, f *float64) (int, error) { return fmt.Sscanf(s, "%f", f) }
```

> Simpler alternative the implementer may choose: `import "strconv"` and `v, _ := strconv.ParseFloat(s, 64); interval = v`. Pick ONE approach and drop the wrappers — the wrappers above exist only to keep the parse in one testable spot. Do not leave both.

- [ ] **Step 4: Run to verify pass**

Run: `cd packages/secubox-toolbox-ng && go test ./internal/sentinel/ -run TestC2Learner -v`
Expected: PASS (3 tests). If `TestC2LearnerPromotesRealC2` doesn't learn, verify Behavioral fires per window: `beaconMinHits=6` needs ≥6 hits and `beaconReported` latches per `(mac,host)` — so it fires only ONCE per key, not once per window. **This is a real design point:** because Behavioral latches, only the first window produces a beacon verdict, so the candidate never reaches `c2MinWindows`. Resolve by having `C2Learner` treat each *flow to a beaconing host after the first beacon* as a window tick OR by tracking windows on its own timing rather than relying on repeated Behavioral fires. Implementer: record a candidate window on the beacon verdict AND advance a window whenever a subsequent flow to that host arrives ≥ `meanInterval` later (own timing in `observeBeacon`), so sustained contact accumulates windows. Add a focused unit test for this window-advance logic.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-toolbox-ng/internal/sentinel/c2learn.go packages/secubox-toolbox-ng/internal/sentinel/c2learn_test.go
git commit -m "feat(sentinel): C2 autolearn orchestrator — learned set + report-only verdicts (ref #ISSUE)"
```

---

### Task 5: daemon wiring + `/c2` HTTP endpoints + seeded config

**Files:**
- Modify: `packages/secubox-toolbox-ng/cmd/sbx-sentinel/main.go` (buildAnalyzers + env)
- Modify: `packages/secubox-toolbox-ng/cmd/sbx-sentinel/http.go` (endpoints)
- Modify: `packages/secubox-toolbox-ng/cmd/sbx-sentinel/http_test.go`
- Create: `packages/secubox-toolbox-ng/debian/c2-allow.txt` (seed) + `debian/browser-ja4.txt` (seed)
- Modify: `packages/secubox-toolbox-ng/debian/rules` (install the seeds), `debian/sentinel.env` (new env vars)

**Interfaces:**
- Consumes: `NewC2Learner`, `(*C2Learner).Learned/Candidates/Allow`.
- Produces: `GET /c2/learned` → `[]LearnedC2`; `GET /c2/candidates` → `[]C2Candidate`; `POST /c2/allow` (form/JSON `host`) → `{"ok":true}`. All read endpoints localhost, bounded.

- [ ] **Step 1: Wire the learner in `buildAnalyzers`**

In `cmd/sbx-sentinel/main.go`, change the behavioral append to wrap it, and thread new config. Replace:
```go
	analyzers = append(analyzers, sentinel.NewBehavioral())
```
with:
```go
	c2 := sentinel.NewC2Learner(sentinel.NewBehavioral(), sentinel.C2Config{
		AllowFile:   getenvDefault("SENTINEL_C2_ALLOW_FILE", "/etc/secubox/sentinel/c2-allow.txt"),
		BoxFile:     getenvDefault("SENTINEL_C2_BOX_DOMAINS", "/etc/secubox/waf/haproxy-routes.json"),
		CandFile:    getenvDefault("SENTINEL_C2_CANDIDATES", "/var/lib/secubox/sentinel/c2-candidates.json"),
		LearnedFile: getenvDefault("SENTINEL_C2_LEARNED", "/var/lib/secubox/sentinel/c2-learned.json"),
		BrowserJA4:  readLinesFile(getenvDefault("SENTINEL_C2_BROWSER_JA4", "/usr/share/secubox/sentinel/browser-ja4.txt")),
	})
	analyzers = append(analyzers, c2)
	c2Learner = c2 // package-level handle for the status mux (see http.go wiring)
```
Add a package-level `var c2Learner *sentinel.C2Learner` and a tiny `readLinesFile(path) []string` helper (fail-safe: missing → nil). Pass `c2Learner` into `newStatusMux` (extend its signature to `newStatusMux(store *sentinel.Store, c2 *sentinel.C2Learner)` and update the caller + existing `http_test.go` calls to pass `nil`).

- [ ] **Step 2: Add the endpoints in `http.go`**

```go
	if c2 != nil {
		mux.HandleFunc("/c2/learned", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			writeJSON(w, c2.Learned())
		})
		mux.HandleFunc("/c2/candidates", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			writeJSON(w, c2.Candidates())
		})
		mux.HandleFunc("/c2/allow", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			host := r.FormValue("host")
			if host == "" {
				http.Error(w, "host required", http.StatusBadRequest)
				return
			}
			if err := c2.Allow(host); err != nil {
				http.Error(w, "allow failed", http.StatusInternalServerError)
				return
			}
			writeJSON(w, map[string]bool{"ok": true})
		})
	}
```

- [ ] **Step 3: Failing test in `http_test.go`**

```go
func TestC2Endpoints(t *testing.T) {
	store := openTestStore(t)
	dir := t.TempDir()
	c2 := sentinel.NewC2Learner(sentinel.NewBehavioral(), sentinel.C2Config{
		AllowFile:   filepath.Join(dir, "allow.txt"),
		CandFile:    filepath.Join(dir, "cand.json"),
		LearnedFile: filepath.Join(dir, "learned.json"),
	})
	mux := newStatusMux(store, c2)

	for _, path := range []string{"/c2/learned", "/c2/candidates"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s status %d", path, rec.Code)
		}
	}

	req := httptest.NewRequest(http.MethodPost, "/c2/allow", strings.NewReader("host=fp.example"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("allow status %d", rec.Code)
	}
}
```
Update the existing `newStatusMux(store)` call sites in `http_test.go` to `newStatusMux(store, nil)`.

- [ ] **Step 4: Seed files + packaging**

Create `debian/c2-allow.txt` (seed known-good periodic destinations — one per line, `#` comments):
```
# Seeded C2-autolearn allowlist — legitimate periodic traffic that must never
# be learned as C2. Operators may append hosts (also via the WebUI "Ignorer").
# Mail / webmail
mail.google.com
imap.gmail.com
outlook.office365.com
# OS / browser update + telemetry
clients2.google.com
update.googleapis.com
push.services.mozilla.com
# Time / connectivity checks
connectivitycheck.gstatic.com
time.cloudflare.com
# Monitoring / CDN keep-alives
ping.chartbeat.net
```
Create `debian/browser-ja4.txt` (a small seed of common browser JA4 fingerprints — comment that operators/feeds extend it; empty file is acceptable and simply disables the non_browser_ja signal shortcut):
```
# Known browser JA4/JA3 fingerprints (one per line). A destination polled with
# one of these is treated as browser-driven (an admin dashboard), so the
# non_browser_ja corroborating signal does NOT fire for it.
```
In `debian/rules` `override_dh_auto_install`, add installs:
```
	install -m 0644 debian/c2-allow.txt debian/secubox-toolbox-ng/etc/secubox/sentinel/c2-allow.txt
	install -m 0644 debian/browser-ja4.txt debian/secubox-toolbox-ng/usr/share/secubox/sentinel/browser-ja4.txt
```
(ensure the `etc/secubox/sentinel/` dir is created with `install -d` first). In `debian/sentinel.env`, append the new vars (documented, defaults matching the code):
```
SENTINEL_C2_ALLOW_FILE=/etc/secubox/sentinel/c2-allow.txt
SENTINEL_C2_BOX_DOMAINS=/etc/secubox/waf/haproxy-routes.json
SENTINEL_C2_CANDIDATES=/var/lib/secubox/sentinel/c2-candidates.json
SENTINEL_C2_LEARNED=/var/lib/secubox/sentinel/c2-learned.json
SENTINEL_C2_BROWSER_JA4=/usr/share/secubox/sentinel/browser-ja4.txt
```

- [ ] **Step 5: Run tests**

Run: `cd packages/secubox-toolbox-ng && go test ./cmd/sbx-sentinel/... ./internal/sentinel/...`
Expected: PASS (new `TestC2Endpoints` + all existing).

- [ ] **Step 6: Commit**

```bash
git add packages/secubox-toolbox-ng/cmd/sbx-sentinel/ packages/secubox-toolbox-ng/debian/
git commit -m "feat(sentinel): wire C2 learner into daemon + /c2 endpoints + seeded allowlist (ref #ISSUE)"
```

---

### Task 6: portal proxy + WebUI "C2 appris" sub-view

**Files:**
- Modify: `packages/secubox-toolbox/secubox_toolbox/sentinel_link.py` (fetch + allow POST, fail-safe)
- Modify: `packages/secubox-toolbox/secubox_toolbox/api.py` (proxy routes)
- Modify: `packages/secubox-toolbox/www/toolbox/index.html` (C2 sub-view + Ignorer)
- Test: `packages/secubox-toolbox/tests/test_sentinel_c2.py`

**Interfaces:**
- Consumes: daemon `GET /c2/learned`, `GET /c2/candidates`, `POST /c2/allow`.
- Produces: `sentinel_link.fetch_c2() -> dict` (`{"learned":[...],"candidates":[...]}`, fail-safe `{}`); `sentinel_link.c2_allow(host) -> bool`; routes `GET /admin/sentinel/c2` and `POST /admin/sentinel/c2/allow`.

- [ ] **Step 1: Failing Python test**

Create `packages/secubox-toolbox/tests/test_sentinel_c2.py`:
```python
from fastapi.testclient import TestClient
from secubox_toolbox.app import app
from secubox_toolbox import sentinel_link as sl

client = TestClient(app)


def test_c2_route_active(monkeypatch):
    monkeypatch.setattr(sl, "fetch_c2", lambda: {
        "learned": [{"host": "x7f3q9zk2vw8plmn.example", "signals": ["dga", "rare"],
                     "interval_s": 300.0, "devices": 1}],
        "candidates": [],
    })
    r = client.get("/admin/sentinel/c2")
    assert r.status_code == 200
    body = r.json()
    assert body["active"] is True
    assert body["learned"][0]["host"] == "x7f3q9zk2vw8plmn.example"


def test_c2_route_failsafe(monkeypatch):
    monkeypatch.setattr(sl, "fetch_c2", lambda: {})
    r = client.get("/admin/sentinel/c2")
    assert r.status_code == 200
    assert r.json() == {"active": False, "learned": [], "candidates": []}


def test_c2_allow_route(monkeypatch):
    called = {}
    monkeypatch.setattr(sl, "c2_allow", lambda host: called.setdefault("host", host) or True)
    r = client.post("/admin/sentinel/c2/allow", data={"host": "fp.example"})
    assert r.status_code == 200
    assert r.json()["ok"] is True
    assert called["host"] == "fp.example"
```

- [ ] **Step 2: Run to verify fail**

Run: `cd packages/secubox-toolbox && PYTHONPATH=../../common:. python3 -m pytest tests/test_sentinel_c2.py -q`
Expected: FAIL (routes 404 / `fetch_c2` missing).

- [ ] **Step 3: Implement `sentinel_link` helpers**

Add to `secubox_toolbox/sentinel_link.py`:
```python
import urllib.parse


def fetch_c2() -> dict:
    """Fetch learned + candidate C2 sets from the daemon. Fail-safe → {}."""
    learned = _get_json("/c2/learned")
    cands = _get_json("/c2/candidates")
    if learned is None and cands is None:
        return {}
    return {
        "learned": learned if isinstance(learned, list) else [],
        "candidates": cands if isinstance(cands, list) else [],
    }


def c2_allow(host: str) -> bool:
    """POST an allowlist request to the daemon. Fail-safe → False."""
    if not host:
        return False
    base = daemon_base()
    if not base:
        return False
    try:
        data = urllib.parse.urlencode({"host": host}).encode()
        req = urllib.request.Request(base + "/c2/allow", data=data,
                                     headers={"Content-Type": "application/x-www-form-urlencoded"})
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            return resp.status == 200
    except Exception as exc:
        log.debug("sentinel c2_allow failed: %s", exc)
        return False
```

- [ ] **Step 4: Implement the routes in `api.py`**

```python
@router.get("/admin/sentinel/c2")
async def admin_sentinel_c2() -> dict:
    """Learned + candidate C2 hosts for the WebUI 'C2 appris' view. Fail-safe."""
    data = sentinel_link.fetch_c2()
    if not data:
        return {"active": False, "learned": [], "candidates": []}
    return {"active": True,
            "learned": data.get("learned", []),
            "candidates": data.get("candidates", [])}


@router.post("/admin/sentinel/c2/allow")
async def admin_sentinel_c2_allow(host: str = Form(...)) -> dict:
    """Operator 'Ignorer' — allowlist a host so it is never learned as C2."""
    return {"ok": sentinel_link.c2_allow(host)}
```
(ensure `from fastapi import Form` is imported — check the existing imports; add if absent.)

- [ ] **Step 5: WebUI sub-view in `index.html`**

Inside the `#panel-sentinel` section, add a "C2 appris" block after the detections table, and a `loadSentinelC2()` called from `loadSentinel()`:
```html
      <div id="sentinel-c2" style="margin-top:1rem"></div>
```
```javascript
async function loadSentinelC2() {
    const el = document.getElementById('sentinel-c2');
    if (!el) return;
    const d = await J('/admin/sentinel/c2');
    if (d.__error || !d.active) { el.innerHTML = ''; return; }
    const row = (h, kind) => `<tr>
        <td>${esc(h.host)}</td>
        <td>${esc((h.signals || []).join(', '))}</td>
        <td>${h.interval_s ? Math.round(h.interval_s) + 's' : '—'}</td>
        <td>${h.devices || (h.windows ? 'w' + h.windows : '')}</td>
        <td>${kind === 'learned'
            ? `<button onclick="c2Ignore('${encodeURIComponent(h.host)}')">Ignorer</button>`
            : '<span class="v">candidat</span>'}</td></tr>`;
    const learned = (d.learned || []).map(h => row(h, 'learned')).join('');
    const cand = (d.candidates || []).map(h => row(h, 'candidate')).join('');
    el.innerHTML = `<h3>🕸️ C2 appris</h3>` + ((learned || cand)
        ? `<table><thead><tr><th>Hôte</th><th>Signaux</th><th>Intervalle</th><th>Vu</th><th></th></tr></thead><tbody>${learned}${cand}</tbody></table>`
        : '<span class="v">Aucun C2 appris ni candidat.</span>');
}

async function c2Ignore(hostEnc) {
    await fetch(`${API}/admin/sentinel/c2/allow`, {
        method: 'POST', credentials: 'same-origin',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'host=' + hostEnc,
    });
    loadSentinelC2();
}
```
Add `if (!stats.__error && data.active) loadSentinelC2();` at the end of `loadSentinel()` (only when the daemon is active).

- [ ] **Step 6: Run tests + JS check**

Run: `cd packages/secubox-toolbox && PYTHONPATH=../../common:. python3 -m pytest tests/test_sentinel_c2.py -q` → PASS.
Extract the inline `<script>` from `index.html` and `node --check` → exit 0.

- [ ] **Step 7: Commit**

```bash
git add packages/secubox-toolbox/secubox_toolbox/sentinel_link.py packages/secubox-toolbox/secubox_toolbox/api.py packages/secubox-toolbox/www/toolbox/index.html packages/secubox-toolbox/tests/test_sentinel_c2.py
git commit -m "feat(toolbox): WebUI C2 appris sub-view + Ignorer allowlist proxy (ref #ISSUE)"
```

---

## Self-Review

**Spec coverage:**
- FP gate (box-vhost / first-party-LAN / seeded allowlist / suffix) → Task 1. ✓
- Corroborating signals (rare / non-browser-JA4 / DGA) → Task 2. ✓
- Candidate→confirm (sustained ≥3 windows / ≥30m span / ≥1 signal, persisted, LRU) → Task 3. ✓
- Orchestrator, learned set, report-only verdicts, promotion, allow safety-valve, TTL decay → Task 4. ✓
- Daemon wiring + `/c2/*` endpoints + seeded `c2-allow.txt` + browser-JA4 + env → Task 5. ✓
- Portal proxy + WebUI C2 sub-view + Ignorer → Task 6. ✓
- Report-only invariant (Action=Report, Severity 75 < 85) → every emit in Task 4 + endpoints; enforced also by FinalizeAction. ✓
- Fail-safe file I/O (read→empty, write→atomic) → Tasks 1/3/4. ✓

**Placeholder scan:** No TBD/TODO. The one open design point (Behavioral latches per key so windows need own-timing) is called out explicitly in Task 4 Step 4 with the exact resolution to implement + a required test — not a hand-wave.

**Type consistency:** `LearnedC2`/`C2Candidate` field names used identically across Tasks 3/4/5/6 (host, signals, interval_s, devices, windows). `C2Config` fields (AllowFile/BoxFile/CandFile/LearnedFile/BrowserJA4) match Task 4 定義 and Task 5 wiring. `Allowed`/`Add`/`Reload` (Task 1) consumed by Task 4. `Fired`/`Observe` (Task 2) consumed by Task 4. `Record`/`Snapshot`/`Remove`/`Persist` (Task 3) consumed by Task 4. Endpoint paths `/c2/{learned,candidates,allow}` (Task 5) consumed by `sentinel_link.fetch_c2/c2_allow` (Task 6). `atomicWriteFile` defined once in Task 1, reused in Tasks 3/4.
