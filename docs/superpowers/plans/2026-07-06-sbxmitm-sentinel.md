<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# sbxmitm Sentinel Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a defensive threat-detection engine to the R3 toolbox MITM — an inline hot-path IOC gate in `sbxmitm` that neutralizes high-confidence threats, plus an async Go analyzer (`sbx-sentinel`) doing YARA/behavioral/spyware detection and emitting proposal/solution reports.

**Architecture:** All Go in `packages/secubox-toolbox-ng`. A pure `internal/sentinel` library (IOC model, pack loader, gate matcher, scorer, verdict store, behavioral, spyware, reporter) is consumed by two binaries: the existing `cmd/sbxmitm` (inline gate + neutralize + mirror) and a new `cmd/sbx-sentinel` daemon (async analysis). Content is a shipped base pack overlaid with live feeds.

**Tech Stack:** Go 1.22, SQLite (`modernc.org/sqlite`, pure-Go — no cgo), libyara via cgo (build-tagged, with a no-cgo stub), the existing `internal/forge` + sbxmitm neutralize primitives, `blacklist-sync` for feeds.

## Global Constraints

- **Defensive only** — detection + neutralization + reporting for the operator's own R3-consented tunnel. No offensive/exploit capability, no decrypting non-consented traffic.
- **Hot-path budget** — the inline gate does **IOC hash/trie matching only**; NEVER YARA or heavy analysis inline. A per-flow match must be O(1)/O(log n). Benchmarked.
- **Fail-open gate** — any matcher/pack error lets the flow pass (logged), never blocks browsing on a Sentinel bug.
- **Block vs report split** — only **high-confidence known-infra IOC** hits (`action=block/strip/sinkhole`) neutralize inline; **heuristic + zero-click + low-confidence are `action=report` only** (never auto-block). The shipped base pack MUST enforce this (a test asserts every `zero_click`/heuristic indicator is `action=report`).
- **Async fail-safe** — the mirror from sbxmitm to the analyzer is bounded fire-and-forget over a local socket; a down/slow analyzer never stalls sbxmitm (drop-with-count on overflow).
- **Privacy** — identity is `mac_hash` only; verdicts/reports carry no raw PII; verdict store has a bounded TTL.
- **No `waf_bypass`**; block pages route through the existing inspected path.
- **libyara is a NEW cgo dependency** — build-tagged (`//go:build cgo && yara`) with a pure-Go stub fallback so the default build (and CI without libyara) still compiles.
- **SQLite = `modernc.org/sqlite`** (pure Go), NOT mattn/go-sqlite3 (avoids a second cgo dep).
- Reuse `cmd/sbxmitm/policy.go`'s `LoadPolicy`/`maybeReload` hot-reload pattern for the pack loader.
- SPDX `LicenseRef-CMSD-1.0` header on every new `.go` file.
- Tests: `cd packages/secubox-toolbox-ng && go test ./internal/sentinel/... ./cmd/sbx-sentinel/... ./cmd/sbxmitm/...`

## File Structure

```
packages/secubox-toolbox-ng/
├── internal/sentinel/
│   ├── ioc.go / ioc_test.go              # IOC type model + IOCSet (per-type match structures)
│   ├── pack.go / pack_test.go            # base-pack parse + live-overlay merge + hot-reload
│   ├── gate.go / gate_test.go            # Match(FlowMeta) → *Verdict ; fail-open ; hot-path
│   ├── verdict.go                        # Verdict type (class/severity/confidence/action/evidence)
│   ├── store.go / store_test.go          # SQLite verdict store (modernc), TTL
│   ├── scorer.go / scorer_test.go        # class+severity+confidence→action ; report-only guard
│   ├── mirror.go / mirror_test.go        # bounded fire-and-forget mirror (client, in sbxmitm)
│   ├── behavioral.go / behavioral_test.go# beaconing / one-time-link / redirect / zero-click heuristics
│   ├── spyware.go / spyware_test.go      # commercial-spyware indicator correlation
│   ├── yara.go (//go:build cgo && yara)  # libyara wrapper
│   ├── yara_stub.go (//go:build !yara)   # no-op stub (default build)
│   └── report.go / report_test.go        # proposal/solution report (text/template)
├── cmd/sbx-sentinel/main.go              # async daemon: socket → analyzer → store → report
├── cmd/sbxmitm/
│   ├── sentinel.go / sentinel_test.go    # gate wiring into the per-flow hook + neutralize + mirror emit
│   └── (integrate into transparent.go:336 handleTransparent)
├── packs/base/                           # shipped base IOC/YARA pack (JSON) + yara rules
└── debian/                               # sbx-sentinel.service, config, retention timer, changelog
```

---

## Task 1: IOC model + IOCSet

**Files:** Create `internal/sentinel/ioc.go`, `internal/sentinel/ioc_test.go`

**Interfaces:**
- Produces: `type IOCType string` (consts `IOCDomain,IOCURLRegex,IOCIP,IOCJA3,IOCJA4,IOCCertSHA1,IOCFileSHA256,IOCYara`); `type ThreatClass string` (consts `ClassMalware,ClassTrojan,ClassBotnetC2,ClassPhishing,ClassSpywarePegasus,ClassSpywarePredator,ClassSpywareIntellexa,ClassZeroClick`); `type Action string` (`ActionBlock,ActionStrip,ActionSinkhole,ActionReport`); `type IOC struct{ Type IOCType; Value string; Class ThreatClass; Severity int; Source string; Action Action }`; `type IOCSet struct{...}` with `func NewIOCSet() *IOCSet`, `func (s *IOCSet) Add(IOC) error`, `func (s *IOCSet) MatchDomain(host string) (*IOC,bool)`, `MatchIP`, `MatchJA4`, `MatchCertSHA1`, `MatchFileSHA256`, `MatchURL(url string) (*IOC,bool)`. Domain/IP/JA/cert/hash → map lookups (O(1)); URL → compiled-regex slice.

- [ ] **Step 1: failing test** — `internal/sentinel/ioc_test.go`:
```go
// SPDX-License-Identifier: LicenseRef-CMSD-1.0
package sentinel

import "testing"

func TestIOCSetExactMatches(t *testing.T) {
	s := NewIOCSet()
	must := func(e error) { if e != nil { t.Fatal(e) } }
	must(s.Add(IOC{Type: IOCDomain, Value: "evil.example", Class: ClassBotnetC2, Severity: 90, Action: ActionBlock}))
	must(s.Add(IOC{Type: IOCJA4, Value: "t13d1516h2_8daaf6152771_02713d6af862", Class: ClassSpywarePegasus, Severity: 100, Action: ActionBlock}))
	must(s.Add(IOC{Type: IOCFileSHA256, Value: "abc123", Class: ClassMalware, Severity: 80, Action: ActionStrip}))

	if m, ok := s.MatchDomain("evil.example"); !ok || m.Class != ClassBotnetC2 { t.Fatal("domain miss") }
	if _, ok := s.MatchDomain("good.example"); ok { t.Fatal("false domain hit") }
	if m, ok := s.MatchJA4("t13d1516h2_8daaf6152771_02713d6af862"); !ok || m.Class != ClassSpywarePegasus { t.Fatal("ja4 miss") }
	if m, ok := s.MatchFileSHA256("abc123"); !ok || m.Action != ActionStrip { t.Fatal("hash miss") }
}

func TestIOCSetURLRegex(t *testing.T) {
	s := NewIOCSet()
	if err := s.Add(IOC{Type: IOCURLRegex, Value: `https://[a-z0-9]+\.free\.example/onetime/[A-Za-z0-9]{16}`, Class: ClassZeroClick, Severity: 70, Action: ActionReport}); err != nil { t.Fatal(err) }
	if m, ok := s.MatchURL("https://x1.free.example/onetime/ABCDEFGHIJKLMNOP"); !ok || m.Class != ClassZeroClick { t.Fatal("url miss") }
	if _, ok := s.MatchURL("https://normal.example/page"); ok { t.Fatal("false url hit") }
}

func TestIOCSetRejectsBadRegex(t *testing.T) {
	s := NewIOCSet()
	if err := s.Add(IOC{Type: IOCURLRegex, Value: `([`, Class: ClassPhishing, Action: ActionReport}); err == nil { t.Fatal("expected bad-regex error") }
}
```
- [ ] **Step 2: run — fails** — `go test ./internal/sentinel/ -run TestIOCSet` → build/undefined errors.
- [ ] **Step 3: implement `internal/sentinel/ioc.go`** — the types above; `IOCSet` holds `domains map[string]*IOC`, `ips map[string]*IOC`, `ja4 map[string]*IOC`, `ja3 map[string]*IOC`, `certs map[string]*IOC`, `hashes map[string]*IOC`, `urls []*compiledURL` (`struct{re *regexp.Regexp; ioc *IOC}`); `Add` switches on `Type`, compiles the regex for `IOCURLRegex` (return the compile error), and for host types stores lowercased keys. `MatchDomain` lowercases + also tries the registrable-domain fallback via a simple suffix check (exact map hit first). Each `Match*` returns `(*IOC,bool)`. Keep it allocation-light (no per-call maps).
- [ ] **Step 4: run — passes.**
- [ ] **Step 5: Commit** — `git add internal/sentinel/ioc.go internal/sentinel/ioc_test.go && git commit -m "feat(sentinel): IOC model + IOCSet matchers (ref #823)"`

---

## Task 2: Pack loader + hot-reload

**Files:** Create `internal/sentinel/pack.go`, `internal/sentinel/pack_test.go`; Reference: `cmd/sbxmitm/policy.go:196` `LoadPolicy` + `:428` `maybeReload`

**Interfaces:**
- Consumes: `IOCSet`, `IOC` (Task 1).
- Produces: `type Pack struct{ Version string; IOCs []IOC; YaraRules []string }`; `func LoadBasePack(path string) (*Pack, error)` (parse a JSON pack file); `func MergePacks(base *Pack, overlays ...*Pack) *IOCSet` (base first, overlays add/override by `(Type,Value)`); `type Loader struct{...}` with `func NewLoader(baseDir, overlayDir string) (*Loader, error)`, `func (l *Loader) Set() *IOCSet` (current merged set, safe for concurrent read via atomic pointer), `func (l *Loader) MaybeReload()` (re-read if any pack file mtime changed — mirror `policy.go maybeReload`), and `func (l *Loader) YaraRules() []string`.

- [ ] **Step 1: failing test** — `pack_test.go`: write a base pack JSON to a temp dir (`{"version":"1","iocs":[{"type":"domain","value":"c2.example","class":"botnet_c2","severity":90,"action":"block"}]}`), `NewLoader(dir,"")`, assert `Set().MatchDomain("c2.example")` hits; write an overlay pack adding `{"type":"domain","value":"pegasus.example","class":"spyware_pegasus","action":"block"}`, touch it, `MaybeReload()`, assert both hit; assert a corrupt overlay file is ignored (base retained) and `MaybeReload` doesn't panic.
- [ ] **Step 2: run — fails.**
- [ ] **Step 3: implement** — JSON tags on `IOC`/`Pack`; `LoadBasePack` reads+unmarshals; `MergePacks` builds an `IOCSet`; `Loader` stores `baseDir`/`overlayDir`, an `atomic.Pointer[IOCSet]`, and a `map[string]time.Time` of file mtimes; `MaybeReload` re-globs `*.json`, re-loads on any mtime change, skips a file that fails to parse (log + keep prior), stores the new set atomically. Follow `policy.go`'s mtime/reload structure.
- [ ] **Step 4: run — passes.**
- [ ] **Step 5: Commit** — `feat(sentinel): pack loader + live-overlay merge + hot-reload (ref #823)`

---

## Task 3: Inline gate matcher

**Files:** Create `internal/sentinel/gate.go`, `internal/sentinel/gate_test.go`

**Interfaces:**
- Consumes: `IOCSet` (Task 1), `Loader` (Task 2), `Verdict`/`ThreatClass`/`Action` (Task 1 + Task 4 defines `Verdict`; to avoid a cycle, define `Verdict` in Task 4's `verdict.go` and have Task 3 import it — sequence Task 4 before finalizing, or define `Verdict` here and Task 4 reuses. DECISION: define `Verdict` in `verdict.go` as part of THIS task's prerequisites — move the `Verdict` struct into Task 3 and have Task 4's store consume it.)
- Produces: `type FlowMeta struct{ Host, URL, ClientIP, JA3, JA4, CertSHA1, FileSHA256, MacHash string }`; `type Gate struct{ loader *Loader }`; `func NewGate(l *Loader) *Gate`; `func (g *Gate) Match(m FlowMeta) *Verdict` — returns the highest-severity matching `*Verdict` or `nil`; **never panics** (recover→nil, log). Also `verdict.go`: `type Verdict struct{ Class ThreatClass; Severity, Confidence int; Action Action; Evidence map[string]string; MacHash string; TS int64 }`.

- [ ] **Step 1: failing test** — `gate_test.go`: build a `Loader` over a temp base pack with a `block` domain + a `report` url-regex; `g := NewGate(l)`; assert `Match(FlowMeta{Host:"c2.example"})` returns a Verdict with `Action==ActionBlock`; a benign flow returns `nil`; assert **fail-open**: inject a Gate whose loader Set is nil → `Match` returns `nil` without panicking (wrap the nil deref in recover).
- [ ] **Step 2: run — fails.**
- [ ] **Step 3: implement `verdict.go` + `gate.go`** — `Match` calls `g.loader.MaybeReload()` then queries the set in cheap order (domain, ip, ja4, ja3, cert, hash, then url-regex last), keeps the highest `Severity` hit, builds a `Verdict` copying `Class/Severity/Action` + `Evidence{"ioc_type":..,"ioc_value":..,"source":..}`; wrap the whole body in `defer func(){ recover() }()` returning nil on panic. Confidence for a direct IOC hit = severity (known-infra = high). No allocations beyond the returned Verdict.
- [ ] **Step 4: run — passes.**
- [ ] **Step 5: Commit** — `feat(sentinel): inline gate matcher (fail-open, highest-severity) (ref #823)`

---

## Task 4: Verdict store (SQLite)

**Files:** Create `internal/sentinel/store.go`, `internal/sentinel/store_test.go`; add `modernc.org/sqlite` to `go.mod`

**Interfaces:**
- Consumes: `Verdict` (Task 3).
- Produces: `type Store struct{...}`; `func OpenStore(path string) (*Store, error)` (opens/creates the SQLite db + `verdicts` table); `func (s *Store) Record(v *Verdict) error`; `func (s *Store) Recent(limit int) ([]Verdict, error)`; `func (s *Store) ByMac(macHash string, limit int) ([]Verdict, error)`; `func (s *Store) Prune(olderThan time.Duration) (int, error)`; `func (s *Store) Close() error`. Schema: `verdicts(id INTEGER PK, ts INTEGER, class TEXT, severity INT, confidence INT, action TEXT, mac_hash TEXT, evidence TEXT/*json*/, report_id TEXT)`; index on `ts`, `mac_hash`.

- [ ] **Step 1: failing test** — `store_test.go`: `OpenStore(t.TempDir()+"/s.db")`; `Record` a verdict; `Recent(10)` returns it with fields intact (evidence round-trips as JSON); `ByMac` filters; `Prune(0)` removes old rows and returns the count; concurrent `Record` from 4 goroutines doesn't error (WAL + a `sync.Mutex` around writes).
- [ ] **Step 2: run — fails.**
- [ ] **Step 3: implement** — `database/sql` + `_ "modernc.org/sqlite"`, `sql.Open("sqlite", path)`, `PRAGMA journal_mode=WAL`, a `sync.Mutex` around writes; `Record` marshals `Evidence` to JSON; `Recent/ByMac` scan rows; `Prune` deletes `ts < now-olderThan`.
- [ ] **Step 4: run — passes** (`go test ./internal/sentinel/ -run TestStore`).
- [ ] **Step 5: Commit** — `feat(sentinel): SQLite verdict store (modernc, WAL, TTL prune) (ref #823)`

---

## Task 5: Scorer (report-only guard)

**Files:** Create `internal/sentinel/scorer.go`, `internal/sentinel/scorer_test.go`

**Interfaces:**
- Consumes: `Verdict`, `ThreatClass`, `Action` (Task 3).
- Produces: `func FinalizeAction(v *Verdict) Action` — enforces the block/report split: if `v.Class ∈ {ClassZeroClick}` OR `v.Confidence < HighConfidenceThreshold` (const `= 85`) → returns `ActionReport` regardless of the IOC's declared action; else returns the IOC's `v.Action`. Const `HighConfidenceThreshold = 85`. Also `func IsHeuristicClass(c ThreatClass) bool`.

- [ ] **Step 1: failing test** — `scorer_test.go`: a `ClassBotnetC2` verdict with `Confidence 90, Action ActionBlock` → `FinalizeAction == ActionBlock`; a `ClassZeroClick` verdict with `Action ActionBlock` (mis-declared) → forced to `ActionReport`; a `ClassMalware` with `Confidence 60, Action ActionStrip` → `ActionReport` (below threshold). This is the safety-critical test.
- [ ] **Step 2: run — fails.**
- [ ] **Step 3: implement** as specified.
- [ ] **Step 4: run — passes.**
- [ ] **Step 5: Commit** — `feat(sentinel): action scorer — heuristic/low-confidence forced report-only (ref #823)`

---

## Task 6: Bounded mirror channel

**Files:** Create `internal/sentinel/mirror.go`, `internal/sentinel/mirror_test.go`

**Interfaces:**
- Produces: `type MirrorMsg struct{ Meta FlowMeta; Body []byte /*capped*/; TS int64 }`; `type Mirror struct{...}`; `func NewMirror(socketPath string, queue int, bodyCap int) *Mirror`; `func (m *Mirror) Emit(msg MirrorMsg)` — **non-blocking**: JSON-encodes + sends on a buffered channel; on full channel → increments a dropped counter and returns immediately (fire-and-forget); a background goroutine dials the unix socket and writes queued msgs, reconnecting on failure. `func (m *Mirror) Dropped() uint64`. `func (m *Mirror) Close() error`. Body is truncated to `bodyCap`.

- [ ] **Step 1: failing test** — `mirror_test.go`: start a unix-socket listener in the test that collects newline-delimited JSON msgs; `NewMirror(sock, 8, 1024)`; `Emit` 3 msgs → the listener receives 3; assert a body > bodyCap is truncated; assert overflow: with `queue=1` and no reader draining, `Emit` many → `Dropped() > 0` and `Emit` never blocks (run under a `time.After` guard).
- [ ] **Step 2: run — fails.**
- [ ] **Step 3: implement** — buffered `chan MirrorMsg`; `Emit` uses `select { case ch<-msg: default: atomic.AddUint64(&dropped,1) }`; a writer goroutine dials `net.Dial("unix",...)`, JSON-encodes each msg + `\n`, reconnects with backoff on write error. Truncate `Body` in `Emit`.
- [ ] **Step 4: run — passes.**
- [ ] **Step 5: Commit** — `feat(sentinel): bounded fire-and-forget mirror channel (drop-with-count) (ref #823)`

---

## Task 7: sbxmitm inline integration + neutralize + perf bench

**Files:** Create `cmd/sbxmitm/sentinel.go`, `cmd/sbxmitm/sentinel_test.go`; Modify `cmd/sbxmitm/transparent.go` (the `handleTransparent` response path, ~line 336) + `cmd/sbxmitm/main.go` (wire construction + env flags); Reference neutralize: `poisonSetCookies`, `newSWNeuter`, `internal/forge`

**Interfaces:**
- Consumes: `sentinel.Gate`, `sentinel.FinalizeAction`, `sentinel.Mirror`, `sentinel.FlowMeta` (Tasks 3/5/6).
- Produces: `type sentinelHook struct{ gate *sentinel.Gate; mirror *sentinel.Mirror; enabled bool }`; `func newSentinelHook() *sentinelHook` (reads `SENTINEL_ENABLED`, pack dirs, mirror socket from env; disabled → all methods no-op); `func (h *sentinelHook) inspect(meta sentinel.FlowMeta, respBody []byte) (action sentinel.Action, blockPage []byte)` — calls `gate.Match` → `FinalizeAction`; on `ActionBlock/Sinkhole` returns a Sentinel block page (mirror the WAF 421 page style); on `ActionStrip` returns `(ActionStrip,nil)` (caller drops the body); on `ActionReport`/none → mirrors the flow (bounded) and returns `(ActionReport,nil)` (flow proceeds). Wired into the response path AFTER JA4/host are known.

- [ ] **Step 1: failing unit test** — `sentinel_test.go`: build a `sentinelHook` with a `Gate` over a temp pack containing a `block` domain; `inspect(FlowMeta{Host:"c2.example"}, nil)` → `action==ActionBlock` and a non-empty block page; a benign host → `action==ActionReport` (or none) and the flow is NOT blocked; disabled hook → always no-op passthrough. Add a **benchmark** `BenchmarkSentinelInspectMiss` over a benign flow asserting (via `-benchtime`) it's allocation-light — document the hot-path budget in a comment (target: < ~2µs/op, 0-1 allocs on a miss).
- [ ] **Step 2: run — fails** (`go test ./cmd/sbxmitm/ -run TestSentinel`).
- [ ] **Step 3: implement `sentinel.go`** (the hook) then wire it into `transparent.go`'s response handling: after the response headers + JA4 are available, build `FlowMeta`, call `h.inspect(...)`; on `ActionBlock/Sinkhole` write the block page instead of the upstream response; on `ActionStrip` replace the body with empty; else proceed. Guard everything so a disabled or erroring hook is a passthrough (fail-open — reuse the recover in `Gate.Match`). Add env flags in `main.go` (`SENTINEL_ENABLED`, `SENTINEL_PACK_DIR`, `SENTINEL_OVERLAY_DIR`, `SENTINEL_MIRROR_SOCK`). Do NOT regress existing sbxmitm tests.
- [ ] **Step 4: run — passes** — `go test ./cmd/sbxmitm/...` (all existing + new green); run `go test -bench BenchmarkSentinel -benchmem ./cmd/sbxmitm/` and record the ns/op + allocs in the commit message.
- [ ] **Step 5: Commit** — `feat(sbxmitm): inline Sentinel gate — neutralize high-confidence, mirror rest, fail-open (ref #823)`

---

## Task 8: sbx-sentinel async daemon scaffold

**Files:** Create `cmd/sbx-sentinel/main.go`, `cmd/sbx-sentinel/main_test.go`

**Interfaces:**
- Consumes: `sentinel.MirrorMsg`, `sentinel.Store`, `sentinel.Gate`/`Loader` (re-run richer matching async), `sentinel.FinalizeAction`.
- Produces: a daemon that listens on the mirror unix socket, decodes newline-JSON `MirrorMsg`, runs the analyzer pipeline (Task 9/10/11 plug in here via a `type Analyzer interface{ Analyze(MirrorMsg) []*Verdict }` slice), records verdicts to the `Store`, and runs a periodic `Prune`. `func run(cfg Config) error` testable with a fake socket + in-memory analyzer.

- [ ] **Step 1: failing test** — `main_test.go`: start `run` with a temp socket + temp db + a stub analyzer that returns one `Verdict` for any msg; connect, send a `MirrorMsg` JSON line; assert the verdict lands in the `Store` (poll `Recent`); assert a malformed line is skipped (no crash); assert graceful shutdown via context.
- [ ] **Step 2: run — fails.**
- [ ] **Step 3: implement** — `net.Listen("unix",...)`, per-conn `bufio.Scanner` decoding lines, each msg → run every `Analyzer` → `FinalizeAction` on each verdict → `Store.Record`; a ticker calls `Store.Prune(cfg.TTL)`; context-cancel closes the listener. Analyzers are injected (empty slice = scaffold).
- [ ] **Step 4: run — passes.**
- [ ] **Step 5: Commit** — `feat(sentinel): sbx-sentinel async daemon scaffold + store wiring (ref #823)`

---

## Task 9: YARA engine (cgo, build-tagged) + stub

**Files:** Create `internal/sentinel/yara.go` (`//go:build cgo && yara`), `internal/sentinel/yara_stub.go` (`//go:build !yara`), `internal/sentinel/yara_test.go` (`//go:build yara`); add `github.com/hillu/go-yara/v4` to go.mod (behind the tag)

**Interfaces:**
- Produces (both files, same signatures): `type YaraEngine struct{...}`; `func NewYaraEngine(rulePaths []string) (*YaraEngine, error)`; `func (y *YaraEngine) Scan(body []byte) []string` (returns matched rule names); `func (y *YaraEngine) Close() error`. The **stub** (`!yara`) returns an engine whose `Scan` always returns `nil` and `NewYaraEngine` succeeds — so the default build compiles + runs with YARA simply disabled. It implements `sentinel.Analyzer` via a small adapter `func (y *YaraEngine) Analyze(m MirrorMsg) []*Verdict`.

- [ ] **Step 1: failing test** (`yara_test.go`, `//go:build yara`) — compile a trivial rule (`rule t { strings: $a = "EICAR-STANDARD" condition: $a }`), `NewYaraEngine`, `Scan([]byte("...EICAR-STANDARD..."))` returns `["t"]`; a clean body returns nil. Also a **stub test** (no build tag) asserting `NewYaraEngine(nil)` succeeds and `Scan` returns nil (proves the default build path).
- [ ] **Step 2: run — fails** — stub test first: `go test ./internal/sentinel/ -run TestYaraStub` (default build).
- [ ] **Step 3: implement** — `yara_stub.go` (no-op) makes the default build pass; `yara.go` wraps go-yara `Compiler`/`Rules`/`ScanMem`. Document in the file header: the tagged build needs `libyara-dev`; the deb build uses the stub unless `-tags yara` + libyara present (Task 12 decides the shipped build).
- [ ] **Step 4: run — passes** — default: `go test ./internal/sentinel/` (stub). If libyara present: `go test -tags yara ./internal/sentinel/`.
- [ ] **Step 5: Commit** — `feat(sentinel): YARA engine (cgo, build-tagged) + no-cgo stub (ref #823)`

---

## Task 10: Behavioral engine

**Files:** Create `internal/sentinel/behavioral.go`, `internal/sentinel/behavioral_test.go`

**Interfaces:**
- Consumes: `MirrorMsg`, `FlowMeta`, `Verdict`.
- Produces: `type Behavioral struct{...}` (keeps bounded per-`(macHash,host)` timing state); `func NewBehavioral() *Behavioral`; `func (b *Behavioral) Analyze(m MirrorMsg) []*Verdict` implementing `Analyzer`. Heuristics: (a) **beaconing** — ≥ N (const 6) requests to the same host from one mac at near-constant intervals (low jitter) → `ClassBotnetC2`, `ActionReport`, confidence ~70; (b) **one-time-link / suspicious redirect** — a URL matching a high-entropy one-time-token shape delivered then never revisited → `ClassZeroClick`, `ActionReport`, confidence ~60; (c) bounded LRU state so memory can't grow unbounded.

- [ ] **Step 1: failing test** — feed 6 msgs same mac+host at ~equal `TS` deltas → one `ClassBotnetC2` report verdict; feed a one-time-link URL msg → one `ClassZeroClick` report verdict; assert BOTH have `Action==ActionReport` (never block); assert unrelated single requests produce no verdict; assert state is LRU-bounded (feed > cap distinct hosts, no unbounded growth — check map size ≤ cap).
- [ ] **Step 2: run — fails.**
- [ ] **Step 3: implement** — per-key ring buffer of recent timestamps; jitter = stddev/mean of deltas; entropy check on the URL last path segment; LRU map with a cap (const 4096). All emitted verdicts hardcode `ActionReport`.
- [ ] **Step 4: run — passes.**
- [ ] **Step 5: Commit** — `feat(sentinel): behavioral engine — beaconing + zero-click heuristics (report-only) (ref #823)`

---

## Task 11: Spyware indicator engine + commercial-spyware base pack

**Files:** Create `internal/sentinel/spyware.go`, `internal/sentinel/spyware_test.go`, `packs/base/spyware.json`, `packs/base/malware.json`, `packs/base/botnet.json`, `packs/base/README.md`

**Interfaces:**
- Consumes: `IOCSet`/`Loader`, `MirrorMsg`, `Verdict`.
- Produces: `type Spyware struct{ set *IOCSet }`; `func NewSpyware(l *Loader) *Spyware`; `func (s *Spyware) Analyze(m MirrorMsg) []*Verdict` — correlates a flow's domain/JA4/cert/URL against the spyware-class IOCs in the loaded set; a known-infra hit (`spyware_pegasus/predator/intellexa`, high severity) → verdict with the IOC's action (block); a `zero_click` hit → forced report (via FinalizeAction). The base `packs/base/spyware.json` ships the commercial-spyware indicators sourced from Amnesty MVT / Citizen Lab (domains, C2, JA3/JA4, cert-sha1, delivery url_regex), each tagged with its `source`, and every `zero_click`/heuristic entry `action=report`.

- [ ] **Step 1: failing test** — load a `Loader` over `packs/base/`; a `MirrorMsg` whose `FlowMeta.Host` == a shipped Pegasus C2 domain → `Analyze` returns a `ClassSpywarePegasus` verdict; a `zero_click` url match → a report-only verdict. **Security test** `TestBasePackZeroClickIsReportOnly`: load every base pack, assert EVERY IOC with `Class==ClassZeroClick` (and every heuristic class) has `Action==ActionReport` — the shipped-content safety invariant.
- [ ] **Step 2: run — fails.**
- [ ] **Step 3: implement** `spyware.go` + author the base packs. Seed `spyware.json` with real, publicly-documented commercial-spyware indicators (Amnesty MVT `pegasus.stix2` domains, Citizen Lab Predator/Intellexa domains), each with `"source":"amnesty-mvt"` / `"citizen-lab"`; zero-click delivery URL patterns as `action:"report"`. `malware.json`/`botnet.json` seed a small set from abuse.ch categories (documented placeholders that the live overlay expands). Keep the base pack small + documented in `README.md` (provenance + that the live overlay is authoritative for volume).
- [ ] **Step 4: run — passes** — including `TestBasePackZeroClickIsReportOnly`.
- [ ] **Step 5: Commit** — `feat(sentinel): spyware indicator engine + commercial-spyware base pack (MVT/CitizenLab) (ref #823)`

---

## Task 12: Live feed overlay + reporter + WebUI/API + packaging

**Files:** Create `internal/sentinel/report.go` + `report_test.go`; `sbin/secubox-sentinel-feeds` (fetch MVT/CitizenLab/abuse.ch → overlay dir); `debian/secubox-toolbox-ng` additions: `sbx-sentinel.service`, `secubox-sentinel-feeds.{service,timer}`, config; extend the toolbox portal/ng WebUI + API for verdicts/reports; changelog + build.

**Interfaces:**
- Consumes: `Store`, `Verdict` (reporter reads verdicts → report text).
- Produces: `func RenderReport(v Verdict) string` (a proposal/solution report: what/evidence/why/recommended mitigation, via `text/template`); the feeds fetcher writing signed/validated overlays into `SENTINEL_OVERLAY_DIR`; systemd units running `sbx-sentinel` + the feeds timer; an API route `GET /api/v1/toolbox/sentinel/{verdicts,report/{id}}` surfaced in the existing toolbox API + a WebUI panel (mirror an existing toolbox WebUI list view); `/stats`-style `{detections, blocked, spyware}` for the sidebar.

- [ ] **Step 1: reporter test** — `report_test.go`: a `ClassSpywarePegasus` blocked verdict → `RenderReport` contains the class, the matched IOC evidence, "blocked"/"neutralized", and a recommended-mitigation line; a `ClassZeroClick` report verdict → contains "reported (not blocked)" + advice. Assert no raw PII beyond `mac_hash`.
- [ ] **Step 2: run — fails; Step 3: implement `report.go`; Step 4: passes.**
- [ ] **Step 5: feeds fetcher** — `sbin/secubox-sentinel-feeds` (bash, `set -euo pipefail`, SPDX): fetch the MVT + Citizen Lab + abuse.ch indicator files over TLS, validate (non-empty, parses as the pack JSON), write atomically into the overlay dir; fail-safe (a fetch error keeps the last good overlay, never wipes). `bash -n` clean.
- [ ] **Step 6: systemd + config** — `debian/sbx-sentinel.service` (`User=secubox` or the toolbox-ng worker user, `RuntimeDirectoryPreserve=yes`, ReadWritePaths incl. `/var/lib/secubox/sentinel` + overlay dir), `secubox-sentinel-feeds.timer` (daily), config keys (enabled, TTL, thresholds) in the toolbox config; wire `sbx-sentinel` + the sbxmitm `SENTINEL_*` env into the ng deploy. Build the toolbox-ng package (`dpkg-buildpackage` — the DEFAULT build uses the YARA stub; document the `-tags yara` variant + `libyara-dev` for a YARA-enabled build).
- [ ] **Step 7: WebUI/API** — add the `/api/v1/toolbox/sentinel/*` routes (verdicts list, single report, `/stats`) to the toolbox API (plain handlers) + a WebUI verdicts panel (mirror an existing toolbox list view) + the sidebar `/stats` metrics line. Document (do not hard-bypass the WAF).
- [ ] **Step 8: verify + Commit** — `go test ./... ` green (default build, stub YARA); package builds; `git commit -m "feat(sentinel): live feed overlay + reporter + WebUI/API + packaging (ref #823)"`

---

## Deployment (post-merge, human-run — gated)
Deploy `secubox-toolbox-ng` with Sentinel to gk2 (R3 host): enable `SENTINEL_ENABLED`, start `sbx-sentinel` + the feeds timer, restart the ng-workers to load the gate; verify the base pack loads, a known-bad test domain is neutralized, a benign flow is untouched (hot-path budget), the feeds overlay lands, and a detection produces a report in the WebUI. Enabling inline blocking on live tunnel traffic is gated on explicit go.

## Self-Review Notes
- **Spec coverage:** §4.1 gate→Task 3/7; analyzer→Task 8; YARA→Task 9; behavioral→Task 10; spyware+packs→Task 11; §4.2 IOC model/pack→Task 1/2; §4.3 verdict/action/report→Task 3/4/5/12; feeds→Task 12; store→Task 4; mirror/fail-safe→Task 6/7/8; §6 hot-path/fail-open/report-only/privacy→Tasks 3/5/7/10/11 (+ the `TestBasePackZeroClickIsReportOnly` invariant); packaging→Task 12. Covered.
- **Report-only invariant** is enforced in code (Task 5 `FinalizeAction`) AND asserted on shipped content (Task 11 security test) — defense in depth.
- **Default build has no cgo** (modernc sqlite + YARA stub); the YARA-enabled build is an explicit `-tags yara` + `libyara-dev` variant (Task 9/12) — CI stays green without libyara.
