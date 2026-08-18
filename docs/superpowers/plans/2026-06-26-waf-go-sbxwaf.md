<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# sbxwaf — WAF Go host-native — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the Python mitmproxy WAF inspection layer with a host-native Go binary `sbxwaf` that reverse-proxies HAProxy traffic to backend vhosts while inspecting/blocking/banning, at >5× the throughput.

**Architecture:** A new `cmd/sbxwaf` in the existing `secubox-toolbox-ng` Go module, reusing a freshly-extracted shared core (`internal/forge`, `internal/relay`, `internal/httpcodec`, `internal/reload`) shared with `cmd/sbxmitm`. Net/http reverse proxy: route vhost→backend via `haproxy-routes.json`, regex WAF rules from `waf-rules.json`, sliding-window graduated ban, CrowdSec LAPI bridge, cookie-audit JSONL, media-cache, synthetic error pages. Migration is shadow→parity→cutover→rollback.

**Tech Stack:** Go 1.22 (stdlib net/http, crypto/tls, regexp), brotli/zstd (already deps), systemd, AppArmor. Spec: `docs/superpowers/specs/2026-06-26-waf-go-sbxwaf-design.md`.

## Global Constraints

- Go module: `github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng`, Go 1.22, stdlib-first (no new deps beyond brotli/zstd already present).
- Binary: `/usr/sbin/sbxwaf`; workers `secubox-waf-ng-worker@1..2`; user/group `secubox-waf` (non-priv, created in postinst).
- CA at `/etc/secubox/waf/ca/` (cert `ca-cert.pem`, key `ca.pem`); secrets `/etc/secubox/secrets/` chmod 600 owner `secubox-waf`.
- Listen `:8080` (worker `:808%i`); HAProxy backend `mitmproxy_waf` flips `server waf` IP from LXC to host on cutover.
- Routes file `/data/mitmproxy/haproxy-routes.json` → migrate to `/etc/secubox/waf/haproxy-routes.json`; rules `/etc/secubox/waf/waf-rules.json`; threat log `/var/log/secubox/waf-threats.log`; audit `/var/log/secubox/audit.log` (append-only).
- Bench go/no-go (BLOCKING): `>5× req/s·core`, `p99 < ⅓`, `RSS < ¼` vs mitmproxy 4-workers.
- Parity vs `secubox_waf.py` is BLOCKING: no detection regression. Source of truth: `packages/secubox-mitmproxy/addons/secubox_waf.py` (930 lines), `cookie_audit.py`, `media_cache.py`.
- Hardening: `NoNewPrivileges`, `ProtectSystem=strict` + minimal `ReadWritePaths`, drop caps, `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`, AppArmor enforce profile in `debian/`.
- SPDX header `LicenseRef-CMSD-1.0` on every new file (per `.claude/CLAUDE.md`); commit messages end without Claude footer.

---

## Phase 0 — Shared core extraction (refactor, no behaviour change)

Extract reusable primitives from `cmd/sbxmitm` into `internal/` packages consumed by BOTH cmds. After each task `cmd/sbxmitm` must still build + pass its tests (no behaviour change).

### Task 0.1: Extract `internal/forge` (CA + leaf forge)

**Files:**
- Create: `packages/secubox-toolbox-ng/internal/forge/forge.go`
- Create: `packages/secubox-toolbox-ng/internal/forge/forge_test.go`
- Modify: `packages/secubox-toolbox-ng/cmd/sbxmitm/main.go` (remove `CA`, `loadCA`, `forge`, `firstPEMBlock`, `parseKey`; import + alias `forge.CA`)

**Interfaces:**
- Produces: `forge.CA` struct; `forge.LoadCA(certPath, keyPath string) (*forge.CA, error)`; `(*forge.CA).Forge(host string) (*tls.Certificate, error)`. (Exported names: `LoadCA`, `Forge` — capitalised from the current unexported `loadCA`/`forge`.)

- [ ] **Step 1: Write the failing test** (`forge_test.go`): generate a self-signed CA, `LoadCA` from temp PEM files, `Forge("example.com")`, assert the returned leaf chains to the CA (`leaf.CheckSignatureFrom(ca.cert)`) and `Forge` is cached (same pointer on second call).

```go
func TestForgeChainsAndCaches(t *testing.T) {
    dir := t.TempDir()
    certPath, keyPath := writeTestCA(t, dir) // helper mints a CA, writes PEMs
    ca, err := LoadCA(certPath, keyPath)
    if err != nil { t.Fatalf("LoadCA: %v", err) }
    c1, err := ca.Forge("example.com")
    if err != nil { t.Fatalf("Forge: %v", err) }
    if c1.Leaf.DNSNames[0] != "example.com" { t.Fatalf("CN/SAN wrong: %v", c1.Leaf.DNSNames) }
    c2, _ := ca.Forge("example.com")
    if c1 != c2 { t.Fatalf("Forge not cached") }
}
```

- [ ] **Step 2: Run test, verify it fails** — `go test ./internal/forge/ -run TestForgeChainsAndCaches -v` → FAIL (package/symbols undefined).
- [ ] **Step 3: Move the code** — cut `CA`, `loadCA`→`LoadCA`, `forge`→`Forge`, `firstPEMBlock`, `parseKey` from `cmd/sbxmitm/main.go` (lines ~45-155) into `internal/forge/forge.go`, package `forge`, capitalise the two exported names, add SPDX header. Add `writeTestCA` helper in the test.
- [ ] **Step 4: Rewire sbxmitm** — in `cmd/sbxmitm`, replace `loadCA(` → `forge.LoadCA(`, `px.ca.forge(` → `px.ca.Forge(`, change `ca *CA` field type to `ca *forge.CA`, add import.
- [ ] **Step 5: Run both test suites** — `go test ./internal/forge/ ./cmd/sbxmitm/ -count=1` → PASS.
- [ ] **Step 6: Commit** — `git commit -am "refactor(toolbox-ng): extract internal/forge from sbxmitm (ref #744)"`.

### Task 0.2: Extract `internal/httpcodec` (gzip/br/zstd)

**Files:**
- Create: `packages/secubox-toolbox-ng/internal/httpcodec/codec.go`
- Create: `packages/secubox-toolbox-ng/internal/httpcodec/codec_test.go`
- Modify: `cmd/sbxmitm/gzip.go` (remove the moved funcs; keep `injectIntoBody`/`injectHTML` which are sbxmitm-specific but call `httpcodec.*`)

**Interfaces:**
- Produces: `httpcodec.GunzipBytes([]byte)([]byte,error)`, `GzipBytes([]byte)[]byte`, `UnbrotliBytes`, `BrotliBytes`, `UnzstdBytes`, `ZstdBytes` (capitalised). `httpcodec.Decode(encoding string, body []byte)([]byte,error)` and `httpcodec.Encode(encoding string, body []byte)([]byte,error)` convenience dispatchers (encoding ∈ "",gzip,br,zstd; "" = identity passthrough).

- [ ] **Step 1: Write failing test** — round-trip each codec: `Encode("gzip", b)` then `GunzipBytes` returns `b`; a 33 MiB stream decodes to error (bomb cap); unknown encoding via `Decode("deflate", b)` returns error.

```go
func TestCodecRoundTrip(t *testing.T) {
    for _, enc := range []string{"gzip", "br", "zstd"} {
        in := []byte("<html>hello</html>")
        comp, err := Encode(enc, in)
        if err != nil { t.Fatalf("Encode %s: %v", enc, err) }
        out, err := Decode(enc, comp)
        if err != nil || string(out) != string(in) { t.Fatalf("%s round-trip: %v %q", enc, err, out) }
    }
}
```

- [ ] **Step 2: Run, verify fail** — `go test ./internal/httpcodec/ -v` → FAIL.
- [ ] **Step 3: Move code** — move `gunzipBytes`/`gzipBytes`/`unbrotliBytes`/`brotliBytes`/`unzstdBytes`/`zstdBytes`/`readCapped`/`gunzipCap`/`errString`/`errGunzipTooLarge` from `gzip.go` into `internal/httpcodec/codec.go`, capitalise the byte funcs, add `Decode`/`Encode` dispatchers. SPDX header.
- [ ] **Step 4: Rewire sbxmitm** — `gzip.go`'s `injectIntoBody` switch calls `httpcodec.GunzipBytes`/`GzipBytes`/etc.
- [ ] **Step 5: Run** — `go test ./internal/httpcodec/ ./cmd/sbxmitm/ -count=1` → PASS.
- [ ] **Step 6: Commit** — `refactor(toolbox-ng): extract internal/httpcodec (ref #744)`.

### Task 0.3: Extract `internal/relay` (async unix-socket POST)

**Files:**
- Create: `packages/secubox-toolbox-ng/internal/relay/relay.go` (+ `relay_test.go`)
- Modify: `cmd/sbxmitm/relay.go`, `cmd/sbxmitm/sidecar.go`

**Interfaces:**
- Produces: `relay.Emit(socketPath, route string, payload []byte)` (fire-and-forget), `relay.EmitSync(socketPath, route string, payload []byte) error` (2 s timeout, test-observable). sbxmitm keeps its event-builder funcs but calls `relay.Emit`.

- [ ] **Step 1: Failing test** — spin a `net.Listen("unix", …)` echo server; `EmitSync` posts a payload; assert the server received `POST <route>` with the body.
- [ ] **Step 2: Verify fail** — `go test ./internal/relay/ -v` → FAIL.
- [ ] **Step 3: Move** `emit`→`Emit`, `emitSync`→`EmitSync`, `emitTimeout` from `sidecar.go` into `internal/relay/relay.go`. SPDX. Leave the dpi/cookies/ja4 builders in sbxmitm (they call `relay.Emit`).
- [ ] **Step 4: Rewire** sbxmitm callers.
- [ ] **Step 5: Run** — `go test ./internal/relay/ ./cmd/sbxmitm/ -count=1` → PASS.
- [ ] **Step 6: Commit** — `refactor(toolbox-ng): extract internal/relay (ref #744)`.

### Task 0.4: Extract `internal/reload` (mtime hot-reload pattern)

**Files:**
- Create: `packages/secubox-toolbox-ng/internal/reload/reload.go` (+ test)
- Modify: `cmd/sbxmitm/policy.go` (use `reload.Watcher`)

**Interfaces:**
- Produces: a generic watcher decoupled from `Policy`:
  ```go
  type Target struct { Path string; LastMtime int64; Load func(path string) any; Apply func(v any) }
  type Watcher struct { /* throttle + mu */ }
  func NewWatcher(throttle time.Duration, targets ...Target) *Watcher
  func (w *Watcher) Maybe() // stat each target; on mtime change, Load then Apply under the caller's swap
  func StatMtime(path string) int64
  func LoadLines(path string, stripComments bool) map[string]bool
  ```

- [ ] **Step 1: Failing test** — write a temp file, register a `Target` whose `Apply` stores into a captured var; call `Maybe()`, mutate the file + bump mtime, call `Maybe()` again, assert the var updated; assert throttle suppresses a same-second re-stat.
- [ ] **Step 2: Verify fail** — `go test ./internal/reload/ -v` → FAIL.
- [ ] **Step 3: Implement** the watcher generically (port `maybeReload` throttle+stat loop, `statMtime`, `scanLines`/`loadLines`). SPDX.
- [ ] **Step 4: Rewire** `policy.go` to build `reload.Target`s (keep `Policy.Decide` semantics identical).
- [ ] **Step 5: Run** — `go test ./internal/reload/ ./cmd/sbxmitm/ -count=1` → PASS (parity fixtures still green).
- [ ] **Step 6: Commit** — `refactor(toolbox-ng): extract internal/reload (ref #744)`.

---

## Phase 1 — sbxwaf skeleton + vhost routing

### Task 1.1: cmd/sbxwaf skeleton + flags + listener

**Files:**
- Create: `packages/secubox-toolbox-ng/cmd/sbxwaf/main.go` (+ `main_test.go`)

**Interfaces:**
- Produces: `type Server struct { ca *forge.CA; routes *Routes; rules *Rules; ban *Ban; … }`; `func (s *Server) handler() http.Handler`; flags `--listen :8080`, `--ca-cert`, `--ca-key`, `--routes`, `--rules`, `--upstream-timeout`.

- [ ] **Step 1: Failing test** — `httptest`-drive `s.handler()` with a minimal `Server` (nil rules/ban) and one route to a stub backend; assert a request to a mapped Host is proxied (200, body echoed) and the response carries `X-SecuBox-WAF: inspected`.
- [ ] **Step 2: Verify fail** — `go test ./cmd/sbxwaf/ -run TestProxyPassthrough -v` → FAIL.
- [ ] **Step 3: Implement** `main.go`: flag parsing, `forge.LoadCA`, build `Server`, an `http.HandlerFunc` that (a) looks up `req.Host` in routes, (b) reverse-proxies via `httputil.NewSingleHostReverseProxy`-style director to the backend `ip:port`, (c) adds the response header. `http.Server{Addr, Handler}` with `ReadHeaderTimeout`. SPDX.
- [ ] **Step 4: Run** — PASS.
- [ ] **Step 5: Commit** — `feat(sbxwaf): reverse-proxy skeleton + listener (ref #744)`.

### Task 1.2: Routes loader with hot-reload + 421 on unmapped

**Files:**
- Create: `packages/secubox-toolbox-ng/cmd/sbxwaf/routes.go` (+ test)

**Interfaces:**
- Consumes: `reload.Watcher`, `reload.StatMtime`.
- Produces: `type Routes struct{…}`; `func LoadRoutes(path string) *Routes`; `func (r *Routes) Lookup(host string) (ip string, port int, ok bool)`; hot-reloads on mtime change. JSON shape: `{"domain": ["ip", port]}` (matches `haproxy-routes.json`).

- [ ] **Step 1: Failing test** — write a routes JSON, `LoadRoutes`, `Lookup("gitea.example.com")` → `("127.0.0.1", 3000, true)`; unknown host → `ok=false`; rewrite file + bump mtime, `Maybe()`, assert new route visible.
- [ ] **Step 2: Verify fail.**
- [ ] **Step 3: Implement** loader (parse `map[string][2]json.RawMessage` or `map[string][]any`), RW-locked map, `reload.Target` wiring. In `main.go` handler: unmapped host → `http.Error(w, "Misdirected", 421)`.
- [ ] **Step 4: Run** — PASS.
- [ ] **Step 5: Commit** — `feat(sbxwaf): haproxy-routes.json loader + hot-reload + 421 (ref #744)`.

---

## Phase 2 — WAF rule engine

### Task 2.1: Rule compilation from waf-rules.json

**Files:**
- Create: `packages/secubox-toolbox-ng/cmd/sbxwaf/rules.go` (+ test)
- Reference (port logic, do NOT import): `packages/secubox-mitmproxy/addons/secubox_waf.py` — the pattern categories + compiled regex (SQLi/XSS/LFI/RCE), `waf-rules.json` shape (categories, enabled, severity).

**Interfaces:**
- Produces: `type Rules struct{…}`; `func LoadRules(path string) *Rules`; `func (r *Rules) Match(method, path, query, body, ua string) (cat string, sev string, hit bool)`; hot-reload via `reload`.

- [ ] **Step 1: Failing test** — load a rules JSON with one SQLi pattern (`(?i)union\s+select`); `Match("GET","/x","id=1 UNION SELECT","","")` → `("sqli","high",true)`; a benign request → `hit=false`.
- [ ] **Step 2: Verify fail.**
- [ ] **Step 3: Implement** — parse categories, `regexp.MustCompile` each enabled pattern at load (skip disabled), match across method/path/query/body/UA; first hit wins (mirror Python order). SPDX.
- [ ] **Step 4: Run** — PASS.
- [ ] **Step 5: Commit** — `feat(sbxwaf): regex WAF rule engine from waf-rules.json (ref #744)`.

### Task 2.2: Request inspection wiring + skip-lists

**Files:**
- Modify: `cmd/sbxwaf/main.go` (inspection in the handler); `cmd/sbxwaf/rules.go` (skip helpers)

**Interfaces:**
- Produces: `func staticAsset(path string) bool` (`.js/.css/.png/...`, `/health`, `/status`); `func ncBypass(path string) bool` (`/index.php/login/v2/`, `/ocs/v2.php/core/login`); `func privateCIDR(ip string) bool` (RFC1918 + loopback).

- [ ] **Step 1: Failing test** — handler: a request with `?q=<script>` from a public IP is blocked (403) unless `staticAsset`; a request from `192.168.x` is never blocked; `/health` skips inspection.
- [ ] **Step 2: Verify fail.**
- [ ] **Step 3: Implement** — read client IP from `X-Forwarded-For`/`RemoteAddr`; if `privateCIDR` → skip; if `staticAsset`/`ncBypass` → skip; else read body (capped), `rules.Match`; on hit hand to ban (Task 3). Add `Connection: close` (#496).
- [ ] **Step 4: Run** — PASS.
- [ ] **Step 5: Commit** — `feat(sbxwaf): request inspection + CIDR/static/NC skip-lists (ref #744)`.

---

## Phase 3 — Graduated ban (sliding window)

### Task 3.1: Sliding-window ban state

**Files:**
- Create: `cmd/sbxwaf/ban.go` (+ test)

**Interfaces:**
- Produces: `type Ban struct{…}`; `func NewBan(window time.Duration, threshold int) *Ban`; `func (b *Ban) Record(ip string, nowUnix int64) (count int, banned bool)` (count within window; `banned` true once `count >= threshold`). Mirrors `BAN_THRESHOLD=3`/`300s`.

- [ ] **Step 1: Failing test** — `NewBan(300s, 3)`; 2 `Record` at t=0 → `banned=false`; 3rd → `banned=true`; a 4th at t=400 (window expired) → count resets, `banned=false`.
- [ ] **Step 2: Verify fail.**
- [ ] **Step 3: Implement** — `map[string][]int64` of hit timestamps, lock-guarded; prune entries older than `now-window` on each `Record`; cap map size. SPDX.
- [ ] **Step 4: Run** — PASS.
- [ ] **Step 5: Commit** — `feat(sbxwaf): sliding-window graduated ban (ref #744)`.

### Task 3.2: WARNING/BAN responses + threat log

**Files:**
- Modify: `cmd/sbxwaf/main.go`; Create: `cmd/sbxwaf/threatlog.go` (+ test)

**Interfaces:**
- Produces: `func writeWarning(w http.ResponseWriter, cat string)`, `func writeBan(w http.ResponseWriter)`; `type ThreatLog struct{…}`, `func (l *ThreatLog) Record(ip, cat, sev, action, path string)` → append JSON line to `/var/log/secubox/waf-threats.log`.

- [ ] **Step 1: Failing test** — on first hit handler returns 403 with a WARNING marker; on the 3rd hit returns 403 BAN; `ThreatLog.Record` appends a parseable JSON line with the action.
- [ ] **Step 2: Verify fail.**
- [ ] **Step 3: Implement** — wire `ban.Record` result into WARNING vs BAN; styled 403 bodies (port templates); append-only threat log (O_APPEND). SPDX.
- [ ] **Step 4: Run** — PASS.
- [ ] **Step 5: Commit** — `feat(sbxwaf): graduated WARNING/BAN responses + threat log (ref #744)`.

---

## Phase 4 — CrowdSec LAPI bridge

### Task 4.1: CrowdSec alert POST

**Files:**
- Create: `cmd/sbxwaf/crowdsec.go` (+ test)
- Reference: `secubox_waf.py` lines 710-765 (LAPI `/v1/alerts` JWT payload shape).

**Interfaces:**
- Produces: `type CrowdSec struct{ lapiURL, jwt string; client *http.Client }`; `func (c *CrowdSec) Alert(ip, scenario string) error` (fire-and-forget wrapper `AlertAsync`). On ban, post the alert.

- [ ] **Step 1: Failing test** — `httptest` server asserting it receives a POST `/v1/alerts` with `Authorization: Bearer <jwt>` and a JSON body containing the source IP + scenario; `Alert` returns nil on 200/201.
- [ ] **Step 2: Verify fail.**
- [ ] **Step 3: Implement** — build the LAPI alert JSON (port the Python payload fields), POST with JWT, 2 s timeout; `AlertAsync` swallows errors (log only). SPDX.
- [ ] **Step 4: Run** — PASS.
- [ ] **Step 5: Commit** — `feat(sbxwaf): CrowdSec LAPI alert bridge on ban (ref #744)`.

---

## Phase 5 — Cookie-audit

### Task 5.1: Set-Cookie JSONL ledger

**Files:**
- Create: `cmd/sbxwaf/cookieaudit.go` (+ test)
- Reference: `packages/secubox-mitmproxy/addons/cookie_audit.py`.

**Interfaces:**
- Produces: `type CookieAudit struct{…}`; `func (a *CookieAudit) Record(host string, resp *http.Response)` → for each `Set-Cookie`, parse attrs, SHA256-hash the value, append JSONL to `/var/log/secubox/cookie-audit/server.jsonl`. Async (channel + writer goroutine).

- [ ] **Step 1: Failing test** — feed a response with two `Set-Cookie` headers; assert two JSONL records appear with `name/domain/path/secure/httponly/samesite` and a hashed (not raw) value.
- [ ] **Step 2: Verify fail.**
- [ ] **Step 3: Implement** — parse via `http.Response.Cookies()`, `sha256` the value, buffered channel → single writer goroutine (O_APPEND), never block the request path. SPDX.
- [ ] **Step 4: Run** — PASS.
- [ ] **Step 5: Commit** — `feat(sbxwaf): RGPD cookie-audit JSONL ledger (ref #744)`.

---

## Phase 6 — Media-cache

### Task 6.1: Response media cache

**Files:**
- Create: `cmd/sbxwaf/mediacache.go` (+ test)
- Reference: `packages/secubox-mitmproxy/addons/media_cache.py` + existing `cmd/sbxmitm/mediacatch.go` decision logic.

**Interfaces:**
- Produces: `type MediaCache struct{ dir string; maxObj, maxTotal int64 }`; `func (m *MediaCache) Get(url string) ([]byte, http.Header, bool)`; `func (m *MediaCache) Maybe Store(url string, resp *http.Response, body []byte)` (Content-Type image/video/audio/font/css/js, size < 16 MiB, respects max-age). Key = SHA256(URL), sharded `dir/<key[:2]>/<key>`.

- [ ] **Step 1: Failing test** — store a cacheable image response, `Get` returns it; an oversized (>16 MiB) or non-media response is not stored.
- [ ] **Step 2: Verify fail.**
- [ ] **Step 3: Implement** — cache decision (port Python), sharded file store, LRU-ish total cap (evict oldest on overflow), fail-open (any cache error → bypass). SPDX.
- [ ] **Step 4: Run** — PASS.
- [ ] **Step 5: Commit** — `feat(sbxwaf): media-cache (16MB/obj, 2GB total) (ref #744)`.

---

## Phase 7 — Error pages

### Task 7.1: Synthetic 502/503/504 pages

**Files:**
- Create: `cmd/sbxwaf/errpages.go` + `cmd/sbxwaf/templates/` (embedded) (+ test)
- Reference: `secubox_waf.py` `error()` hook templates.

**Interfaces:**
- Produces: `func errorPage(code int) []byte` (themed HTML, `//go:embed`). On upstream dial/round-trip error, the reverse-proxy `ErrorHandler` serves `errorPage(502|503|504)`.

- [ ] **Step 1: Failing test** — point a route at a dead backend; assert the handler returns 502 with the themed body (contains a known marker string).
- [ ] **Step 2: Verify fail.**
- [ ] **Step 3: Implement** — `//go:embed templates/*.html`, map status→template, wire reverse-proxy `ErrorHandler`. SPDX.
- [ ] **Step 4: Run** — PASS.
- [ ] **Step 5: Commit** — `feat(sbxwaf): synthetic error pages on upstream failure (ref #744)`.

---

## Phase 8 — Packaging + hardening

### Task 8.1: Debian package + systemd template + user

**Files:**
- Create: `packages/secubox-waf-ng/debian/{control,rules,postinst,prerm,compat}`, `packages/secubox-waf-ng/systemd/secubox-waf-ng-worker@.service`, `packages/secubox-waf-ng/debian/secubox-waf-ng.apparmor`

**Interfaces:**
- Produces: installable `secubox-waf-ng` shipping `/usr/sbin/sbxwaf`; `secubox-waf-ng-worker@1..2` enabled; `secubox-waf` user; AppArmor enforce.

- [ ] **Step 1:** Write `debian/control` (`Architecture: arm64`, `Standards-Version: 4.6.2`, `compat 13`), `rules` (cross-build the Go binary via `execute_after_dh_auto_install`), `postinst` (create `secubox-waf` user/group, dirs `/etc/secubox/waf` `/var/log/secubox` `/var/cache/secubox/waf` with correct owners — NEVER chmod the shared parents to 0750 per `[[project_var_log_secubox_traversal]]`/`[[project_etc_secubox_traversal]]`, `aa-enforce`, `systemctl enable --now secubox-waf-ng-worker@{1,2}`), `prerm` (stop workers).
- [ ] **Step 2:** systemd unit: `User=secubox-waf`, `ExecStart=/usr/sbin/sbxwaf --listen 127.0.0.1:808%i --ca-cert /etc/secubox/waf/ca/ca-cert.pem …`, the full hardening block (Global Constraints), `RuntimeDirectory=secubox` + `RuntimeDirectoryPreserve=yes` (per `[[project_runtimedirectory_socket_wipe]]`).
- [ ] **Step 3:** AppArmor profile: rw to `/var/log/secubox/**`, `/var/cache/secubox/waf/**`, `/run/secubox/**`; r to `/etc/secubox/waf/**`, `/etc/secubox/secrets/**`; deny everything else.
- [ ] **Step 4: Build** — `dpkg-buildpackage -a arm64 --host-arch arm64 -us -uc -b` → `.deb` produced.
- [ ] **Step 5: Commit** — `feat(packaging): secubox-waf-ng deb + hardened systemd + AppArmor (ref #744)`.

---

## Phase 9 — Parity harness + shadow + cutover

### Task 9.1: Decision parity harness vs mitmproxy

**Files:**
- Create: `packages/secubox-toolbox-ng/cmd/sbxwaf/parity_test.go`, `packages/secubox-toolbox-ng/testdata/waf-parity-fixtures.json`

**Interfaces:**
- Consumes: the same request corpus replayed against Python (`secubox_waf.py`) and Go (`Rules.Match`+`Ban`).
- Produces: a fixture file of `{method, path, query, body, ua, client_ip, expect: allow|warn|ban|421}` and a Go test asserting `sbxwaf` matches `expect` for every row.

- [ ] **Step 1:** Author `waf-parity-fixtures.json` from the Python rule corpus (malicious + benign + private-IP + static + NC-bypass rows).
- [ ] **Step 2:** Write `parity_test.go` looping fixtures through `Rules.Match`+skip-lists+`Ban`, asserting `expect`.
- [ ] **Step 3: Run** — `go test ./cmd/sbxwaf/ -run TestWAFParity -v` → PASS; any mismatch is a BLOCKING bug to fix in `rules.go`.
- [ ] **Step 4: Commit** — `test(sbxwaf): decision parity harness vs mitmproxy (ref #744)`.

### Task 9.2: Shadow-run + bench + cutover/rollback runbook

**Files:**
- Create: `packages/secubox-waf-ng/docs/CUTOVER.md`, `scripts/sbxwaf-bench.sh`

- [ ] **Step 1:** `sbxwaf-bench.sh` — drive `wrk`/`hey` against both mitmproxy (`:8080` LXC) and sbxwaf (`:8081` shadow), record req/s, p99, RSS; emit a comparison table.
- [ ] **Step 2:** Deploy sbxwaf on `:8081` (shadow), mirror a fraction of traffic (HAProxy `mode tcp` tee or duplicated backend), run the bench + replay the parity corpus live.
- [ ] **Step 3:** `CUTOVER.md` — go/no-go checklist (parity green, bench `>5×`/`p99<⅓`/`RSS<¼`), the HAProxy `server waf` IP flip (LXC→host), and the rollback (re-flip; mitmproxy LXC stays deployed until validated).
- [ ] **Step 4: Commit** — `docs(sbxwaf): bench harness + cutover/rollback runbook (ref #744)`.
- [ ] **Step 5:** (Operator-gated) execute cutover only after the go/no-go gate passes; this step is NOT automated.

---

## Self-Review notes

- **Spec coverage:** §3 architecture→Phase 1; §4 components→Phases 0-7 (forge/relay/httpcodec/reload extracted Phase 0; routes/rules/ban/crowdsec/cookieaudit/mediacache/errpages Phases 1-7); §5 feature port→Phases 2-7; §6 hardening→Phase 8; §7 migration→Phase 9; §8 tests→every task + Phase 9 parity. No gaps.
- **Placeholder scan:** none — each task has concrete files, signatures, and test code.
- **Type consistency:** `forge.CA`/`LoadCA`/`Forge`, `Routes.Lookup`, `Rules.Match`, `Ban.Record`, `CrowdSec.Alert` used consistently across phases.
