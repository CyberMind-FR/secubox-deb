# Task 15 report — per-vhost signal source for scale-to-zero AUTO-sleep (#896)

## Fix — review-found Critical bug: WAF-blocked/banned traffic counted as activity

Review caught a Critical correctness bug in the original hook placement: the
`Begin`/`defer End` bracket sat right after the on-demand/waker/421 checks but
**before** the entire WAF-inspection block (rules match → detect/escalate/
block → graduated warning/ban, main.go's ~lines 373-548). So a request the
WAF blocked with 403 — never reaching the real backend — still called
`Begin`, refreshing `lastSeen[host]` to "now". Public on-demand vhosts sit
under near-constant internet scanning (masscan/shodan/bots) that trips
block-mode rules, so `last_request_ts` kept getting refreshed by BLOCKED
traffic and `should_sleep()`'s `last_request_age >= idle_threshold` never
passed — defeating auto-sleep for exactly the deployment this feature exists
for (public on-demand vhosts). The sibling visit-stats recorder in the same
function already excludes 403/421/waker from its tally (via a deferred
status check) but the vhostsignals hook had only excluded the waker/421
branch, not the WAF-block/ban early-returns.

**Fix**: moved the `Begin`/`defer End` bracket from its original spot (right
after the on-demand/waker + 421 checks, before WAF inspection) to
immediately after the WAF-inspection block closes — right before the
"Task 6.1 — media cache hit" comment. All of the WAF-inspection block's
early `return`s (escalate-ban at ~line 502, plain 403 at ~521, graduated
ban at ~557, graduated warning at ~559) now execute, if they're going to,
*before* reaching the hook. A single placement there still covers three
exit paths via the one `defer`: the media-cache-hit `return` just below it,
the media-cache-miss `proxy.ServeHTTP` further down, and the plain
`proxy.ServeHTTP` at the very end of the handler. I judged the media-cache
hit to count as legitimate vhost activity per the coordinator's guidance —
the client gets a genuine response for that vhost's content, same as a
backend-served response — so it is included, not excluded.

Regression test `TestVhostSignalsExcludedForWAFBlock` (in `main_test.go`,
next to `TestVhostSignalsExcludedForWakerBranch`): sends an on-demand vhost
*with a live route* a SQLi payload (same fixture/payload as
`TestHandlerWarningThenBan`) and asserts the vhost snapshot stays empty
after the 403. Verified RED against the pre-fix placement (`git stash` on
just `main.go` to isolate the placement regression, confirmed the test
failed with the vhost recorded — `map[sleepy.example.com:{LastRequestTS:...
ActiveConns:0}]` — then `git stash pop` to restore the fix) and GREEN after.

Re-verified after the fix: `go build ./...` clean, `go vet ./cmd/sbxwaf/`
clean, `go test ./cmd/sbxwaf/ -count=1 -v` → **110 PASS / 0 FAIL** (whole
package, one more than the original 109 for this new test), `go test
./cmd/sbxwaf/ -race -run 'TestVhostSignals|TestOnDemand' -count=1 -v` → all
PASS. Fixed in a follow-up commit
`fix(waf-ng): vhost signal excludes WAF-blocked/banned traffic (real
activity only) (ref #896)`.

## Summary (original implementation)

Two independent changes, one per package:

- **Part A (Go, sbxwaf)**: `packages/secubox-toolbox-ng/cmd/sbxwaf/vhostsignals.go`
  (+ `vhostsignals_test.go`) — a `VhostSignals` emitter mirroring `visitstats.go`'s
  lock+flusher+atomic-rename shape, hooked once in `handler()`, wired through
  `main()` via `--vhost-signals` (default `/var/cache/secubox/waf/vhost-signals.json`),
  and added to the worker unit's `ExecStart`.
- **Part B (Python, secubox-profiles)**: `api/sleeper_daemon.py::_signal_reader`
  now reads that file (best-effort, `{}` on any failure) instead of the safe
  stub, and `main_async` now wires `now=time.time` (was `time.monotonic`) into
  `sleeper.serve`, matching sbxwaf's unix wall-clock `last_request_ts`.

Both parts were already present as **uncommitted working-tree changes** when
this task started (main.go/main_test.go/sleeper_daemon.py/service unit
modified, vhostsignals.go/_test.go untracked) — I verified/completed them
rather than writing from scratch. Part A (Go) was already fully correct and
tested; Part B (Python) had the docstring already rewritten to describe the
fix but the actual `_signal_reader` body was still the `{}` stub and `now`
was still `time.monotonic` — I implemented the real reader and flipped the
clock.

## Part A — Go emitter

`VhostSignals{mu, lastSeen map[string]int64, active map[string]int64, path}`:
- `Begin(vhost)`: `lastSeen[vhost] = time.Now().Unix()`, `active[vhost]++`.
- `End(vhost)`: `active[vhost]--`; deletes the key once `<= 0` (so an idle
  vhost's `active_conns` reads as "key absent" == 0, never a stale zero).
  `lastSeen` is never touched by `End` — it must survive long after
  `active_conns` drops back to zero (that's exactly what `should_sleep()`
  needs: age since last request AND zero in-flight).
- Flusher: 5s ticker (shorter than `visitstats.go`'s 30s — the sleeper polls
  every ~30s by default, so a 30s-stale snapshot would double the effective
  idle-decision latency; 5s keeps the skew small). Atomic temp+rename write,
  best-effort (errors swallowed), same shape as `VisitStats.writeSnapshot`.
- No top-N cap — deliberately, since the sleeper needs *every* on-demand
  vhost's signal, not a "top busiest" sample; the map stays small anyway
  because recording is gated to the on-demand set (operator-curated,
  expected small), not the whole public vhost fleet.

**Hook placement** (`main.go` `handler()`): a single `Begin`/`defer End` pair
placed once, right after the on-demand/403/421/waker-branch checks, gated on
`s.vhostSignals != nil && s.onDemand != nil && s.onDemand.Contains(host)`,
*before* the two real-backend proxy branches (media-cache-miss path and the
plain path). One placement covers both because `defer` fires on whichever
branch the function returns through — so exactly one `Begin` pairs with
exactly one `End` regardless of which of the two proxy sites actually served
the request. The waker branch already returns earlier in the function and is
never reached by this code, so a sleeping vhost never gets a phantom hit.

Flag: `--vhost-signals` (default `/var/cache/secubox/waf/vhost-signals.json`,
empty disables), same convention as `--visits-stats`/`--on-demand-vhosts`.
Added to `secubox-waf-ng-worker@.service`'s `ExecStart`.

### Go tests / vet

- `TestVhostSignalsBeginEnd`, `TestVhostSignalsEndWithoutBeginNeverGoesPositive`,
  `TestVhostSignalsFlushWritesJSON`, `TestVhostSignalsFlushReflectsEndedRequest`,
  `TestVhostSignalsEmptyPathDisablesFlush` (unit-level, in `vhostsignals_test.go`).
- `TestVhostSignalsRecordedForRealOnDemandRequest` (handler-level: a real
  on-demand request is bracketed, ends with `active_conns=0` + non-zero
  `last_request_ts`) and `TestVhostSignalsExcludedForWakerBranch` (a
  waker-splash 503 response records nothing) in `main_test.go`.
- `go build ./cmd/sbxwaf/` and `go build ./...` (whole module): clean.
- `go vet ./cmd/sbxwaf/`: clean.
- `go test ./cmd/sbxwaf/ -count=1 -v`: **109 PASS, 0 FAIL** (full package,
  not just the new tests).
- `go test ./cmd/sbxwaf/ -race -count=1`: PASS (whole package, ~4.3s).
- `gofmt -l`: flags pre-existing drift in `main.go`/`main_test.go` that is
  **already present at HEAD** (verified via `git show HEAD:... | gofmt -l`,
  reproduced without any task-15 diff — a gofmt-version artifact on doc
  comments and unrelated struct literals), out of this task's scope. The one
  alignment issue that *was* introduced by this task's new struct literal
  (`vhostSignals: vs` misaligned against sibling fields in
  `TestVhostSignalsExcludedForWakerBranch`) was fixed.

## Part B — Python reader

`api/sleeper_daemon.py`:
- New module constant `VHOST_SIGNALS_PATH = Path("/var/cache/secubox/waf/vhost-signals.json")`
  (module-level so it's monkeypatchable in tests, same pattern as
  `api.waker._WAKE_ACTIVE_PATH`).
- `_signal_reader()`: `json.loads(VHOST_SIGNALS_PATH.read_text())`, catching
  `(OSError, ValueError)` → `{}` (missing file, permission error, or corrupt/
  partial JSON — e.g. a read racing sbxwaf's flush). Also guards the shape:
  non-dict top level → `{}`; non-dict per-vhost values are dropped (JSON
  object keys are always strings, so no further key-type guard is reachable,
  but the `isinstance` check documents the contract). Passes the raw
  per-vhost dict straight through — `front_signals.vhost_signals()` does its
  own field-level validation (missing/wrong-typed `last_request_ts`/
  `active_conns` → `None`, never fabricated).

### Wall-clock-now correctness

`sbxwaf` writes `last_request_ts` via `time.Now().Unix()` — unix wall-clock
seconds. `front_signals.vhost_signals(reader, now)` computes
`age = now() - last_request_ts`. Read `sleeper.py::serve`'s docstring first:
its `now` parameter's *only* consumer is `vhost_signals(reader=signal_reader,
now=now)` (line 134) — the *separate* `stamp` parameter is what feeds
`run_once(..., now=stamp_fn())`'s audit-timestamp string. So `now` in `serve()`
is purely the float wall/monotonic clock for signal-age math, never anything
else — confirming that flipping `sleeper_daemon.py`'s wiring from
`now=time.monotonic` to `now=time.time` is an isolated, correct fix with no
other call site to reconcile. `time.monotonic()`'s epoch is arbitrary
(process/OS-dependent, unrelated to unix time), so subtracting a unix
timestamp from it would have produced a meaningless (and, on this Linux host,
enormous) "age" — silently defeating auto-sleep by making every vhost look
either permanently fresh or permanently ancient depending on monotonic-clock
epoch vs unix-epoch sign, not proportional to real elapsed time.

### Python tests

Updated `tests/test_sleeper.py` (RED→GREEN against the stub, now GREEN
against the real implementation):
- `test_sleeper_daemon_wires_serve_with_production_deps`: assertion flipped
  from `daemon.time.monotonic` to `daemon.time.time`.
- Replaced the old `..._stub_is_safe_empty` test (which asserted the
  hardcoded `{}` stub) with:
  - `test_sleeper_daemon_signal_reader_missing_file_is_safe_empty`
  - `test_sleeper_daemon_signal_reader_corrupt_json_is_safe_empty`
  - `test_sleeper_daemon_signal_reader_unexpected_shape_is_safe_empty`
  - `test_sleeper_daemon_signal_reader_reads_real_snapshot` (shape sbxwaf
    actually writes, read straight through)
  - `test_sleeper_daemon_signal_reader_feeds_wall_clock_idle_decision`:
    end-to-end — an old `last_request_ts` (real `time.time() - 1000`) written
    to a tmp file, read through `_signal_reader`, fed through
    `front_signals.vhost_signals(reader=..., now=time.time)`, asserts
    `last_request_age >= 999.0` and that `should_sleep()` returns `True` —
    proving the wall-clock plumbing end-to-end, not just each piece in
    isolation.
- `_hint_probe` stub test untouched (still a documented stub, out of scope).

Results:
- `python -m pytest tests/test_sleeper.py -v`: **17 passed**.
- `python -m pytest tests/ -q` (full profiles suite): **228 passed**, 3
  pre-existing deprecation warnings (pydantic/fastapi `on_event`), unrelated.
- mypy vs baseline (per `git rev-parse HEAD` = `b4e89696`, measured by
  stashing all task-15 changes and running `python -m mypy api/`): baseline
  **3 errors in 3 files** (`api/scan.py:80`, `api/snapshot.py:55`,
  `api/web.py:49` — all pre-existing, unrelated to this task). After
  restoring and applying this task's changes: same **3 errors in 3 files**
  (checked 23 source files both times) — **0 new errors**.
  `mypy --strict api/sleeper_daemon.py api/sleeper.py api/front_signals.py`
  shows only pre-existing untyped-def errors in `api/actuate.py`/`api/apply.py`/
  `api/sleeper.py::run_once` — none in `sleeper_daemon.py` itself.

## Files changed

- `packages/secubox-toolbox-ng/cmd/sbxwaf/vhostsignals.go` (new)
- `packages/secubox-toolbox-ng/cmd/sbxwaf/vhostsignals_test.go` (new)
- `packages/secubox-toolbox-ng/cmd/sbxwaf/main.go` (Server field, handler
  hook, `--vhost-signals` flag, wiring in `main()`)
- `packages/secubox-toolbox-ng/cmd/sbxwaf/main_test.go` (two handler-level
  tests + struct-literal alignment fix)
- `packages/secubox-waf-ng/systemd/secubox-waf-ng-worker@.service`
  (`--vhost-signals` added to `ExecStart`)
- `packages/secubox-profiles/api/sleeper_daemon.py` (`VHOST_SIGNALS_PATH`,
  real `_signal_reader`, `now=time.time`)
- `packages/secubox-profiles/tests/test_sleeper.py` (updated + new tests)

## Self-review

- Checked for double-counting at the two proxy call sites (media-cache-miss
  vs plain): confirmed a single `Begin`/`defer End` pair before both branches
  is correct — `defer` runs exactly once per request regardless of which
  branch executes, so no double-count and no missed `End` (including on
  panic, which was the whole point of using `defer` over an explicit call at
  each of the two `proxy.ServeHTTP` sites).
- Checked the waker branch is structurally unreachable from the hook's
  position (it returns earlier in `handler()`) — confirmed by reading the
  function; the exclusion test (`TestVhostSignalsExcludedForWakerBranch`)
  exercises this directly.
- Checked `sleeper.py::serve`'s `now` parameter has exactly one call site
  (`vhost_signals`) so the clock-source fix has no other consumer to
  reconcile — confirmed by reading the full file, not just grepping.
- Verified the mypy baseline against the actual `git rev-parse HEAD`
  (`b4e89696`) commit rather than trusting the brief's framing, by stashing
  the working-tree diff and re-running mypy, then popping the stash.
- Ran the full package/module-level test suites (not just the new tests) on
  both sides, plus `-race` on Go, to confirm nothing regressed.

## Concerns / follow-ups (not blocking, out of this task's scope)

- `_hint_probe` remains a documented stub (`None` always) — unchanged, not
  part of this task.
- The `_signal_reader`'s `isinstance(vhost, str)` guard is unreachable in
  practice (JSON object keys always decode to `str`) — kept as documentation
  of intent / defense-in-depth, not a functional gap.
- `gofmt -l` reports drift on `main.go`/`main_test.go` beyond what this task
  touched; verified it pre-dates this task (present at HEAD) and left alone
  to avoid an unrelated, unreviewed reformatting sweep in this commit.
