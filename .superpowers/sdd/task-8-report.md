# Task 8 Report: sleeper `serve` daemon loop (secubox-profiles, ref #896)

**Status:** Done.

(Note: this file previously held an unrelated stale Task-8 report for a
different plan — "obfs4 bridges + reapply-when-armed" — overwritten here
since it did not belong to this plan.)

## What was implemented

- `packages/secubox-profiles/api/sleeper.py`:
  - `async def serve(*, root, interval, sleep, observe_all, signal_reader, hint_probe, run, observe, now, stamp=None, tick_limit=None) -> None`
    — each tick: `load_all(root/"modules.d")`, `observe_all(manifests, routes=None)`,
    `front_signals.vhost_signals(reader=signal_reader, now=now)`, then maps
    vhost→module by `m.portal_domain` (a module whose domain isn't in the
    vhost-signal dict simply gets no entry — `run_once`/`should_sleep`
    already treat a missing signal as "never sleep", so no extra guard was
    needed), probes `hint_probe(mid, m)` per module (only records a hint when
    it isn't `None` — `None` means indeterminate, `run_once` already treats a
    missing hint key the same as `None`), reads the wake-lock file
    best-effort, and calls `run_once(...)`. The tick body is wrapped in
    `try/except Exception` (`logging.exception`, then continue) so one bad
    tick (a transient TOML parse error, a briefly-unreadable signal source,
    etc.) never kills the daemon.
  - `_read_wake_locked(path=WAKE_LOCK_FILE) -> frozenset[str]` — reads
    `/run/secubox/waker-active.json` (a JSON list of ids), returns
    `frozenset()` on any `OSError`/`ValueError`/non-list content. This is the
    "wake-lock source" the brief asks for; the waker side (writing this file
    from its `_last_wake` state) is explicitly out of scope for Task 8 per
    the brief — it names only the file contract, not a waker-side change.
  - `_default_stamp() -> str` — `datetime.now(timezone.utc).isoformat()`,
    used only when the caller doesn't supply `stamp`.
  - A follow-up code comment on `serve`'s docstring (see below) about the
    shared-4R-snapshot churn, per the brief's explicit instruction not to
    solve it in this task.

## `now` / `stamp` resolution (brief flagged this as ambiguous)

The brief's illustrative code reused a single `now` param for two
incompatible roles: `front_signals.vhost_signals` requires `Callable[[],
float]` (wall/monotonic clock, for signal-age arithmetic), while
`run_once`/`apply_plan`'s `now` is an opaque value blindly written into audit
records and the 4R snapshot (`test_run_once_stops_only_idle_sleepable`
already passes it a bare string, `now="t"`, confirming it's not a clock at
apply.py's own level — `apply_plan` has a *separate* `clock` parameter,
defaulting to `time.monotonic`, that actually drives `wait_state`'s polling).

Resolved with two params, per the brief's suggested escape hatch:
- `now: Callable[[], float]` — single-purpose float clock, passed straight
  through to `vhost_signals`.
- `stamp: Callable[[], str] | None = None` — single-purpose audit-string
  producer, passed as `run_once`'s `now=` argument; defaults to
  `_default_stamp` (UTC ISO-8601) when the caller omits it.

The brief's test only passes `now=lambda: 100000.0` (no `stamp`), which
stays green under this signature since `stamp` has a default.

## TDD

- **RED**: added `test_serve_one_tick_stops_idle` (verbatim from the brief,
  with one addition — see "test environment gap" below) to
  `tests/test_sleeper.py` before writing `serve`; confirmed failure:
  `ImportError: cannot import name 'serve' from 'api.sleeper'`.
- **GREEN**: implemented `serve` as above; test passes.

## Test environment gap found (not a Task 8 regression — pre-existing, first exposed here)

`run_once` → `apply.apply_plan` → `actuate.actuate` STOPs a portal-routed
module (`m.portal_domain` set) by reading/writing the WAF routes file with
**real, un-injected** `Path.read_text`/`os.replace` I/O
(`api/actuate.py:_portal_remove`), at a **hardcoded default**
(`routes_path=ROUTES_FILE` = `/etc/secubox/waf/haproxy-routes.json`,
bound once at `actuate.py` import time as the function's `__kwdefaults__`
entry). Neither `apply_plan` nor `run_once` threads a `routes_path` override
through to `actuate()` — only the `routes={}` snapshot-capture dict is
parametrized, which is a different concept (used only by `snapshot.capture`
for the 4R record, not by the live route file).

Every existing test that exercises `run_once`/`apply_plan` with a real,
non-monkeypatched `actuate()` call (`test_run_once_stops_only_idle_sleepable`,
`test_run_once_skips_wake_locked`) sidesteps this by using manifests with no
`portal_domain` at all. The brief's Task 8 test is the first to combine a
`portal.domain` manifest (needed to exercise `serve`'s vhost→module mapping)
with a real, non-monkeypatched `run_once` call — this hits
`/etc/secubox/waf/haproxy-routes.json`, which does not exist and is not
writable by an unprivileged test user in this dev sandbox (confirmed no
sudo: "no new privileges" flag blocks it even with the sandbox override).

This is a genuine, real-system-correct default for production (the sleeper
*should* touch the live WAF routes file when stopping a routed module) — it
is a test-isolation gap in the existing `apply_plan`/`actuate` plumbing, out
of scope for Task 8 to fix (the brief says reuse `run_once` as-is). Fixed
**only in the test**, by retargeting `actuate.actuate`'s own bound
`__kwdefaults__["routes_path"]` via `monkeypatch.setitem` to a `tmp_path`
file seeded with `{}` — this is reversible (monkeypatch teardown), touches
no source file, and does not change `apply_plan`/`run_once`'s signatures.
Flagging this for a possible future follow-up (thread `routes_path` through
`apply_plan`/`run_once` the same way `snap_root`/`audit_path` already are,
via `actuate_paths.py`) — not done here, per scope.

## Test results

```
cd packages/secubox-profiles && python -m pytest tests/test_sleeper.py -v
# 10 passed (9 pre-existing + test_serve_one_tick_stops_idle)

cd packages/secubox-profiles && python -m pytest tests/ -q
# 215 passed, 3 warnings (pre-existing Pydantic/FastAPI deprecation noise, unrelated)
```

## mypy vs. baseline

```
cd packages/secubox-profiles && python -m mypy --strict api/
# Found 93 errors in 12 files (checked 21 source files)
```

Confirmed the baseline itself (HEAD, `8bf51528`, via `git stash`) also
reports exactly **93 errors in 12 files** — identical count, identical file
set. The only `sleeper.py` line still flagged is line 54 (`run_once`'s
signature, pre-existing from Task 5, untouched by this task); `serve`,
`_read_wake_locked`, and `_default_stamp` (all newly added, fully
type-annotated) introduce zero new mypy errors.

## Files changed

- `packages/secubox-profiles/api/sleeper.py` — added `serve`,
  `_read_wake_locked`, `_default_stamp`, `WAKE_LOCK_FILE` constant, and the
  new imports (`json`, `logging`, `datetime`, `front_signals.vhost_signals`,
  `manifest.load_all`, `typing.Callable`/`Awaitable`/`Any`).
- `packages/secubox-profiles/tests/test_sleeper.py` — added
  `test_serve_one_tick_stops_idle`.

## Self-review

- Tick isolation: confirmed a raised exception inside the try body (e.g.
  `observe_all` raising) is caught, logged via `logging.exception`, and the
  loop proceeds to the next tick/sleep rather than propagating — matches
  the "never let one tick kill the daemon" constraint.
- `tick_limit=1` with `interval=0`: verified the loop does exactly one pass
  and returns without ever calling `sleep` (the `if tick_limit is None or
  ticks < tick_limit` guard around the `await sleep(interval)` — after
  `ticks` becomes 1 and `tick_limit=1`, it skips the sleep and the outer
  `while` condition also stops), consistent with `run_once`/T5's use of
  `sleep` only as an inter-tick pause, never a post-loop pause.
- Hint contract: `hint_probe(mid, m)` returning `True`/`False`/`None` is
  handled by only inserting into `hints` when not `None` — `should_sleep`
  (T4) already treats a missing key the same as an explicit `None` via
  `hints.get(mid)`, so vetoing (`False`) is the only value that changes
  behavior; this matches the brief's stated contract.
- Wake-lock read is genuinely best-effort: `OSError` (file missing/
  permission) and `ValueError` (malformed JSON) both degrade to
  `frozenset()`, never raise into the tick's outer handler.
- No secrets, no privileged calls added; `serve` itself does not run as
  root — it only calls the injected `run`/`observe`/`observe_all` callables,
  same privilege model as `run_once`.

## Concerns / follow-ups (not fixed here, out of scope)

1. **Shared 4R-snapshot churn** (flagged by the brief, not to be solved in
   this task): `run_once` → `apply_plan` takes one snapshot per stopped
   module into the *same* `R1..R4` rollback chain that operator
   `profilectl rollback` uses. A busy sleeper will rotate that chain
   independently of operator-driven applies. Noted as a comment in
   `serve`'s docstring; real fix (e.g. a distinct sleeper-only rollback
   slot, or skip snapshotting entirely since sleep is reversible by
   wake-on-access) is future work (ref #896 follow-up).
2. **`routes_path` not threaded through `apply_plan`/`run_once`** (found
   while making the Task 8 test hermetic, see "Test environment gap"
   above) — a real gap, but genuinely orthogonal to Task 8's brief; only
   worked around at the test level.
3. The wake-lock file's *writer* side (the waker maintaining
   `/run/secubox/waker-active.json` from its `_last_wake` state) is not
   part of this task — the brief specifies only the reader contract here.
