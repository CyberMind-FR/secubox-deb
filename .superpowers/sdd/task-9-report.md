# Task 9 Report: systemd units + sudoers + waker active-state writer (ref #896)

(Note: this file previously held an unrelated stale Task-9 report for a
different plan — "Marvell PPv2 NIC Driver Addition (#748)" — overwritten
here since it did not belong to this plan, same situation noted in the
Task 7 report of this plan.)

**Status:** Done.

## What was implemented

1. **`api/waker.py::_write_wake_active`** (the TDD'd code change) — persists
   the module ids with a recent `_last_wake` entry to
   `/run/secubox/waker-active.json`, pruning (deleting from `_last_wake`
   itself, not just filtering the output) any entry older than
   `_WAKE_ACTIVE_TTL_S` (90s — chosen to stay above both
   `_WAKE_MIN_INTERVAL_S`=20s, so an entry never gets purged before that
   anti-storm window ends, and above the sleeper's default 30s tick, with
   margin for jitter). Wired into the `/_wake/{vhost}` route right after
   `_fire_wake(mid)`. Best-effort: an `OSError` writing the file is swallowed
   — a wake that's already fired must never be reported as failed because of
   this side-channel.

2. **`_fire_wake` rewritten to wrap in `systemd-run`** (item 4 of the brief):
   `sudo -n /usr/bin/systemd-run --collect --quiet /usr/sbin/secubox-wakectl
   wake <mid> --json`, fire-and-forget (no `--wait`/`--pipe`, unlike
   `secubox-profilectl`'s panel path which does wait) — the waker never
   blocks an HTTP request on the wake's outcome. Same EROFS rationale as the
   existing `secubox-profilectl` sudoers (waker runs `ProtectSystem=strict`
   with `ReadWritePaths=/run/secubox` only; a plain `sudo` child would
   inherit that sandbox and `secubox-wakectl`, which writes the 4R snapshot
   + audit and drives systemd/LXC, would see everything else EROFS).

3. **`sudoers.d/secubox-profiles`** — added:
   ```
   secubox ALL=(root) NOPASSWD: /usr/bin/systemd-run --collect --quiet /usr/sbin/secubox-wakectl wake *
   ```
   Documented the deliberate wildcard exception (module id is a genuine
   per-call variable): sudo never shells the matched argv (execve, not
   `/bin/sh -c`), `secubox-wakectl`'s argparse treats `module` as a single
   positional never re-parsed as flags, and `wake()` further refuses any id
   not in `load_all()` before touching systemd/LXC. `visudo -c -f
   sudoers.d/secubox-profiles` → **`analyse réussie`** (parsed OK).

4. **`debian/secubox-waker.service`** (new) — `User=secubox`,
   `ExecStart=... uvicorn api.waker:app --uds /run/secubox/waker.sock`,
   `NoNewPrivileges=false` (needs sudo), `RuntimeDirectory=secubox` +
   `RuntimeDirectoryPreserve=yes`, `ProtectSystem=strict` +
   `ReadWritePaths=/run/secubox` only (the socket + `waker-active.json`).
   Hardening copied from `debian/secubox-profiles.service`.

5. **`debian/secubox-sleeper.service`** (new) — `User=root`,
   `ExecStart=/usr/bin/python3 -m api.sleeper_daemon`. Deliberately **no**
   `.timer` unit and **no** sudo/`systemd-run` wrapper: per the brief's own
   guidance ("pick service form to keep the interval in-process"), this is a
   long-running daemon, and unlike the waker it *is* the privileged actuator
   itself (`run_once` → `apply.apply_plan`, same trust level as
   `secubox-wakectl`/`secubox-profilectl`). No `ProtectSystem=strict` either
   — `apply_plan`/`actuate.py` write `/data/lxc/<n>/config`
   (`lxc.start.auto`) and `/etc/secubox/waf/haproxy-routes.json` directly in
   addition to the 4R snapshot dir and audit log; sandboxing this service
   would just reproduce, one layer up, the exact EROFS lesson that motivated
   wrapping the *other* two ctls in `systemd-run` in the first place.

6. **`api/sleeper_daemon.py`** (new) — `main()`/`main_async()` wires
   `sleeper.serve()`'s production dependencies: `observe_all`/`observe` from
   `api/observe.py`, a local `_run` (same subprocess contract as
   `wakectl._run`/`cli.py._run`), `time.monotonic`/an ISO-8601 `stamp`, and
   `DEFAULT_INTERVAL_S=30.0`. Two dependencies are **documented stubs**:
   - `_signal_reader` → returns `{}`. The real sbxwaf-stats source
     (per-vhost `last_request_ts`/`active_conns`) is **not yet stabilized**
     — the interim Go WAF (`secubox-toolbox-ng/cmd/sbxwaf`) doesn't write an
     exploitable `waf-stats.json` yet (project memory: "waf-stats.json
     gap"). `{}` is safe by construction: `should_sleep()` requires a
     non-`None` `Signal` to ever sleep a module, so this stub can never
     sleep anything. **NEEDS_CONTEXT for T12/follow-up**: wire the real
     file/format once sbxwaf writes one.
   - `_hint_probe` → always returns `None` (no per-module `/idle` route
     exists yet); `None` never vetoes nor manufactures a green light.

## TDD: RED → GREEN (the waker-active writer)

RED (`_write_wake_active` didn't exist yet):
```
FAILED tests/test_waker.py::test_wake_writes_active_state_file - FileNotFoundError
FAILED tests/test_waker.py::test_wake_active_file_prunes_stale_entries - AttributeError: module 'api.waker' has no attribute '_write_wake_active'
2 failed, 4 passed in 0.34s
```
GREEN after implementing `_write_wake_active` + wiring the route:
```
cd packages/secubox-profiles && python3 -m pytest tests/test_waker.py -q
7 passed in 0.32s
```
Also added `test_fire_wake_wraps_in_systemd_run_fire_and_forget` (captures
the actual `Popen` argv and asserts the `systemd-run` wrapper + absence of
`--wait`/`--pipe`) and, in `tests/test_sleeper.py`,
`test_sleeper_daemon_wires_serve_with_production_deps` (locks the keyword
wiring between `sleeper_daemon.main_async` and `sleeper.serve` — a rename on
either side is otherwise a runtime-only failure with no static check across
the two modules) plus two tests asserting both stubs are the documented
safe defaults (`{}` / `None`).

## Test results

```
cd packages/secubox-profiles && python3 -m pytest tests/ -q
224 passed, 3 warnings (pre-existing FastAPI on_event deprecation, unrelated)
```

## mypy vs. baseline

```
cd packages/secubox-profiles && python3 -m mypy --strict api/
93 errors in 12 files (checked 23 source files)
```
Identical to the baseline recorded in prior task reports (Task 6/7: "93
errors ... identical to the pre-fix count"). Grepped the output for
`waker.py`/`sleeper_daemon.py` — **zero errors attributed to either file**.
(A plain non-strict `mypy api/` also still shows the same pre-existing 3
errors in `scan.py`/`snapshot.py`/`web.py`, none in my changed/new files.)

## What T12 (packaging) must wire

- `debian/rules` — the default `dh_installsystemd` call only auto-installs
  `debian/secubox-profiles.service` (matches the single binary package
  name). It will **not** pick up `debian/secubox-waker.service` or
  `debian/secubox-sleeper.service` automatically. T12 needs:
  ```
  override_dh_installsystemd:
  	dh_installsystemd --name=secubox-profiles
  	dh_installsystemd --name=secubox-waker
  	dh_installsystemd --name=secubox-sleeper
  ```
  (the `--name=X` convention matches `debian/X.service` exactly, which is
  how these two files are named).
- `debian/postinst` — currently only does
  `enable`/`restart secubox-profiles.service`. T12 must add
  `systemctl daemon-reload`, `enable --now secubox-waker.service`, and
  `enable --now secubox-sleeper.service` (idempotent, matching the existing
  pattern).
- `sudoers.d/secubox-profiles` — **no T12 action needed**: the new waker
  grant was added to the *same file* the existing `override_dh_auto_install`
  already installs wholesale, so it ships automatically.
- nginx wiring (the `@waker` `include`) is Task 7/12's separate concern, not
  touched here.
- The `_signal_reader` stub (`api/sleeper_daemon.py`) is a genuine
  NEEDS_CONTEXT item — the real sbxwaf stats path/format should be resolved
  before scale-to-zero can actually observe front traffic in production;
  until then the sleeper is inert-but-safe (never sleeps anything).

## Files changed

- `packages/secubox-profiles/api/waker.py` — `_write_wake_active` +
  `_WAKE_ACTIVE_PATH`/`_WAKE_ACTIVE_TTL_S`, `_fire_wake` rewritten to the
  `systemd-run` wrapper, wired into the wake route.
- `packages/secubox-profiles/api/sleeper_daemon.py` (new) — production
  entrypoint for `secubox-sleeper.service`.
- `packages/secubox-profiles/sudoers.d/secubox-profiles` — added the waker→
  `systemd-run`→`wakectl` grant.
- `packages/secubox-profiles/debian/secubox-waker.service` (new).
- `packages/secubox-profiles/debian/secubox-sleeper.service` (new).
- `packages/secubox-profiles/tests/test_waker.py` — 3 new tests (writer,
  pruning, `systemd-run` argv).
- `packages/secubox-profiles/tests/test_sleeper.py` — 3 new tests (wiring +
  both stub safety checks).

## Self-review

- Confirmed `_WAKE_ACTIVE_PATH` matches `api/sleeper.py::WAKE_LOCK_FILE`'s
  literal value (`/run/secubox/waker-active.json`) — no cross-import between
  the two modules by design (they're separate processes/services
  communicating only through this file), so I cross-checked the literal
  string by hand instead of relying on a shared import.
- Verified the sudoers wildcard risk reasoning against `api/wake.py::wake()`
  (confirms it rejects unknown module ids via `load_all()` before driving
  systemd/LXC) rather than just asserting it in the comment.
- Ran the full per-directory suite and `mypy --strict api/` (matching the
  established baseline-comparison method from prior tasks in this plan, not
  just a single-file mypy check).
- Deliberately did **not** create `secubox-sleeper.timer` even though the
  brief's file list mentions it — its own "Interfaces" section explicitly
  offers the long-running-service alternative and recommends it ("cleaner...
  keeps the interval in-process"); documented this as a considered deviation
  rather than an oversight.

## Concerns

- `_WAKE_ACTIVE_TTL_S=90.0` and `sleeper_daemon.DEFAULT_INTERVAL_S=30.0` are
  my own chosen defaults (the brief left the exact numbers unspecified
  beyond "within the sleeper interval"); both are cross-referenced in code
  comments on both sides so a future change to one should prompt a look at
  the other, but there's no automated check tying them together.
- The `_signal_reader` stub is a real functional gap, not just a test seam:
  until T12/a follow-up wires real sbxwaf stats, the sleeper daemon will run
  forever without ever sleeping a single module. Flagged above as
  NEEDS_CONTEXT, not silently swept under a TODO.
- `secubox-sleeper.service` has no filesystem sandbox at all beyond
  `ProtectHome`/`PrivateTmp` — appropriate given it drives systemd/LXC/WAF
  routes directly as root, but it's a broader trust surface than the waker;
  worth a second look if this daemon's scope ever grows beyond the
  actuation it already delegates to `apply.apply_plan`.
