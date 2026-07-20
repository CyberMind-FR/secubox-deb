# Task 11 report — watchdog exclusion + boot reconciliation + health-monitor awareness (ref #896)

**Status: DONE_WITH_CONCERNS** (concerns are documented findings, not
failures — see "Concerns" below; everything that could be built and tested
in-scope is built and green).

## What I investigated

### secubox-watchdog (`packages/secubox-watchdog/api/main.py`)

On the **current HEAD** (`8e9ca2df`), `secubox-watchdog` has **no auto-revive
logic at all**: `monitor_loop()` (line 394) only tracks up/down state
transitions and fires webhooks (`add_event`, line 194) — it never calls
`lxc-start`/`systemctl restart` on its own. The only restart paths are the
JWT-protected `POST /container/restart` (line 646) and `POST /service/restart`
(line 673), invoked by a human/other actor, not automatically. So **today**,
nothing in this repo would fight the sleeper/waker over a stopped on-demand
container.

However, there is a **separate, unmerged local branch**
`feat/watchdog-auto-revive` (commit `0370beb4`, based on master `60f059ac`,
NOT an ancestor of this feature branch's HEAD) that adds exactly this
capability: `_discover_containers()` (`sudo lxc-ls -f`) + `_auto_revive()`
wired into `monitor_loop`. Its own commit message states the gate
explicitly: *"managed containers (`lxc.start.auto=1` — the 'should be up'
flag) that are STOPPED get `sudo lxc-start`... The AUTOSTART gate
deliberately EXCLUDES scale-to-zero sleepers (streamlit et al. are
NO-AUTO)."* — i.e. **the exclusion mechanism is `lxc.start.auto`**, checked
live via `lxc-ls -f`, not a separate exclusion file.

I traced how "streamlit sleepers are excluded today" actually works:
`packages/secubox-streamlit/sbin/streamlitctl`'s `stop`/`pause` path calls
`lxc-stop -n "$LXC_NAME"` directly (line 164/185/199) and **never touches
`lxc.start.auto`**. The streamlit LXC simply never had `lxc.start.auto = 1`
granted in the first place (unlike `install-lxc.sh` for mail/lyrion/grafana/
frigate/etc., which explicitly write `lxc.start.auto = 1` — streamlit's
provisioning does not). So the "exclusion" is not an active un-setting, it's
the container never having been granted autostart to begin with — the same
flag the (unmerged) auto-revive gate checks.

**Verification of the task's core hypothesis:** `packages/secubox-profiles/api/actuate.py::runtime_stop`
(lines 175-188) already sets `lxc.start.auto=0` **before** `lxc-stop` for
every module it stops (LXC-backed on-demand or eager), with the comment on
line 185-186 spelling out the exact reason: *"autostart=0 AVANT lxc-stop :
sinon secubox-watchdog relance le conteneur (course observée sur la
board)."* — this is a pre-existing, already-shipped safeguard written
specifically anticipating this race. Combined with the discovery above:
**once `feat/watchdog-auto-revive` is merged, it is already fully compatible
with #896's on-demand sleepers with zero additional wiring** — it reads the
exact same flag the actuator already toggles, using the exact same
mechanism as the existing streamlit exclusion. No new exclusion file/format
was invented, per the task's explicit permission to document this instead
of forcing an artifact with no consumer.

Native (non-LXC) modules: `secubox-watchdog`'s `services` monitoring is a
static allowlist (`nginx`, `haproxy`, `crowdsec`, `nftables` in
`DEFAULT_CONFIG`) with no auto-restart logic anywhere (native or LXC) on
HEAD, and the unmerged auto-revive commit only touches containers — no gap
for native on-demand modules either now or after that merge.

### Health monitor (`admin.gk2.secubox.in/health/`)

The `/health/` page is served by `secubox-hub`
(`packages/secubox-hub/menu.d/05-health.json`, `www/health/`). Its
JWT-protected data (`module_health_summary`/`status`/`alerts`,
`packages/secubox-hub/api/main.py:1173-1247`) reads
`MODULE_HEALTH_CACHE = /var/cache/secubox/health/modules.json` — produced by
**`module_prober.py`/`prober.py`, which are NOT in this source tree.**
`.claude/TODO.md:224` tracks this explicitly: `#393 source-home des scripts
health prober`. `.claude/WIP.md` (Session 107/108) documents these scripts
were created directly on the board (`/usr/lib/secubox/health/prober.py`,
`/usr/lib/secubox/health/module_prober.py`) and never rapatriated. **This is
a genuine cross-package situation I cannot cleanly fix from within this
repo** — exactly the fallback the task anticipated.

`secubox-hub` **does** compute a second, simpler, in-repo signal used for the
sidebar LED widgets: `_refresh_health_batch()`
(`packages/secubox-hub/api/main.py:382`), a direct `systemctl list-units
secubox-*` walk. Before my change, any `secubox-*.service` observed
`inactive`/`dead` (exactly what an intentionally-slept module's unit looks
like once `actuate.runtime_stop` disables+stops it) fell into the catch-all
`else` branch → `{"status": "warn", "msg": "inactive/dead"}` — flagged as
degraded, indistinguishable from an actual failure. This one I *could* fix
in-repo, and did.

## What I built

1. **`packages/secubox-profiles/api/lifecycle.py`** — two new pure functions
   (TDD, `tests/test_lifecycle.py` extended with 6 new tests, all RED before
   → GREEN after):
   - `boot_should_start(m) -> bool`: `effective_lifecycle(m) in ("always-on",
     "eager")`. Exact brief signature.
   - `watchdog_should_manage(m) -> bool`: `not is_sleepable(m)`. Documents
     (docstring) that this is deliberately *not* a file-generator trigger —
     the real non-revival mechanism is the `lxc.start.auto` flag toggled by
     `actuate.py`, verified above; this pure function exists to make the
     invariant explicit and testable, per the brief's required interface.

2. **`packages/secubox-profiles/api/healthsync.py`** (new) — the
   profiles-side export for the cross-package health-monitor gap:
   `sleepable_module_ids(manifests)` (sorted ids where `is_sleepable`) and
   `write_sleepable(*, manifests, out_path)` (atomic temp+rename write,
   same pattern as `wafsync.write_ondemand`/`nginxgen`). TDD:
   `tests/test_healthsync.py` (3 tests, RED → GREEN).

3. **`packages/secubox-profiles/api/wake.py`** — new `health-sync` CLI verb
   on `secubox-wakectl` (mirrors `nginx-sync`/`waf-sync`: config→file
   round-trip, does **not** require root), default output
   `/etc/secubox/health/sleepable-modules.json`. TDD:
   `tests/test_wake.py` (+1 test, RED → GREEN).

4. **`packages/secubox-hub/api/main.py`** — wired the export into the
   in-repo sidebar signal: `_load_sleepable_modules()` (best-effort read of
   the export, same absent/corrupt→empty-set discipline used throughout
   `secubox-profiles`) + `_refresh_health_batch()` now checks the sleepable
   set before falling into the generic `warn` branch: a sleepable module's
   `inactive`/`dead` unit → `{"status": "ok", "msg": "Asleep (on-demand)"}`
   instead of `warn`. A `failed` unit is **not** affected (stays `error`
   even for a sleepable module — a crash is a real alarm; intentional sleep
   goes through disable+stop, never `failed`). TDD:
   `packages/secubox-hub/tests/test_cache_warm.py` (+2 tests: asleep-not-warn,
   failed-beats-sleepable — both RED → GREEN).

## TDD summary

- `test_lifecycle.py`: RED (`ImportError: boot_should_start`) → wrote
  `lifecycle.py` → GREEN, 11/11.
- `test_healthsync.py`: RED (`ModuleNotFoundError: api.healthsync`) → wrote
  `healthsync.py` → GREEN, 3/3.
- `test_wake.py` (`health-sync` verb): RED (`argparse: invalid choice`) →
  wired subparser+dispatch → GREEN, 10/10.
- `test_cache_warm.py` (secubox-hub): RED (asleep test asserted `"ok"`/
  `"Asleep (on-demand)"` against unmodified code, which produced `"warn"`) →
  patched `_refresh_health_batch` → GREEN.

## Test results

```
cd packages/secubox-profiles && python -m pytest tests/ -q
246 passed, 3 warnings

cd packages/secubox-hub && python -m pytest tests/ -q
1 failed (test_health_batch_cold_miss_builds_once), 24 passed
```

The one hub failure is **pre-existing** — verified via `git stash` (reverts
all my changes) and re-running the exact same test in isolation:
`FAILED tests/test_cache_warm.py::test_health_batch_cold_miss_builds_once`
fails identically on unmodified HEAD `8e9ca2df`. Not caused by, and not
fixed by, this task's changes.

## mypy vs baseline

- `packages/secubox-profiles`: `python -m mypy --strict api/` →
  **102 errors in 12 files**, identical count/file-set to unmodified HEAD
  `8e9ca2df` (`git stash` verified). Targeted `mypy --strict api/lifecycle.py
  api/healthsync.py` → 4 errors, all pre-existing and transitively from
  `api/manifest.py` (same as Task 4's documented baseline noise) — zero
  attributable to the two files touched/added here.
- `packages/secubox-hub`: `python -m mypy api/main.py` → **16 errors**,
  identical count/content to unmodified HEAD (line numbers shift because
  code was inserted; the error set itself — `secubox_core` import-not-found,
  `datetime` not defined, etc. — is unchanged). Zero new errors from my
  additions.

## Files changed

- `packages/secubox-profiles/api/lifecycle.py` — `boot_should_start`,
  `watchdog_should_manage`.
- `packages/secubox-profiles/api/healthsync.py` (new) — sleepable-ids export.
- `packages/secubox-profiles/api/wake.py` — `health-sync` CLI verb.
- `packages/secubox-profiles/tests/test_lifecycle.py` (+6 tests).
- `packages/secubox-profiles/tests/test_healthsync.py` (new, 3 tests).
- `packages/secubox-profiles/tests/test_wake.py` (+1 test).
- `packages/secubox-hub/api/main.py` — `SLEEPABLE_MODULES_CACHE`,
  `_load_sleepable_modules`, `_refresh_health_batch` sleepable branch.
- `packages/secubox-hub/tests/test_cache_warm.py` (+2 tests).

## Judgment calls / deviations from the brief

1. **No watchdog exclusion file was generated.** The brief's illustrative
   interface says "a generated watchdog-exclusion list... so `wakectl
   watchdog-sync` writes the exclusion file the watchdog reads." Investigation
   showed **no such file is read by any watchdog code path** (current HEAD
   has no auto-revive at all; the unmerged auto-revive commit reads
   `lxc.start.auto` live via `lxc-ls`, never a config file for this
   specific gate). Inventing a file nothing consumes would be exactly the
   "parallel format" the task instructions explicitly forbid. I implemented
   `watchdog_should_manage(m)` as the required pure-policy interface instead,
   and documented the real mechanism (the flag) in its docstring and here.
2. **`boot_should_start` is not wired into any boot-time reconciler**,
   because none exists in `secubox-profiles` today (`api/cli.py` only has
   `status`/`diff`/`scan`/`export`/`apply`/`rollback`; no systemd unit runs
   a reconcile pass at boot). Building that reconciler from scratch (a new
   CLI verb + systemd unit + `actuate.py` semantics changes to distinguish
   "profile ON" from "start now" for eager vs. on-demand) is materially
   larger than this task's Files/Interfaces scope and touches
   already-tested `actuate.py`/`apply.py` behavior relied on by
   `test_actuate.py`/`test_apply.py`. Delivered as pure, tested policy ready
   for that future reconciler; not wired.
3. **`health-sync` is not scheduled anywhere** (no systemd timer, no
   postinst invocation) — consistent with `nginx-sync` (Task 7) and
   `waf-sync` (Task 2), neither of which is scheduled either; nothing in
   `apply.py`/`web.py`/`sleeper.py`/`waker.py` calls any of the three
   `*-sync` verbs automatically today. This is a pre-existing, consistent
   gap across all three generators, not something this task introduced or
   was asked to close.

## Concerns (why DONE_WITH_CONCERNS, not DONE)

- The health-monitor fix only covers **secubox-hub's sidebar LED signal**
  (`_refresh_health_batch`). The actual `/health/` full-page dashboard reads
  a *different* cache (`/var/cache/secubox/health/modules.json`) produced by
  board-only, not-yet-sourced scripts (TODO #393). Once those scripts are
  rapatriated, they should read
  `/etc/secubox/health/sleepable-modules.json` (produced by `secubox-wakectl
  health-sync`) the same way `_load_sleepable_modules()` does here, and
  report a sleepable+inactive module as a distinct non-alarm status instead
  of `down`/`degraded`. This is an explicit, precise follow-up, not
  something I can close from `secubox-profiles`/`secubox-hub`.
- `feat/watchdog-auto-revive` (commit `0370beb4`) is unmerged. I did **not**
  merge it — it is unrelated pre-existing work for a different bug
  (photoprism 502 self-heal), and merging branches without being asked is
  out of scope here. Flagging as a recommended follow-up: once merged, no
  further #896 wiring is needed (verified above), but until then the
  watchdog literally cannot auto-revive anything, sleeping or not.
- `secubox-wakectl health-sync` needs to actually run (e.g. from whatever
  eventually schedules `waf-sync`/`nginx-sync`) for `secubox-hub`'s new
  branch to ever see a non-empty sleepable set on a real board; until then
  `_load_sleepable_modules()` safely returns `set()` (no regression, just no
  effect yet).
