# Task 5 report — sleeper `run_once` (scale-to-zero, #896)

Branch: `feat/scale-to-zero-public-services` (pre-existing, not created here).

## What was implemented

`packages/secubox-profiles/api/sleeper.py`:

- Added `run_once(*, root, manifests, actuals, signals, hints, run, observe,
  now, apply=True, wake_locked=frozenset()) -> list[str]` alongside the
  existing (Task 4) `should_sleep`.
- For each module (sorted by id): skip if `mid in wake_locked`; compute
  `now_up = is_on(actuals[mid])` (guarded — `a is not None`); if
  `should_sleep(m, signals.get(mid), hint_idle=hints.get(mid),
  now_up=now_up)` is true, build a one-element STOP `Change` and hand it to
  `apply.apply_plan` (one module at a time, exactly the brief's code). If the
  report is `"applied"` and `mid` is in `report.changed`, append `mid` to the
  returned list.

**Snap_root/audit_path safety (the flagged risk)** — the brief's literal
`run_once` passes `snap_root=SNAP_DIR, audit_path=AUDIT_LOG` verbatim (real
`/var` paths), which would make `test_run_once_stops_only_idle_sleepable`
(non-mocked `apply_plan`) write into the live 4R chain / audit log. Task 2's
`api/wake.py` had already solved the identical problem for `wake()` with a
private `_snap_root_for`/`_audit_path_for` pair keyed on `root ==
DEFAULT_ROOT`. Rather than duplicate that logic in `sleeper.py` (divergence
risk flagged in the task brief), I **factored it into a new shared module**,
`packages/secubox-profiles/api/actuate_paths.py`:

```python
DEFAULT_ROOT = Path("/etc/secubox")

def snap_root_for(root: Path) -> Path:
    return SNAP_DIR if root == DEFAULT_ROOT else root / "profiles" / "rollback"

def audit_path_for(root: Path) -> Path:
    return AUDIT_LOG if root == DEFAULT_ROOT else root / "audit.log"
```

`api/wake.py` was refactored to import `DEFAULT_ROOT`,
`snap_root_for as _snap_root_for`, `audit_path_for as _audit_path_for` from
`.actuate_paths` instead of defining its own copies (its own local
`SNAP_DIR`/`AUDIT_LOG` imports were dropped, now only reached transitively
through `actuate_paths`). `wake()`'s behavior, docstrings-worth of reasoning,
and public API are unchanged — only the two helper *definitions* moved,
carrying their explanatory comment (production must share the 4R chain +
audit with `profilectl`; non-default `--root` is test-only confinement; a
future multi-root deployment, e.g. cellule-in-a-box #843, would need
`cli.py` aligned too — not in scope here).

`api/sleeper.py`'s `run_once` imports the same two functions from
`.actuate_paths` and calls `_snap_root_for(root)` / `_audit_path_for(root)`
exactly like `wake()` does, so wake and sleep share one definition of "which
root gets the real 4R chain" — no divergent logic between the two actuators.

## TDD evidence

### Step 1 — RED

Added the SPDX header (the file lacked one) plus the two verbatim tests from
the brief to `tests/test_sleeper.py`:
`test_run_once_stops_only_idle_sleepable`, `test_run_once_skips_wake_locked`.

```
$ python -m pytest tests/test_sleeper.py -k run_once -v
tests/test_sleeper.py::test_run_once_stops_only_idle_sleepable FAILED
tests/test_sleeper.py::test_run_once_skips_wake_locked FAILED
ImportError: cannot import name 'run_once' from 'api.sleeper'
2 failed, 7 deselected in 0.09s
```

### Step 4 — GREEN

```
$ python -m pytest tests/test_sleeper.py -v
9 passed in 0.07s

$ python -m pytest tests/ -q
207 passed, 3 warnings in 0.85s
```

(207 = full package suite; warnings are pre-existing FastAPI `on_event`
deprecation notices, unrelated to this task.)

## Live-path-untouched verification (the flagged risk, checked explicitly)

Before and after the full test run:

```
$ ls /var/lib/secubox/profiles/rollback
ls: impossible d'accéder à '/var/lib/secubox/profiles/rollback': Aucun fichier ou dossier de ce nom
$ stat -c '%Y %n' /var/log/secubox/audit.log
1783140369 /var/log/secubox/audit.log     # mtime = July 4, unrelated to this run
```

`SNAP_DIR` (`/var/lib/secubox/profiles/rollback`) does not exist at all on
this machine — never created by the test. `AUDIT_LOG`'s mtime predates this
session by weeks. Both `_snap_root_for`/`_audit_path_for` correctly redirect
under `tmp_path` (a non-`DEFAULT_ROOT` root) in both new tests, confirming
the confinement mirrors Task 2's `wake.py` pattern exactly.

## mypy — whole-`api/` vs baseline (dee5670a)

Baseline (`git stash` to pure HEAD before this task):

```
$ python -m mypy --strict api/
Found 92 errors in 11 files (checked 19 source files)
```

After this task's changes (`git stash pop`):

```
$ python -m mypy --strict api/
Found 93 errors in 12 files (checked 19 source files)
```

Diffed the two sorted error lists directly (not just counts):

- `api/wake.py`'s two baseline errors (`no-untyped-def`, `type-arg` on
  `wake()`) **moved from lines 59/60 to lines 33/34** — same errors, same
  function, just shifted because the import block shrank. Not new.
- **One genuinely new line**: `api/sleeper.py:43: error: Function is missing
  a type annotation for one or more parameters [no-untyped-def]` — this is
  `run_once`'s untyped `manifests`/`actuals`/`signals`/`hints`/`run`/
  `observe`/`wake_locked` parameters, transcribed verbatim from the brief's
  literal signature. It is the exact same error *category*, on the exact
  same *kind* of function (an injected-`run`/bare-collection actuator entry
  point), as the pre-existing `wake.py` baseline error — the accepted idiom
  named in the global constraints ("no NEW errors beyond the accepted
  untyped-injected-run/bare-collection idiom, NOT zero"). No new error
  *categories* were introduced.

## Files changed

- `packages/secubox-profiles/api/sleeper.py` — added `run_once` + imports.
- `packages/secubox-profiles/api/actuate_paths.py` — new, shared
  `DEFAULT_ROOT`/`snap_root_for`/`audit_path_for`, factored out of
  `wake.py`.
- `packages/secubox-profiles/api/wake.py` — refactored to import the shared
  helpers instead of defining its own; no behavior change.
- `packages/secubox-profiles/tests/test_sleeper.py` — SPDX header added
  (was missing); two new tests appended verbatim from the brief.

## Self-review

- Confirmed `wake.py`'s public behavior is byte-identical after the
  refactor: full suite (`tests/test_wake.py`, 7 tests) still green, and the
  mypy diff shows only a line-number shift for its two pre-existing errors,
  not a change in kind or count.
- Confirmed `run_once` never touches `manifests`/`actuals`/`signals`/`hints`
  from disk itself — `root` is used *only* to derive `snap_root`/
  `audit_path`, matching the brief's contract ("signals/hints are dicts
  keyed by module id; the caller maps vhost→module and probes /idle").
- Confirmed `wake_locked` is checked before any `should_sleep`/`observe`
  work — a wake-locked module is skipped outright, never even evaluated for
  idleness, matching `test_run_once_skips_wake_locked`.
- Verified via `git status --short` before staging that only the four files
  above (plus this report) are part of this task's commit — the
  pre-existing unrelated modified files (`.superpowers/sdd/task-2-report.md`,
  `.superpowers/sdd/task-4-report.md`, `.superpowers/sdd/task-7-report.md`)
  were left untouched/unstaged.
- Ran the tests from `packages/secubox-profiles/` (per-directory), never
  from repo root, per the known `pytest.ini` collision gotcha.

## Concerns

- `run_once` calls `apply.apply_plan` once per idle module inside its loop,
  each call doing its own snapshot capture (`_snapshot.capture`) and R1→R4
  rotation. On a box with many simultaneously-idle sleepable modules, a
  single daemon pass will rotate the 4R chain once per stopped module in
  that pass, not once for the whole pass — same granularity trade-off as
  `wake()` (one wake = one snapshot), consistent with the existing design,
  but worth flagging if a future reviewer expects one snapshot per daemon
  pass rather than per module.
- Per the brief/global-constraints, `run_once`'s new parameters are
  intentionally left untyped (bare collections, injected `run`/`observe`),
  matching the codebase's established actuator-entry-point idiom (`wake()`
  has the same shape) — flagged above under mypy, not treated as a defect.
