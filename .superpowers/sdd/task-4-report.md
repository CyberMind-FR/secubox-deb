# Task 4 report — profiles Phase 3a: CLI `apply`/`rollback` (root-only) + version + tests

**Status:** DONE
**Branch:** feat/profiles-apply-phase3a (already checked out, not switched)
**Commit:** `c9690a52` — feat(profiles): secubox-profilectl apply/rollback (root-only, dry-run default) — 0.4.0

## Starting state found

`packages/secubox-profiles/api/cli.py` and `tests/test_cli.py` already carried
an **uncommitted** implementation of `apply`/`rollback` in the working tree
(from an earlier, interrupted session on this same branch) — imports,
`_cmd_apply`, `_cmd_rollback`, subparser registration, and the brief's first
two apply tests plus a concretized `test_apply_only_filters_plan` were
already present, matching the brief closely. `debian/changelog` had **not**
been bumped yet. I verified this against committed `HEAD` via `git stash`
(HEAD's `cli.py`/`test_cli.py` are still Phase-1 read-only, with the old
`test_apply_is_not_a_command_in_phase_1` guard test — 12 passed), so the
delta below is real, not a no-op.

## Bug found and fixed (in `cli.py`, not test code)

`_cmd_rollback` called the bare name `rollback_to(...)`, but `rollback_to`
was **never imported anywhere** in `cli.py` (only `from . import apply,
export` at the top, and `apply.apply_plan` used via attribute access in
`_cmd_apply` for the documented monkeypatch reason). This is a guaranteed
`NameError` on the very first real `rollback` invocation, and nothing in the
existing test suite exercised the `rollback` subcommand at all, so it was
invisible. Fixed by switching to `apply.rollback_to(...)` — same
attribute-access pattern as `apply.apply_plan`, same rationale (a test that
monkeypatches `api.apply.rollback_to` after import must be seen through the
module attribute, not a name bound at import time).

## Test coverage added beyond the brief

The brief's Step 1 only specified `apply` tests (`test_apply_requires_root`,
`test_apply_dry_run_default_acts_on_nothing`, and the placeholder
`test_apply_only_filters_plan`, already concretized in the working tree with
two native modules `x`/`y`, both observed on via a monkeypatched
`_observe_all`, `--only x` asserted to leave `{"x"}` as the only id in the
plan passed to a spied `apply.apply_plan`). It said nothing about testing
`rollback`. Since the NameError bug above was only reachable through
`rollback`, I added two tests mirroring the apply ones:
`test_rollback_requires_root` (root gate → rc 1) and
`test_rollback_dry_run_default_acts_on_nothing` (monkeypatches
`cli.read_snapshot` and spies `api.apply.rollback_to`, asserting `apply=False`
was passed and the call happened exactly once). Both would have failed
against the pre-fix `cli.py` (NameError, not just a wrong return value).

## Verification

Step 2 (must fail) — replayed by checking out committed `HEAD`'s `cli.py`
against the new/extended `test_cli.py`:
```
$ .venv/bin/python -m pytest packages/secubox-profiles/tests/test_cli.py -q
5 failed, 11 passed in 0.54s
FAILED test_apply_requires_root — SystemExit (argparse: invalid choice 'apply')
FAILED test_apply_dry_run_default_acts_on_nothing
FAILED test_apply_only_filters_plan
FAILED test_rollback_requires_root — SystemExit (argparse: invalid choice 'rollback')
FAILED test_rollback_dry_run_default_acts_on_nothing — AttributeError: no attribute 'read_snapshot'
```

Step 4 (must pass) — current `cli.py` (with the `rollback_to` fix) + full
test file:
```
$ .venv/bin/python -m pytest packages/secubox-profiles/tests/test_cli.py -q
16 passed in 0.12s
```

Full module suite:
```
$ .venv/bin/python -m pytest packages/secubox-profiles/tests -q
142 passed, 3 warnings in 0.66s
```
(warnings are pre-existing FastAPI `on_event` deprecation notices in
`api/web.py`, unrelated to this task.)

AST check:
```
$ python3 -c "import ast; ast.parse(open('packages/secubox-profiles/api/cli.py').read()); print('cli OK')"
cli OK
```

## Invariants verified

- **Root-only**: `test_apply_requires_root` and `test_rollback_requires_root`
  both assert rc 1 when `_running_as_root()` is False, without touching
  anything else.
- **Dry-run default**: `test_apply_dry_run_default_acts_on_nothing` and
  `test_rollback_dry_run_default_acts_on_nothing` spy on
  `apply.apply_plan`/`apply.rollback_to` and assert `apply=False` was passed
  when `--yes` is omitted, and that exactly one call happened (rc 0).
- **`--only` filter**: `test_apply_only_filters_plan` builds two native
  modules (`x`, `y`), both observed on with no active profile (desired off
  for both → an unfiltered plan would stop both), and asserts the plan
  object handed to the spied `apply.apply_plan` contains only `{"x"}` when
  `--only x` is given — proving the filter is applied to the plan itself,
  before the dry-run print and before the (spied) actuation call.

## Files changed

- `packages/secubox-profiles/api/cli.py` — `rollback_to` → `apply.rollback_to`
  fix (the rest of the apply/rollback wiring was already present).
- `packages/secubox-profiles/tests/test_cli.py` — kept the existing apply
  tests as-is, added `test_rollback_requires_root` and
  `test_rollback_dry_run_default_acts_on_nothing`.
- `packages/secubox-profiles/debian/changelog` — prepended the 0.4.0 entry
  from the brief verbatim.

## Concerns

1. No board deployment performed — pure code + local unit tests, as scoped.
2. Boot-time reconciliation and the API/panel surfaces for apply/rollback are
   explicitly out of scope for this task (noted in the changelog entry as a
   follow-up), consistent with the plan's stated Phase 3a boundary.
3. The `.superpowers/sdd/task-4-report.md` file this report replaces held
   unrelated content from a different task (a `secubox-cve-triage`
   product-absent-probes emitter) — overwritten per this task's explicit
   report-writing instruction; that content is preserved in git history if
   needed.

## Final-review fix wave (2026-07-19)

Two review findings fixed on `feat/profiles-apply-phase3a`:

1. **Route-value set/dict conflation** — `observe.load_routes()` returns a
   `set[str]` of domain names (used for `portal_routed` membership);
   `_cmd_apply`/`_cmd_rollback` were deriving `routes_map` from that same set
   via `routes if isinstance(routes, dict) else {}`, which is always `{}` on
   the real board. `snapshot.capture` therefore recorded `route: None` for
   every portal module, so `rollback` could stop+restart a portal module but
   never re-add its WAF route. Fix: added `observe.load_route_values()` (a
   new best-effort dict loader, domain -> `[host, port]`, `{}` on
   absent/corrupt file) and wired `_cmd_apply`/`_cmd_rollback` to pass
   `load_route_values()` — not the set-derived expression — as `apply_plan`'s
   / `rollback_to`'s `routes=` kwarg. `load_routes()` itself is untouched and
   still feeds `_observe_all`.
2. **Corrupt-JSON traceback escape** — `json.JSONDecodeError` is a
   `ValueError`, not caught by `apply_plan`'s forward-loop
   `except (ActuationError, OSError)` nor by `_rollback_applied`'s per-step
   except. Fix: added `ValueError` to both tuples in `api/apply.py`, and
   added a `except (OSError, ValueError)` handler in `cli.main()` (after the
   existing `ManifestError`/`StateError` and `ProtectedViolation`/
   `ApplyError` handlers) so a pre-flight corrupt-JSON failure (e.g.
   `snapshot.capture`) prints `erreur: ...` and returns rc 2 instead of a raw
   traceback.

Tests added in `test_cli.py`:

- `test_apply_passes_route_value_dict_not_set_derived_empty_dict` — spies on
  `apply.apply_plan`, monkeypatches `load_routes` (set) and
  `load_route_values` (dict) separately, asserts the `routes=` kwarg received
  is the dict with real `[host, port]` values, not `{}`.
- `test_main_maps_valueerror_to_rc2_not_traceback` — makes `apply.apply_plan`
  raise a bare `ValueError` and asserts `cli.main()` returns rc 2.

Mutation checks performed (both reverted after confirming):

1. Reverted `cli.py`'s `routes_map` to the old set-derived expression → new
   test failed with `assert {} == {'lyrion.gk2...': [...]}`. Confirms the
   test pins the fix.
2. Removed `ValueError` from `apply_plan`'s forward `except` tuple and drove
   `apply_plan` directly (manual script, not committed) with a
   `_do_change` raising `json.JSONDecodeError` — confirmed it escapes
   uncaught (`ESCAPED as JSONDecodeError: bad: line 1 column 1 (char 0)`).
   Restored the tuple; `cli.main()`'s rc-2 handler remains the primary guard
   for the pre-flight case covered by the added unit test.

Full suite: `145 passed` (`.venv/bin/python -m pytest
packages/secubox-profiles/tests -q`).

Files touched this wave: `packages/secubox-profiles/api/observe.py`,
`packages/secubox-profiles/api/cli.py`, `packages/secubox-profiles/api/apply.py`,
`packages/secubox-profiles/tests/test_cli.py`.

## Concerns (fix wave)

1. `load_route_values()` reads the fixed `ROUTES_FILE` path directly (same
   pattern as `load_routes()`) rather than accepting a `routes_path=`
   parameter from the CLI — consistent with existing conventions in
   `observe.py`, but means CLI-level route-path overrides (if ever added)
   would need to thread through both loaders symmetrically.
2. No board deployment performed for this wave — pure code + local unit
   tests, as scoped by the review brief. The route-value round-trip
   (`apply --only <a portal module> --yes`, then `rollback --yes`) should be
   verified live before this branch merges, per the finding's own board-observed
   failure mode.
   needed.
   needed.
