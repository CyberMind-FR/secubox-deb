<!--
SPDX-License-Identifier: LicenseRef-CMSD-1.0
Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
Source-Disclosed License — All rights reserved except as expressly granted.
See LICENCE-CMSD-1.0.md for terms.
-->

# secubox-profiles — Actuation Robustness (observed-state arbiter) — Design

**Date:** 2026-07-20
**Module:** `secubox-profiles`
**Status:** approved design → implementation plan next
**Related:** [Profiles Phase 3a apply actuator](../plans/) (0.4.1), profiles mass-apply `lite` test (2026-07-19)

---

## Problem

The first real mass apply (profile `lite`, 65 stops) via the live panel path
aborted at module 22 (`metrics`) and auto-rolled-back the 21 already-stopped
modules. The rollback machinery worked end-to-end (gateway stayed 200, board
restored), but the abort was **spurious**: the actuator judged the stop by the
**command's return code**, not by the **observed state**.

Root cause, confirmed by systematic debugging on the board:

1. `metrics` has `TimeoutStopUSec = 90s` (systemd default). `systemctl disable
   --now secubox-metrics.service` **blocks** on the unit's stop, up to 90s.
2. `cli._run` runs every command with a hard `timeout=15` and catches
   `(OSError, subprocess.SubprocessError)` together, returning `(None, "")` —
   so a `subprocess.TimeoutExpired` (the command *ran and is still working*) is
   **indistinguishable** from "the command could not run".
3. `actuate._must` raises `ActuationError` on `rc != 0` (including `None`) —
   immediately, **before** `wait_state` gets to observe reality.
4. `apply.apply_plan` treats that as a module failure → rolls back.

Decisive evidence: after the rollback, `metrics` was `inactive/disabled/dead` —
**systemd completed the stop** after `_run`'s 15s client was killed. The stop
*succeeded*; the ctl mis-read it as a failure.

A second, latent timeout compounds it: `apply_plan(wait_timeout=30.0)` is also
shorter than a 90s `TimeoutStopSec`, so even a corrected `_run` alone would let
`wait_state` time out on a legitimately slow unit.

On a 65-stop plan it is near-certain that at least one unit exceeds these
timeouts → a full-tier apply almost always aborts partway. This blocks applying
`lite` / `secure-gateway` / `media-lab` as designed.

A related defect surfaced in the same path: the `/apply` route
([web.py:492-496](../../../packages/secubox-profiles/api/web.py)) writes
`active = body.profile` **then** runs the ctl, and never reverts `active` when
the ctl reports `rolled_back`. After an auto-rollback the `active` pointer lies:
it names the target profile while the modules are back at the previous one.

## Goal

The **observed state** — not a command's return code — decides whether a
STOP/START reached its target, so a slow-but-successful transition cannot
spuriously fail a mass apply, and `wait_state` waits long enough for the
slowest unit to actually converge.

## Non-goals

- No change to `is_on` semantics for `status` / `diff` (host-unit-only for LXC
  stays — see §2, ripple avoidance).
- No change to the 4R snapshot / rollback-on-failure / protected-refusal design
  (those worked correctly in the test).
- No parallelism (actuation stays strictly one module at a time).
- No new profiles or tiers; no UI redesign.

## Global Constraints

- Python 3.11 (board), `from __future__ import annotations`, mypy `--strict`
  clean, SPDX header block on every file.
- `run` stays dependency-injected everywhere (`rc=None` = command could not run
  = never a false success — existing contract, refined in §4, not removed).
- Tests run per-directory (repo `.venv`), never touch the live board.
- Actuation remains sequential, one module at a time; `wait_state` observes
  real state via injected `observe`/`run`.
- `sudoers` exact-command argv for the panel path is **unchanged** (fix is
  entirely inside the ctl/engine and the web route; no new privileged argv).
- Commit trailer `Co-Authored-By: Gerald KERMA <devel@cybermind.fr>`, no Claude
  references.

---

## Design

### 1. Non-blocking commands; wait_state is the sole arbiter of the state transition

The command's return code confirms only the **fast, synchronous** operations;
the **slow state transition** is confirmed only by observation.

- **Native START:** `systemctl enable <unit>` (fast, rc-checked) +
  `systemctl start --no-block <unit>` (enqueue the job, returns immediately,
  rc = "job accepted"). Then `wait_state` polls until *active*.
- **Native STOP:** `systemctl disable <unit>` (fast, rc-checked) +
  `systemctl stop --no-block <unit>`. Then `wait_state` polls until *inactive*.
  - This replaces the single blocking `systemctl {enable,disable} --now <unit>`.
- **LXC START:** `lxc-start -n <name>` (best-effort; see below) + autostart file
  edit (fast) + host unit via the `--no-block` native START above. `wait_state`
  polls until *container running AND host unit active* (§2).
- **LXC STOP:** host unit via the `--no-block` native STOP (host unit down
  first, so `is_on` can't wedge — existing ordering rationale) + autostart file
  edit set to 0 (before stopping the container — watchdog-race rationale
  unchanged) + `lxc-stop -n <name>`. `wait_state` polls until *container
  stopped AND host unit inactive* (§2).

**`lxc-start` / `lxc-stop` have no `--no-block` flag.** They are issued with a
bounded subprocess timeout, and a **timeout is not treated as a failure**: the
verdict is deferred to `wait_state` (which observes `lxc-info -s`). Only a
genuine `OSError` (§4) or a non-zero rc (e.g. "no such container") is a hard
failure of the command itself.

**`_must` rc rule (unchanged in spirit):** a fast op returning non-zero, or any
command that could-not-run (`OSError` → `rc is None`), is still a hard failure.
What changes: the slow state-transition commands (`start`/`stop --no-block`,
`lxc-start`/`lxc-stop`) no longer *block* the actuator on the transition, and a
`TimeoutExpired` on the LXC ones is deferred, not raised.

### 2. wait_state observes the COMPLETE module state

`wait_state`'s convergence predicate becomes runtime-aware:

- **Native:** `is_on(observe(m)) == want_on` — unit enabled+active, as today.
- **LXC:** the predicate additionally requires the **container** to match:
  - `want_on == True`  → host unit active **AND** `lxc-info -s -n <name>` == RUNNING.
  - `want_on == False` → host unit inactive **AND** container STOPPED (not RUNNING).

This closes the zombie-container gap: with fire-and-forget `lxc-stop`, a
container that refuses to die would otherwise pass unnoticed because `is_on`
(host-unit-only) already reads False. The ctl runs as **root** (via
`systemd-run`), so `lxc-info` works (NNP that blocks the panel does not apply).

**No ripple to `is_on`:** `status` / `diff` keep the existing host-unit-only
`is_on` (changing it would flip module on/off meaning across the inventory and
planner). The richer predicate lives **only** in `wait_state`'s actuation-time
check — a new helper, e.g. `container_state(m, run)` / an `lxc_running(m, run)`
observation, consumed by `wait_state` when `m.runtime == "lxc"`.

`condition_failed(m, run)` (start-condition-gated native units) still
short-circuits a START ahead of `wait_state`, unchanged — it composes.

### 3. wait_timeout derived per-module from systemd

The flat `wait_timeout=30.0` is replaced by a value derived from the unit's own
systemd timeout, so `wait_state` waits at least as long as the unit itself may
legitimately take:

- For a START: read `TimeoutStartUSec`; for a STOP: read `TimeoutStopUSec`
  (via `systemctl show <unit> -p <prop> --value`, same mechanism
  `condition_failed` already uses).
- Effective timeout = `max(derived) + margin`, over the module's units, then
  **bounded by a safety cap** (e.g. 300s) so a unit configured
  `TimeoutStopSec=infinity` (systemd → `TimeoutStopUSec` = a huge/`infinity`
  sentinel) cannot block the apply indefinitely.
- A floor keeps fast units responsive (don't wait less than, say, the current
  poll-based minimum).
- LXC modules (no host-unit systemd stop timeout that bounds the *container*)
  use the same derivation for the host unit plus the safety cap for the
  container shutdown; the cap is the governing bound there.

Exact constants (margin, cap, floor) are fixed in the implementation plan; the
design commits to *derived-per-module, margin-added, safety-capped*.

### 4. `_run` distinguishes "still working" from "could not run"

`cli._run` currently collapses `OSError` and `subprocess.SubprocessError`
(which includes `TimeoutExpired`) into `(None, "")`. Split them:

- `OSError` (command not found, not executable, …) → **could not run** →
  keep the `None` sentinel (hard failure, existing contract).
- `subprocess.TimeoutExpired` → **ran, still working** → a **distinct** signal
  the actuator can defer on (for `lxc-start`/`lxc-stop`, per §1).

The `(int | None, str)` return shape is extended just enough to carry the third
outcome (e.g. a distinct sentinel value or a small result type). The refined
contract is documented in-place; `observe._run_cmd` and `_cmd_scan`'s existing
`rc is None` checks keep their meaning (they treat "could not run" as
indeterminate — a timeout there was never expected and remains an error path).

With §1's `--no-block` split, native commands return promptly, so `_run`'s base
timeout is no longer hit by a blocking stop; the timeout distinction is needed
principally for the LXC commands that cannot be made non-blocking.

### 5. `/apply` route reverts `active` on rollback

In `web.apply_active`, under the existing `_apply_lock`:

1. Capture the **prior** `active` value (or its absence) before overwriting.
2. Write `active = body.profile`, run the ctl.
3. If the ctl report `status == "rolled_back"`: restore the prior `active`
   (rewrite the prior value, or remove the file if there was none).
   On `status == "applied"`: keep `body.profile`.

The write stays atomic (`_atomic_write`), still under `_apply_lock` so no
concurrent `/active` or `/apply` can interleave. The route returns the ctl
report unchanged (the panel already classifies applied-vs-rolled_back).

---

## Components & files

| File | Change |
|------|--------|
| `api/actuate.py` | `--no-block` command split (native start/stop); LXC start/stop issue container commands with timeout-deferral; new container-state observation helper; `wait_state` runtime-aware predicate + derived timeout. |
| `api/observe.py` | Container-state read (`lxc-info -s`) helper for LXC modules (injected `run`), if not co-located in actuate. |
| `api/apply.py` | Pass the derived (not flat) `wait_timeout` through `_do_change` / `_rollback_applied`; consume the runtime-aware `wait_state`. `condition_failed` fast-path unchanged. |
| `api/cli.py` | `_run` splits `OSError` vs `TimeoutExpired`; base timeout revisited for the `--no-block` world. |
| `api/web.py` | `/apply` captures prior `active`, reverts it on `rolled_back`. |
| `debian/changelog` | Minor version bump. |
| `tests/test_actuate.py`, `tests/test_apply.py`, `tests/test_cli.py`, `tests/test_web.py` | New/updated coverage (below). |

## Testing

- **actuate:** native start/stop emit `enable`+`start --no-block` /
  `disable`+`stop --no-block` in the right order; LXC start/stop issue container
  commands and are not failed by a `TimeoutExpired` on `lxc-stop`; `wait_state`
  for an LXC module requires container-state (running for START, stopped for
  STOP) — a container that stays RUNNING on a STOP makes `wait_state` report
  not-reached; derived-timeout is read from mocked `systemctl show` and applied,
  capped at the safety bound.
- **apply:** a slow stop whose command "times out" but whose observed state
  reaches OFF within the derived timeout is a **success** (no rollback); a stop
  whose state never reaches OFF still fails and rolls back; `condition_failed`
  gated START still short-circuits.
- **cli `_run`:** `TimeoutExpired` → distinct sentinel; `OSError` → `None`; a
  clean run → `(rc, out)`.
- **web:** ctl `rolled_back` → `active` reverted to prior value; `applied` →
  `active` kept; no-prior-active + `rolled_back` → `active` file removed.

## Rollout

Source-first. Build the `.deb`, deploy to gk2, then **re-run the real `lite`
mass-apply test** through the panel path — it must now run to completion (or
fail only on a genuinely stuck module, verified by observation), then rollback
clean. Minor version bump; update module README / wiki if the actuation
contract note changes.

## Risks

- `systemctl start/stop --no-block` returns before the transition; a unit that
  fails *after* enqueue is caught by `wait_state` timing out (not by rc) — the
  derived timeout must be generous enough not to false-negative a healthy slow
  unit, and the safety cap must be low enough not to stall a mass apply on a
  genuinely stuck one. The margin/cap constants are the tuning surface.
- `lxc-info -s` output parsing must tolerate transient states
  (STARTING/STOPPING) — the predicate keys on RUNNING vs not-RUNNING, polling
  until the terminal state.
