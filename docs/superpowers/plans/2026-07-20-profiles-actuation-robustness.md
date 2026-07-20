<!--
SPDX-License-Identifier: LicenseRef-CMSD-1.0
Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
Source-Disclosed License — All rights reserved except as expressly granted.
See LICENCE-CMSD-1.0.md for terms.
-->

# Profiles Actuation Robustness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the *observed state* — not a command's return code — decide whether a module STOP/START reached its target, so a slow-but-successful transition can't spuriously fail a mass apply.

**Architecture:** State-transition commands become non-blocking (`systemctl {start,stop} --no-block`) or best-effort (`lxc-start`/`lxc-stop`, which have no `--no-block`); `wait_state` observing real state is the sole arbiter, and for LXC modules it now also checks the container (`lxc_running`, already produced by `observe()`). `wait_state`'s timeout is derived per-module from the unit's own systemd `TimeoutStop/StartUSec` (margin-added, safety-capped). `cli._run` gains a distinct "timed out" signal so the actuator can fast-fail only on genuine could-not-run.

**Tech Stack:** Python 3.11, pytest, systemd/LXC CLIs (injected `run`), FastAPI (web route), Debian packaging.

## Global Constraints

- Python 3.11; every module begins with `from __future__ import annotations` and the SPDX header block (4 lines, verbatim from existing files).
- mypy `--strict` clean; keep existing type annotations consistent.
- `run` stays dependency-injected; `rc is None` means "command could not run" (`OSError`) and is never a false success. A new distinct sentinel means "ran but did not return in time".
- Actuation stays sequential, one module at a time; no parallelism.
- `is_on(a)` (status/diff) semantics are unchanged — host-unit-only for LXC. The container check lives ONLY in `wait_state`'s actuation-time predicate.
- The panel `sudoers` exact-command argv is unchanged (no new privileged command).
- Tests run per-directory from `packages/secubox-profiles` (its `conftest.py` puts the package on `sys.path`); never touch the live board.
- Commit trailer: `Co-Authored-By: Gerald KERMA <devel@cybermind.fr>` — no Claude references.
- Reference commit form: `fix(profiles): <subject> (ref #893)` / `test(profiles): …` / `docs(profiles): …`.

---

## File Structure

| File | Responsibility after this plan |
|------|-------------------------------|
| `packages/secubox-profiles/api/cli.py` | `_run` distinguishes `TimeoutExpired` (→ `TIMED_OUT`) from `OSError` (→ `None`); base command timeout named + bumped. |
| `packages/secubox-profiles/api/actuate.py` | Owns `TIMED_OUT` sentinel; `_parse_systemd_timespan` + `derived_timeout`; `wait_state` runtime-aware predicate; non-blocking native command split; best-effort `_issue` for LXC container commands. |
| `packages/secubox-profiles/api/apply.py` | Computes the derived per-module timeout and passes it to `wait_state`; `wait_timeout` param reinterpreted as the safety cap. |
| `packages/secubox-profiles/api/web.py` | `/apply` captures prior `active` and reverts it when the ctl reports `rolled_back`. |
| `packages/secubox-profiles/debian/changelog` | Minor version bump. |
| `packages/secubox-profiles/README.md` | One-line note that actuation is observed-state-arbitrated with a per-module derived timeout. |
| Test files | `tests/test_cli.py`, `tests/test_actuate.py`, `tests/test_apply.py`, `tests/test_web.py`. |

---

## Task 1: `_run` distinguishes "timed out" from "could not run"

**Files:**
- Modify: `packages/secubox-profiles/api/actuate.py` (add `TIMED_OUT` sentinel + constant near the top, after the imports/`ActuationError`)
- Modify: `packages/secubox-profiles/api/cli.py:299-309` (`_run`) and the `_run` timeout constant
- Test: `packages/secubox-profiles/tests/test_cli.py`

**Interfaces:**
- Produces: `actuate.TIMED_OUT` — a sentinel returncode value (`int`, `1000`) meaning "the command ran but did not return within the deadline"; chosen outside real returncodes (exit codes are 0–255, signal codes are negative). `cli._run(argv) -> tuple[int | None, str]` returns `TIMED_OUT` on `subprocess.TimeoutExpired`, `None` on `OSError`.
- Consumes: nothing new.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_cli.py`:

```python
def test_run_distinguishes_timeout_from_could_not_run(monkeypatch):
    # cli._run must return the actuate.TIMED_OUT sentinel on a subprocess
    # timeout (the command RAN, still working) and None only on OSError
    # (the command could not run at all) — the actuator relies on this
    # distinction to fast-fail only on genuine could-not-run.
    import subprocess

    import api.cli as cli
    from api.actuate import TIMED_OUT

    def raise_timeout(*a, **k):
        raise subprocess.TimeoutExpired(cmd="x", timeout=1)
    monkeypatch.setattr(cli.subprocess, "run", raise_timeout)
    assert cli._run(["whatever"]) == (TIMED_OUT, "")

    def raise_oserror(*a, **k):
        raise OSError("no such binary")
    monkeypatch.setattr(cli.subprocess, "run", raise_oserror)
    assert cli._run(["whatever"]) == (None, "")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-profiles && python -m pytest tests/test_cli.py::test_run_distinguishes_timeout_from_could_not_run -v`
Expected: FAIL — `ImportError: cannot import name 'TIMED_OUT'` (and/or the timeout branch returns `(None, "")`).

- [ ] **Step 3: Add the sentinel in `actuate.py`**

In `api/actuate.py`, immediately after the `class ActuationError(...)` block (around line 33), add:

```python
# Sentinel returncode for a command that RAN but did not return within the
# deadline (subprocess.TimeoutExpired), as opposed to one that could not run at
# all (OSError -> rc is None). The actuator fast-fails only on the latter; a
# timeout on lxc-start/lxc-stop is deferred to wait_state (observed state
# decides). 1000 is outside every real returncode (exit codes 0-255, signal
# codes negative), so `rc != 0` still reads it as "not success".
TIMED_OUT = 1000
```

- [ ] **Step 4: Split the exception handling in `cli._run`**

In `api/cli.py`, add to the imports (near the top `from .diff import ...` group):

```python
from .actuate import TIMED_OUT
```

Replace `_run` (currently lines 299-309) with:

```python
_RUN_TIMEOUT_S = 30  # was 15: --no-block native commands return at once; the
# extra headroom is for lxc-start/lxc-stop (no --no-block flag) so the container
# CLI usually finishes before we give up and defer to wait_state.


def _run(argv: list[str]) -> tuple[int | None, str]:
    """rc=None = la commande n'a PAS pu s'exécuter (OSError) — jamais un faux
    succès. rc=TIMED_OUT = elle a bien démarré mais n'a pas répondu dans le
    délai (subprocess.TimeoutExpired) : pour lxc-start/lxc-stop (sans --no-block)
    ce n'est PAS un échec, c'est wait_state qui tranche sur l'état observé.
    Même contrat de lecture-seule côté observe._run_cmd (qui, lui, garde
    timeout->None : une sonde qui traîne reste indéterminée)."""
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=_RUN_TIMEOUT_S)
        return p.returncode, p.stdout
    except subprocess.TimeoutExpired:
        return TIMED_OUT, ""
    except OSError:
        return None, ""
```

Note: `subprocess.TimeoutExpired` is a subclass of `subprocess.SubprocessError`; catching it first, then `OSError`, preserves the old "couldn't run" path for `OSError` while splitting out the timeout.

- [ ] **Step 5: Run test to verify it passes**

Run: `cd packages/secubox-profiles && python -m pytest tests/test_cli.py::test_run_distinguishes_timeout_from_could_not_run -v`
Expected: PASS.

- [ ] **Step 6: Run the full cli + scan suite (regression — scan reads `rc != 0`)**

Run: `cd packages/secubox-profiles && python -m pytest tests/test_cli.py -v`
Expected: PASS — the scan tests treat `rc != 0` as failure and `TIMED_OUT` (=1000) is `!= 0`, so behaviour is unchanged; the OSError-path scan test (`test_scan_aborts_when_lxc_ls_did_not_execute`) still gets `None`.

- [ ] **Step 7: Commit**

```bash
git add packages/secubox-profiles/api/actuate.py packages/secubox-profiles/api/cli.py packages/secubox-profiles/tests/test_cli.py
git commit -m "fix(profiles): _run distinguishes TimeoutExpired from could-not-run (ref #893)

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

## Task 2: systemd timespan parser + per-module derived timeout

**Files:**
- Modify: `packages/secubox-profiles/api/actuate.py` (add `_parse_systemd_timespan` and `derived_timeout` near the bottom, after `condition_failed`)
- Test: `packages/secubox-profiles/tests/test_actuate.py`

**Interfaces:**
- Consumes: `Manifest` (`m.runtime`, `m.units`), injected `run`.
- Produces:
  - `_parse_systemd_timespan(text: str) -> float | None` — seconds, or `None` for `"infinity"`/unparseable.
  - `derived_timeout(m: Manifest, want_on: bool, run, *, floor: float = 10.0, margin: float = 15.0, cap: float = 300.0) -> float` — how long `wait_state` should wait for `m` to reach `want_on`. Native: `max` over units of `systemctl show <u> -p TimeoutStartUSec|TimeoutStopUSec --value`, `+ margin`, clamped to `[floor, cap]`; `infinity`/unreadable → `cap`. LXC: returns `cap` (container up/down has no systemd unit timeout; `wait_state` returns early on convergence).

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_actuate.py`:

```python
def test_parse_systemd_timespan_forms():
    from api.actuate import _parse_systemd_timespan
    assert _parse_systemd_timespan("90s") == 90.0
    assert _parse_systemd_timespan("1min 30s") == 90.0
    assert _parse_systemd_timespan("2min") == 120.0
    assert _parse_systemd_timespan("1h 30min") == 5400.0
    assert _parse_systemd_timespan("500ms") == 0.5
    assert _parse_systemd_timespan("infinity") is None
    assert _parse_systemd_timespan("") is None
    assert _parse_systemd_timespan("garbage") is None


def test_derived_timeout_native_uses_stop_timeout_plus_margin():
    from api.actuate import derived_timeout
    # STOP -> reads TimeoutStopUSec; 90s + 15s margin = 105, within [10, 300].
    def run(argv):
        if argv[:2] == ["systemctl", "show"] and "TimeoutStopUSec" in argv:
            return 0, "1min 30s\n"
        return 0, ""
    assert derived_timeout(_m("metrics"), False, run, margin=15.0) == 105.0


def test_derived_timeout_native_start_reads_start_timeout():
    from api.actuate import derived_timeout
    seen = {}
    def run(argv):
        if argv[:2] == ["systemctl", "show"]:
            seen["prop"] = argv[argv.index("-p") + 1]
            return 0, "5s\n"
        return 0, ""
    derived_timeout(_m("x"), True, run)          # START
    assert seen["prop"] == "TimeoutStartUSec"


def test_derived_timeout_infinity_and_unreadable_use_cap():
    from api.actuate import derived_timeout
    assert derived_timeout(_m("x"), False, lambda a: (0, "infinity\n"), cap=300.0) == 300.0
    assert derived_timeout(_m("x"), False, lambda a: (1, ""), cap=300.0) == 300.0   # show failed
    assert derived_timeout(_m("x"), False, lambda a: (None, ""), cap=300.0) == 300.0  # couldn't run


def test_derived_timeout_lxc_returns_cap():
    from api.actuate import derived_timeout
    called = []
    m = _m("l", runtime="lxc", lxc="l")
    assert derived_timeout(m, False, lambda a: (called.append(a), (0, "9s"))[1], cap=250.0) == 250.0
    assert not called   # short-circuits: no systemctl show for an LXC module


def test_derived_timeout_clamps_to_floor_and_cap():
    from api.actuate import derived_timeout
    # tiny unit timeout -> floor wins; huge -> cap wins.
    assert derived_timeout(_m("x"), False, lambda a: (0, "1s"), floor=10.0, margin=0.0) == 10.0
    assert derived_timeout(_m("x"), False, lambda a: (0, "10min"), cap=120.0, margin=0.0) == 120.0
```

- [ ] **Step 2: Run to verify they fail**

Run: `cd packages/secubox-profiles && python -m pytest tests/test_actuate.py -k "timespan or derived_timeout" -v`
Expected: FAIL — `ImportError: cannot import name '_parse_systemd_timespan'`.

- [ ] **Step 3: Implement the parser and derivation**

Add to `api/actuate.py` after `condition_failed` (end of file). Add `import re` to the imports at the top if not already present (it is not — add it):

```python
_TS_UNITS = {"us": 1e-6, "ms": 1e-3, "s": 1.0, "min": 60.0, "h": 3600.0, "d": 86400.0}
# Longest-first alternation so "min"/"ms"/"us" win over "s" at the same position.
_TS_TOKEN = re.compile(r"(\d+)\s*(us|ms|min|h|d|s)")


def _parse_systemd_timespan(text: str) -> float | None:
    """Convertit un timespan systemd (« 1min 30s », « 90s », « 500ms ») en
    secondes. « infinity » ou une chaîne non-parsable -> None (l'appelant
    retombe sur le plafond de sûreté). `systemctl show -p TimeoutStopUSec
    --value` imprime la forme humaine, pas des microsecondes brutes — d'où ce
    parseur (vérifié sur la board : « 1min 30s »)."""
    t = text.strip().lower()
    if not t or t == "infinity":
        return None
    total = 0.0
    matched = False
    for m in _TS_TOKEN.finditer(t):
        total += int(m.group(1)) * _TS_UNITS[m.group(2)]
        matched = True
    return total if matched else None


def derived_timeout(m: Manifest, want_on: bool, run, *, floor: float = 10.0,
                    margin: float = 15.0, cap: float = 300.0) -> float:
    """Combien de temps wait_state doit patienter pour que `m` atteigne
    `want_on`. Natif : dérivé du propre TimeoutStart/StopUSec de l'unité (+
    marge), borné [floor, cap] ; « infinity »/illisible -> cap. LXC : cap (la
    montée/descente d'un conteneur n'a pas de timeout d'unité systemd ;
    wait_state rend la main dès convergence, le cap n'est qu'un plafond)."""
    if m.runtime == "lxc":
        return cap
    prop = "TimeoutStartUSec" if want_on else "TimeoutStopUSec"
    best = 0.0
    seen = False
    for u in m.units:
        rc, out = run(["systemctl", "show", u, "-p", prop, "--value"])
        if rc != 0:
            return cap          # unreadable -> be safe, wait the cap
        parsed = _parse_systemd_timespan(out)
        if parsed is None:
            return cap          # infinity/unparseable -> cap
        best = max(best, parsed)
        seen = True
    if not seen:
        return cap              # no units at all -> cap
    return min(cap, max(floor, best + margin))
```

- [ ] **Step 4: Run to verify they pass**

Run: `cd packages/secubox-profiles && python -m pytest tests/test_actuate.py -k "timespan or derived_timeout" -v`
Expected: PASS (all 6).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-profiles/api/actuate.py packages/secubox-profiles/tests/test_actuate.py
git commit -m "fix(profiles): derive wait_state timeout per-module from systemd (ref #893)

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

## Task 3: `wait_state` observes the complete state (container check for LXC)

**Files:**
- Modify: `packages/secubox-profiles/api/actuate.py` (`wait_state`, currently lines 182-192)
- Test: `packages/secubox-profiles/tests/test_actuate.py`

**Interfaces:**
- Consumes: `observe(m) -> Actual` (already returns `lxc_running`), `is_on`, `Manifest`.
- Produces: `wait_state(m, want_on, *, observe=_observe, sleep=time.sleep, now=time.monotonic, timeout=30.0, poll=1.0) -> bool` — signature unchanged; the predicate now also requires `observe(m).lxc_running == want_on` when `m.runtime == "lxc"`.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_actuate.py`:

```python
def test_wait_state_lxc_requires_container_state_for_start():
    # Host unit is up (is_on True) but the container is NOT running yet →
    # a START must NOT be considered reached until lxc_running is True too.
    from api.actuate import wait_state
    from api.observe import Actual
    m = _m("l", runtime="lxc", lxc="l", units=("secubox-l.service",))
    seq = iter([
        Actual(enabled=True, active=True, lxc_running=False),  # unit up, container not yet
        Actual(enabled=True, active=True, lxc_running=True),   # now fully up
    ])
    ok = wait_state(m, True, observe=lambda mm: next(seq),
                    sleep=lambda s: None, now=iter([0, 1, 2]).__next__,
                    timeout=30, poll=1)
    assert ok is True


def test_wait_state_lxc_stop_not_reached_while_container_runs():
    # Host unit is down (is_on False) but the container refuses to die
    # (lxc_running stays True) → a STOP must report NOT reached (zombie guard).
    from api.actuate import wait_state
    from api.observe import Actual
    m = _m("l", runtime="lxc", lxc="l", units=("secubox-l.service",))
    ok = wait_state(m, False, observe=lambda mm: Actual(enabled=False, active=False,
                                                        lxc_running=True),
                    sleep=lambda s: None, now=iter([0, 10, 20, 31]).__next__,
                    timeout=30, poll=10)
    assert ok is False


def test_wait_state_native_unaffected_by_container_predicate():
    # A native module has lxc_running=None; the container clause must not apply.
    from api.actuate import wait_state
    from api.observe import Actual
    ok = wait_state(_m("x"), True, observe=lambda mm: Actual(enabled=True, active=True),
                    sleep=lambda s: None, now=iter([0, 1]).__next__, timeout=30, poll=1)
    assert ok is True
```

- [ ] **Step 2: Run to verify they fail**

Run: `cd packages/secubox-profiles && python -m pytest tests/test_actuate.py -k wait_state_lxc -v`
Expected: FAIL — the STOP test returns `True` (current `wait_state` ignores `lxc_running`, so host-unit-down alone reads as reached).

- [ ] **Step 3: Make the predicate runtime-aware**

Replace `wait_state` (currently lines 182-192) with:

```python
def wait_state(m: Manifest, want_on: bool, *, observe=_observe,
               sleep=time.sleep, now=time.monotonic,
               timeout: float = 30.0, poll: float = 1.0) -> bool:
    """Sonde observe(m) jusqu'à ce que l'ÉTAT OBSERVÉ corresponde à want_on, ou
    expiration. C'est le SEUL arbitre du succès d'un start/stop (le code retour
    de la commande ne l'est pas). Pour un module LXC, l'état complet inclut le
    conteneur (lxc_running), pas seulement l'unité hôte : sinon un conteneur qui
    refuse de mourir passerait inaperçu (is_on ne regarde que l'unité hôte).
    Injectable."""
    start = now()
    while True:
        a = observe(m)
        reached = is_on(a) == want_on
        if m.runtime == "lxc" and m.lxc:
            reached = reached and (a.lxc_running == want_on)
        if reached:
            return True
        if now() - start >= timeout:
            return False
        sleep(poll)
```

- [ ] **Step 4: Run to verify they pass**

Run: `cd packages/secubox-profiles && python -m pytest tests/test_actuate.py -k "wait_state" -v`
Expected: PASS — new LXC tests pass and the pre-existing `test_wait_state_converges` / `test_wait_state_times_out` (native) still pass.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-profiles/api/actuate.py packages/secubox-profiles/tests/test_actuate.py
git commit -m "fix(profiles): wait_state observes container state for LXC modules (ref #893)

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

## Task 4: non-blocking native commands + best-effort LXC container commands

**Files:**
- Modify: `packages/secubox-profiles/api/actuate.py` (`actuate`, the `runtime_start`/`runtime_stop` closures, lines 137-167; add `_issue`)
- Test: `packages/secubox-profiles/tests/test_actuate.py`

**Interfaces:**
- Consumes: `TIMED_OUT` (Task 1), `_must` (unchanged), injected `run`.
- Produces: `_issue(run, argv: list[str]) -> None` — best-effort issue of a container command whose success is judged by `wait_state`; raises `ActuationError` ONLY when `rc is None` (could not run). A non-zero rc ("container already stopped/started") or `TIMED_OUT` (still working) is swallowed and deferred. `actuate`'s emitted argv change: native `enable`+`start --no-block` / `disable`+`stop --no-block`; LXC container via `_issue`; the ordered `done` labels are unchanged.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_actuate.py`:

```python
def test_native_start_enables_then_starts_no_block():
    calls = []
    actuate(Change("x", START, "", 50), _m("x"), run=_ok_run(calls))
    assert ["systemctl", "enable", "u.service"] in calls
    assert ["systemctl", "start", "--no-block", "u.service"] in calls
    # enable (symlink) before start (transition)
    assert calls.index(["systemctl", "enable", "u.service"]) < \
           calls.index(["systemctl", "start", "--no-block", "u.service"])


def test_native_stop_disables_then_stops_no_block():
    calls = []
    actuate(Change("x", STOP, "", 50), _m("x"), run=_ok_run(calls))
    assert ["systemctl", "disable", "u.service"] in calls
    assert ["systemctl", "stop", "--no-block", "u.service"] in calls


def test_issue_raises_only_on_could_not_run():
    from api.actuate import _issue, ActuationError, TIMED_OUT
    _issue(lambda a: (0, ""), ["lxc-stop", "-n", "c"])          # ok
    _issue(lambda a: (1, "already stopped"), ["lxc-stop", "-n", "c"])  # non-zero deferred
    _issue(lambda a: (TIMED_OUT, ""), ["lxc-stop", "-n", "c"])  # timeout deferred
    with pytest.raises(ActuationError):
        _issue(lambda a: (None, ""), ["lxc-stop", "-n", "c"])   # could-not-run fails
```

Also UPDATE the two existing native-command tests and the two LXC-command tests to the new argv (they assert the old `--now` forms):

- In `test_lxc_stop_stops_and_clears_autostart`: replace
  `assert ["systemctl", "disable", "--now", "secubox-lyrion.service"] in calls`
  with
  ```python
  assert ["systemctl", "disable", "secubox-lyrion.service"] in calls
  assert ["systemctl", "stop", "--no-block", "secubox-lyrion.service"] in calls
  ```
- In `test_lxc_start_starts_container_then_host_unit`: replace
  `assert ["systemctl", "enable", "--now", "secubox-lyrion.service"] in calls`
  with
  ```python
  assert ["systemctl", "enable", "secubox-lyrion.service"] in calls
  assert ["systemctl", "start", "--no-block", "secubox-lyrion.service"] in calls
  ```
- Delete the now-superseded `test_native_start_enables_now` and `test_native_stop_disables_now` (their `--now` assertions are replaced by the two new tests above). The order assertions in the LXC tests (`order.index("lxc:autostart:0") < order.index("lxc:stop")`, `order.index("lxc:start") < order.index("systemd:enable")`) stay — the `done` labels are unchanged.

Also realign the argv literals in `tests/test_apply.py` (this task changes the emitted argv, so its downstream consumer's assertions move with it — keeping the whole suite green after this task). These tests use `run=_run_ok(calls)` and pass `wait_timeout=0`, so timing is unchanged; only the command literals change:
- `test_failure_at_module_k_rolls_back_prior`:
  `["systemctl", "enable", "--now", "a.service"]` → `["systemctl", "enable", "a.service"]`
- `test_rollback_never_stops_a_protected_module`:
  `["systemctl", "disable", "--now", "auth.service"] not in calls` → `["systemctl", "disable", "auth.service"] not in calls`
  and `["systemctl", "enable", "--now", "auth.service"]` → `["systemctl", "enable", "auth.service"]`
- `test_rollback_timeout_not_counted_as_success`:
  `["systemctl", "enable", "--now", "a.service"]` → `["systemctl", "enable", "a.service"]`
- `test_rollback_to_restores_snapshot_state`:
  `["systemctl", "enable", "--now", "a.service"]` → `["systemctl", "enable", "a.service"]`

- [ ] **Step 2: Run to verify they fail**

Run: `cd packages/secubox-profiles && python -m pytest tests/test_actuate.py -k "no_block or _issue" -v`
Expected: FAIL — `cannot import name '_issue'`; native tests fail on the missing `--no-block` argv.

- [ ] **Step 3: Add `_issue` and rewrite the command closures**

In `api/actuate.py`, add `_issue` just after `_must` (around line 39):

```python
def _issue(run, argv: list[str]) -> None:
    """Émet une commande de transition d'état en best-effort : son succès est
    jugé par wait_state (état observé), PAS par son code retour. Seul un
    « n'a pas pu s'exécuter » (rc is None = OSError) est un échec dur. Un rc
    non-nul (« conteneur déjà arrêté/démarré ») ou TIMED_OUT (encore en cours /
    tué à mi-course) est délégué à wait_state. Utilisé pour lxc-start/lxc-stop,
    qui n'ont pas de --no-block."""
    rc, _ = run(argv)
    if rc is None:
        raise ActuationError(f"{' '.join(argv)} → n'a pas pu s'exécuter")
```

Replace `runtime_start` and `runtime_stop` (lines 137-167) with:

```python
    def runtime_start():
        if m.runtime == "lxc" and m.lxc:
            # Conteneur et unité hôte DÉCOUPLÉS : on démarre le conteneur
            # (best-effort, wait_state confirme lxc_running), puis l'API hôte.
            _issue(run, ["lxc-start", "-n", m.lxc]); done.append("lxc:start")
            _lxc_autostart(m.lxc, True, run, lxc_root); done.append("lxc:autostart:1")
            for u in m.units:
                _must(run, ["systemctl", "enable", u])
                _must(run, ["systemctl", "start", "--no-block", u])
            done.append("systemd:enable")
        else:
            for u in m.units:
                _must(run, ["systemctl", "enable", u])
                _must(run, ["systemctl", "start", "--no-block", u])
            done.append("systemd:enable")

    def runtime_stop():
        if m.runtime == "lxc" and m.lxc:
            # On éteint l'API hôte d'abord (sinon is_on reste True alors que le
            # conteneur qu'elle sert va mourir). enable/disable = opérations
            # synchrones rapides (rc vérifié) ; start/stop = --no-block, l'état
            # est confirmé par wait_state.
            for u in m.units:
                _must(run, ["systemctl", "disable", u])
                _must(run, ["systemctl", "stop", "--no-block", u])
            done.append("systemd:disable")
            # autostart=0 AVANT lxc-stop : sinon secubox-watchdog relance le
            # conteneur (course observée sur la board).
            _lxc_autostart(m.lxc, False, run, lxc_root); done.append("lxc:autostart:0")
            _issue(run, ["lxc-stop", "-n", m.lxc]); done.append("lxc:stop")
        else:
            for u in m.units:
                _must(run, ["systemctl", "disable", u])
                _must(run, ["systemctl", "stop", "--no-block", u])
            done.append("systemd:disable")
```

- [ ] **Step 4: Run to verify they pass**

Run: `cd packages/secubox-profiles && python -m pytest tests/test_actuate.py -v`
Expected: PASS — the whole actuate suite, including the updated LXC/native command tests and the `_issue` test.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-profiles/api/actuate.py packages/secubox-profiles/tests/test_actuate.py
git commit -m "fix(profiles): non-blocking systemctl + best-effort lxc, state-arbitrated (ref #893)

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

## Task 5: apply wires the derived timeout (cap = wait_timeout)

**Files:**
- Modify: `packages/secubox-profiles/api/apply.py` (`_do_change` lines 41-52, `apply_plan` line 55-57 default, `_rollback_applied` lines 96-133)
- Test: `packages/secubox-profiles/tests/test_apply.py`

**Interfaces:**
- Consumes: `derived_timeout` (Task 2), `wait_state` (Task 3), `condition_failed` (unchanged).
- Produces: `apply_plan(..., wait_timeout=300.0, ...)` — `wait_timeout` is now the **safety cap** passed to `derived_timeout(..., cap=wait_timeout)`; the actual per-module wait is derived. `_do_change` / `_rollback_applied` compute the derived timeout internally.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_apply.py`:

```python
def test_slow_stop_that_reaches_state_within_derived_timeout_is_success(tmp_path):
    # metrics-like: its stop command "times out" (systemd TimeoutStopSec long),
    # but the observed state reaches OFF within the derived timeout -> success,
    # NO rollback. The command rc is irrelevant; wait_state arbitrates.
    from api.observe import Actual
    calls = []

    def run(argv):
        calls.append(argv)
        # derived_timeout asks for TimeoutStopUSec -> report a generous 90s so
        # the (single, immediate) observation below is well inside the window.
        if argv[:2] == ["systemctl", "show"] and "TimeoutStopUSec" in argv:
            return 0, "1min 30s\n"
        return 0, ""

    manifests = {"metrics": _m("metrics")}
    plan = [Change("metrics", STOP, "", 50)]
    rep = apply_plan(plan, manifests, {"metrics": Actual(enabled=True, active=True)},
                     run=run, observe=lambda m: Actual(enabled=False, active=False),
                     now="t", routes={}, snap_root=tmp_path,
                     audit_path=tmp_path / "audit.log", apply=True)
    assert rep.status == "applied"
    assert rep.changed == ["metrics"] and rep.failed == []
```

Then UPDATE the existing command-form assertions in `tests/test_apply.py` (the actuation argv changed in Task 4 — `enable --now` → `enable`):
- `test_failure_at_module_k_rolls_back_prior` line 93:
  `assert ["systemctl", "enable", "--now", "a.service"] in calls`
  → `assert ["systemctl", "enable", "a.service"] in calls`
- `test_rollback_never_stops_a_protected_module` line 122 and 125:
  `assert ["systemctl", "disable", "--now", "auth.service"] not in calls`
  → `assert ["systemctl", "disable", "auth.service"] not in calls`
  and line 125
  `assert ["systemctl", "enable", "--now", "auth.service"] in calls`
  → `assert ["systemctl", "enable", "auth.service"] in calls`
- `test_rollback_timeout_not_counted_as_success` line 154:
  `assert ["systemctl", "enable", "--now", "a.service"] in calls`
  → `assert ["systemctl", "enable", "a.service"] in calls`
- `test_rollback_to_restores_snapshot_state` lines 169 and 154-equivalent:
  `assert ["systemctl", "enable", "--now", "a.service"] in calls`
  → `assert ["systemctl", "enable", "a.service"] in calls`

These tests all use `run=_run_ok(calls)` (returns `(0, "")` for everything, including the `systemctl show` derived-timeout probe → parses `""` → `None` → `derived_timeout` returns the cap = the test's `wait_timeout`). They pass `wait_timeout=0`, so the cap is `0` and `wait_state` times out immediately exactly as before — timing behaviour is preserved.

- [ ] **Step 2: Run to verify (new fails, updated ones may already fail on argv)**

Run: `cd packages/secubox-profiles && python -m pytest tests/test_apply.py -v`
Expected: `test_slow_stop_that_reaches_state_within_derived_timeout_is_success` FAILs (derived timeout not wired — with `wait_timeout` default 30 and `run` returning a real 90s show, current code ignores it; actually current code passes a flat 30 and `run_ok`-style returns nothing meaningful) and the argv-updated tests FAIL until apply emits the new argv (already true after Task 4, so those may already pass — the update just realigns literals).

- [ ] **Step 3: Wire `derived_timeout` into apply.py**

In `api/apply.py`, update the import line 20 to add `derived_timeout`:

```python
from .actuate import ActuationError, actuate, condition_failed, derived_timeout, wait_state
```

Replace `_do_change` (lines 41-52) with:

```python
def _do_change(c: Change, m: Manifest, *, run, observe, routes_value, sleep, now,
               wait_timeout) -> None:
    actuate(c, m, run=run, route_value=routes_value)
    # Un START d'une unité condition-gated ne deviendra jamais active (enable a
    # réussi, systemd la laisse inactive par design) : pas un échec, on n'attend
    # pas (ça timeout inutilement).
    if c.action == START and condition_failed(m, run):
        return
    want = _want_on(c.action)
    # L'ÉTAT OBSERVÉ tranche, pas le code retour de la commande. Le délai est
    # dérivé du propre timeout systemd du module (wait_timeout = plafond de
    # sûreté), pas un plat 30s trop court pour une unité au TimeoutStopSec long.
    timeout = derived_timeout(m, want, run, cap=wait_timeout)
    if not wait_state(m, want, observe=observe, sleep=sleep, now=now, timeout=timeout):
        raise ActuationError(f"{c.id}: état non atteint (timeout)")
```

In `apply_plan` (line 55-57), change the default `wait_timeout=30` to `wait_timeout=300.0`:

```python
def apply_plan(plan, manifests, actuals, *, run, observe, now, routes,
               snap_root, audit_path, apply=False, wait_timeout=300.0,
               sleep=None, clock=None) -> ApplyReport:
```

In `_rollback_applied` (lines 116-129), replace the `reached = ...` block so the wait also uses the derived timeout:

```python
        try:
            actuate(rev, m, run=run, route_value=rv)
            # Même règle que le forward : re-démarrer une unité condition-gated
            # ne la rend jamais active — succès, pas timeout. Sinon l'état
            # observé tranche, avec le même délai dérivé (cap = wait_timeout).
            timeout = derived_timeout(m, want_on, run, cap=wait_timeout)
            reached = (rev.action == START and condition_failed(m, run)) or \
                wait_state(m, want_on, observe=observe, sleep=sleep, now=clock,
                           timeout=timeout)
```

(The rest of `_rollback_applied` — the audit records and the `except` — is unchanged.)

- [ ] **Step 4: Run to verify they pass**

Run: `cd packages/secubox-profiles && python -m pytest tests/test_apply.py -v`
Expected: PASS — the new slow-stop success test passes; all pre-existing rollback/order/protected/condition-gated tests still pass (their `wait_timeout=0` caps the derived timeout to 0).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-profiles/api/apply.py packages/secubox-profiles/tests/test_apply.py
git commit -m "fix(profiles): apply waits the per-module derived timeout, observed-state arbiter (ref #893)

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

## Task 6: `/apply` route reverts `active` on rollback

**Files:**
- Modify: `packages/secubox-profiles/api/web.py` (`apply_active`, lines 481-496)
- Test: `packages/secubox-profiles/tests/test_web.py`

**Interfaces:**
- Consumes: `_run_ctl_json("apply") -> dict` (returns the ctl report with a `status` key), `_atomic_write`, `_apply_lock`.
- Produces: `POST /api/v1/profiles/apply` — on report `status == "rolled_back"`, `active` is restored to its pre-apply value (or the file removed if there was none); on `applied`, `active` stays `body.profile`.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_web.py` (next to `test_apply_rolled_back_returns_report_not_500`):

```python
def test_apply_rolled_back_reverts_active_to_prior(client, root, monkeypatch):
    # A rolled_back apply must leave `active` pointing at the PRIOR profile
    # (state was reverted), not at the target that never took — otherwise the
    # pointer lies. Fixture default active="media"; we apply "lite" -> rolled_back.
    (root / "profiles" / "lite.toml").write_text('name="lite"\nlabel="Lite"\non=["lyrion"]\n')
    assert (root / "profiles" / "active").read_text().strip() == "media"

    def fake_run(argv, **kw):
        class P:
            returncode = 2
            stdout = '{"status":"rolled_back","changed":[],"failed":["x"],"rolled_back":["y"]}'
            stderr = ""
        return P()
    monkeypatch.setattr(web, "_ctl_run", fake_run)

    r = client.post("/api/v1/profiles/apply", json={"profile": "lite"})
    assert r.status_code == 200
    assert r.json()["status"] == "rolled_back"
    assert (root / "profiles" / "active").read_text().strip() == "media"  # reverted


def test_apply_applied_keeps_active_at_target(client, root, monkeypatch):
    (root / "profiles" / "lite.toml").write_text('name="lite"\nlabel="Lite"\non=["lyrion"]\n')

    def fake_run(argv, **kw):
        class P:
            returncode = 0
            stdout = '{"status":"applied","changed":["lyrion"],"failed":[],"rolled_back":[]}'
            stderr = ""
        return P()
    monkeypatch.setattr(web, "_ctl_run", fake_run)

    r = client.post("/api/v1/profiles/apply", json={"profile": "lite"})
    assert r.status_code == 200
    assert (root / "profiles" / "active").read_text().strip() == "lite"  # kept
```

- [ ] **Step 2: Run to verify they fail**

Run: `cd packages/secubox-profiles && python -m pytest tests/test_web.py -k "reverts_active or keeps_active" -v`
Expected: FAIL — `test_apply_rolled_back_reverts_active_to_prior` sees `active` == "lite" (never reverted).

- [ ] **Step 3: Revert `active` on rollback in the route**

Replace `apply_active` (lines 481-496) with:

```python
    @app.post("/api/v1/profiles/apply")
    async def apply_active(body: ApplyRequest, _claims=Depends(require_jwt)):
        # Actue TOUJOURS le profil demandé par CET appel : on réécrit `active`
        # avec body.profile puis on lance le CLI, sous le même verrou. Si le CLI
        # se replie (rolled_back), l'état système est revenu au profil PRÉCÉDENT
        # — `active` doit donc repointer dessus, sinon le pointeur ment (il
        # nommerait un profil qui n'a jamais pris). L'argv sudo reste FIXE.
        root = _root()
        _mod, prof_dir, _pins, active_file = _cli._paths(root)
        active_path = Path(active_file)
        async with _apply_lock:
            if not (Path(prof_dir) / f"{body.profile}.toml").exists():
                raise HTTPException(status_code=404, detail=f"profil inconnu: {body.profile}")
            prior = active_path.read_text(encoding="utf-8") if active_path.exists() else None
            _atomic_write(active_path, body.profile + "\n")
            report = await _run_ctl_json("apply")
            if isinstance(report, dict) and report.get("status") == "rolled_back":
                if prior is None:
                    active_path.unlink(missing_ok=True)
                else:
                    _atomic_write(active_path, prior)
            return report
```

- [ ] **Step 4: Run to verify they pass**

Run: `cd packages/secubox-profiles && python -m pytest tests/test_web.py -v`
Expected: PASS — both new tests plus every existing web test (including `test_apply_rolled_back_returns_report_not_500`, `test_apply_writes_requested_profile_before_calling_ctl`, `test_apply_unknown_profile_404_and_ctl_not_called`).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-profiles/api/web.py packages/secubox-profiles/tests/test_web.py
git commit -m "fix(profiles): /apply reverts active pointer when the ctl rolls back (ref #893)

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

## Task 7: version bump + README note + full suite

**Files:**
- Modify: `packages/secubox-profiles/debian/changelog`
- Modify: `packages/secubox-profiles/README.md`

**Interfaces:** none (packaging + docs).

- [ ] **Step 1: Read the current changelog head to match format**

Run: `head -8 packages/secubox-profiles/debian/changelog`
Expected: shows the top stanza, e.g. `secubox-profiles (0.6.2-1~bookworm1) bookworm; urgency=medium` — note the exact current version.

- [ ] **Step 2: Add a new changelog stanza**

Prepend a new stanza bumping the minor version (e.g. `0.6.2` → `0.7.0`). Use `date -R` for the timestamp. Example (adjust version to be exactly one minor above the current top stanza):

```
secubox-profiles (0.7.0-1~bookworm1) bookworm; urgency=medium

  * apply: observed state (not command return code) arbitrates STOP/START —
    non-blocking systemctl (--no-block) + best-effort lxc, wait_state is the
    sole arbiter and now checks the container (lxc-info) for LXC modules.
  * apply: wait_state timeout is derived per-module from systemd
    TimeoutStop/StartUSec (margin-added, safety-capped), replacing the flat 30s.
  * _run distinguishes a command timeout (still working, deferred) from a
    could-not-run (hard fail).
  * web: /apply reverts the `active` pointer when the ctl rolls back.
  * Fixes the spurious mass-apply rollback (ref #893).

 -- Gerald KERMA <devel@cybermind.fr>  <output of `date -R`>
```

- [ ] **Step 3: Add a README note**

In `packages/secubox-profiles/README.md`, under the apply/actuation section (search for "apply" or "Phase 3"), add one line:

```
Actuation is **observed-state-arbitrated**: a STOP/START succeeds only when the
module's real state (systemd unit, and the container for LXC) reaches the target
within a timeout derived from the unit's own systemd `TimeoutStop/StartUSec` — a
slow-but-successful transition is never mistaken for a failure.
```

- [ ] **Step 4: Run the FULL module test suite + mypy**

Run:
```bash
cd packages/secubox-profiles && python -m pytest tests/ -q && python -m mypy --strict api/
```
Expected: all tests PASS; mypy reports no errors (matches the module's existing clean baseline).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-profiles/debian/changelog packages/secubox-profiles/README.md
git commit -m "docs(profiles): changelog 0.7.0 + README actuation note (ref #893)

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

## Post-implementation (controller, after final review)

Not tasks for the implementer — the controller runs these after the whole-branch review passes:

1. Build the `.deb` (arch:all): `cd packages/secubox-profiles && dpkg-buildpackage -a arm64 --host-arch arm64 -us -uc -b` (or the repo's build-packages path).
2. Deploy to gk2, `systemctl restart secubox-profiles` + `systemctl restart secubox-aggregator` if route code changed (web.py changed → restart the profiles service, which runs on its own socket, not the aggregator).
3. **Re-run the real `lite` mass-apply** through the panel path (secubox → sudo → systemd-run → profilectl). Expected: it now runs to completion (65 stops) — or fails ONLY on a genuinely stuck module, verified by observation — then rollback restores cleanly. Monitor `/var/log/secubox/audit.log` live; confirm gateway stays 200 and the board returns to its pre-test ON set.

---

## Self-Review

**Spec coverage:**
- §1 (non-blocking + wait_state arbiter) → Task 4 (commands) + Task 3 (arbiter). ✅
- §2 (complete state, LXC container) → Task 3 (uses existing `observe().lxc_running`; no new helper needed — refinement noted). ✅
- §3 (derived timeout) → Task 2 (parser + `derived_timeout`) + Task 5 (wired). ✅
- §4 (`_run` distinguishes timeout) → Task 1. ✅
- §5 (`/apply` reverts active) → Task 6. ✅
- Testing section (actuate/apply/cli/web) → covered across Tasks 1-6. ✅
- Rollout (version bump, README, board re-test) → Task 7 + Post-implementation. ✅

**Placeholder scan:** no TBD/TODO; every code step shows full code; constants (floor=10, margin=15, cap=300, `TIMED_OUT=1000`, `_RUN_TIMEOUT_S=30`) are concrete.

**Type consistency:** `derived_timeout(m, want_on, run, *, floor, margin, cap)` is defined in Task 2 and called with `cap=wait_timeout` in Task 5 — matching. `_issue(run, argv)` defined and used in Task 4. `TIMED_OUT` defined in Task 1 (actuate), imported in cli (Task 1) and referenced in Task 4's `_issue` test. `wait_state` signature unchanged across Tasks 3/5. `apply_plan(wait_timeout=300.0)` default set in Task 5; existing callers passing `wait_timeout=0` still valid.

One cross-task note for the executor: Task 4 changes the emitted argv (`enable --now` → `enable` + `start --no-block`), and Task 5 realigns `test_apply.py`'s literal assertions to match. If Tasks are done in order, `test_apply.py`'s argv assertions transiently break after Task 4 and are fixed in Task 5 Step 1 — run `test_apply.py` green only at Task 5's end, not between Task 4 and Task 5. The controller should not treat that interim red as a Task 4 regression.
