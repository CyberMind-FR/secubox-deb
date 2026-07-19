# Profils Phase 3a — Actionneur `apply` — Plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Execute the change plan `diff.plan_changes()` already produces — systemd/LXC/portal actuators, state-wait, 4R snapshot, rollback-on-failure + a rollback command, audit, and a root-only `apply`/`rollback` CLI (dry-run default, `--yes`, `--only`). Validated on `lyrion` alone.

**Architecture:** Pure actuators (`run` injected) + a snapshot that captures each planned module's pre-state (including the portal route entry) so rollback can restore it + an orchestrator that snapshots, then acts one module at a time (stops before starts), waits for state, audits, and rolls back on any failure.

**Tech Stack:** Python 3.11 stdlib (`json`, `os`, `tempfile`, `time`, `subprocess`) + the existing `secubox-profiles` Phase-1 modules.

## Global Constraints

- Package `packages/secubox-profiles`, module `api/`. SPDX 4-line header on every new `.py`. Copyright `Gérald Kerma <devel@cybermind.fr>`.
- Reuse, never reimplement: `diff.Change(id, action, reason, priority)`, `diff.START`/`diff.STOP`, `diff.plan_changes`, `diff.ProtectedViolation`; `observe.observe(m, *, run, routes)`, `observe.is_on`, `observe.load_routes`, `observe.ROUTES_FILE`; `manifest.Manifest` (fields `id, category, runtime, exposure, units:tuple, lxc, portal_domain, priority, protected, needs`), `manifest.load_all`; `state.resolve`; `cli._paths`, `cli._load_profile_or_none`.
- `run` contract (copied from `observe._run_cmd`/`cli._run`): returns `(rc, stdout)` where `rc is None` means the command could NOT run — a `None`/non-zero rc is a FAILED actuation, never a fabricated success.
- **Read-only Phase 1 code is untouched.** All writes live in the new modules.
- Ordering is a SAFETY invariant, already enforced by `plan_changes` (stops by ascending priority, then starts by descending). The orchestrator MUST execute the plan in the given order, one module at a time, never in parallel.
- **Never stop a protected module.** `plan_changes` refuses a protected pin→off; the orchestrator also asserts no STOP targets a `protected` manifest (belt + suspenders).
- Atomic writes (temp in same dir + `os.replace`, mode preserved) for `haproxy-routes.json` and snapshots — same discipline as `emit.write_category`.
- `apply`/`rollback` are **root-only** (refuse `euid != 0`, like `scan`). Tests run per-directory: `.venv/bin/python -m pytest packages/secubox-profiles/tests -q`. Commits end `Co-Authored-By: Gerald KERMA <devel@cybermind.fr>`, NO Claude reference.

---

### Task 1: `actuate.py` — actuators + state-wait (pure, injected)

**Files:**
- Create: `packages/secubox-profiles/api/actuate.py`
- Test: `packages/secubox-profiles/tests/test_actuate.py`

**Interfaces:**
- Produces: `actuate(change, manifest, *, run, route_value=None) -> list[str]` (returns the ordered list of action-labels performed, for audit/tests; raises `ActuationError` on a failed command); `wait_state(manifest, want_on, *, observe, sleep, now, timeout=30.0, poll=1.0) -> bool`; `ActuationError`.

- [ ] **Step 1: Write the failing tests**

Create `packages/secubox-profiles/tests/test_actuate.py`:

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import json

import pytest

from api.actuate import ActuationError, actuate, wait_state
from api.diff import START, STOP, Change
from api.manifest import Manifest
from api.observe import Actual


def _m(mid, runtime="native", units=("u.service",), lxc=None, portal=None):
    return Manifest(id=mid, category="infra", runtime=runtime, exposure="lan",
                    units=tuple(units), lxc=lxc, portal_domain=portal)


def _ok_run(calls):
    def run(argv):
        calls.append(argv)
        return 0, ""
    return run


def test_native_start_enables_now(tmp_path):
    calls = []
    actuate(Change("x", START, "", 50), _m("x"), run=_ok_run(calls))
    assert ["systemctl", "enable", "--now", "u.service"] in calls


def test_native_stop_disables_now():
    calls = []
    actuate(Change("x", STOP, "", 50), _m("x"), run=_ok_run(calls))
    assert ["systemctl", "disable", "--now", "u.service"] in calls


def test_lxc_stop_stops_and_clears_autostart():
    calls = []
    actuate(Change("l", STOP, "", 50), _m("l", runtime="lxc", lxc="lyrion"),
            run=_ok_run(calls))
    assert ["lxc-stop", "-n", "lyrion"] in calls
    # autostart cleared via lxc-update-config (0) — exact tool checked by impl
    assert any("lxc" in " ".join(c) and "0" in c for c in calls)


def test_portal_stop_removes_route_before_backend(tmp_path):
    routes = tmp_path / "haproxy-routes.json"
    routes.write_text(json.dumps({"lyrion.gk2.secubox.in": ["127.0.0.1", 9000],
                                  "other.example": ["10.0.0.1", 80]}))
    calls = []
    order = actuate(Change("l", STOP, "", 50),
                    _m("l", runtime="lxc", lxc="lyrion", portal="lyrion.gk2.secubox.in"),
                    run=_ok_run(calls), route_value=None)
    # route removed
    left = json.loads(routes.read_text())
    assert "lyrion.gk2.secubox.in" not in left and "other.example" in left
    # portal removed BEFORE the lxc backend stopped
    assert order.index("portal:remove") < order.index("lxc:stop")


def test_portal_start_restores_route_from_value(tmp_path):
    routes = tmp_path / "haproxy-routes.json"
    routes.write_text(json.dumps({"other.example": ["10.0.0.1", 80]}))
    actuate(Change("l", START, "", 50),
            _m("l", runtime="lxc", lxc="lyrion", portal="lyrion.gk2.secubox.in"),
            run=_ok_run([]), route_value=["127.0.0.1", 9000])
    got = json.loads(routes.read_text())
    assert got["lyrion.gk2.secubox.in"] == ["127.0.0.1", 9000]


def test_failed_command_raises():
    def bad_run(argv):
        return 1, "boom"
    with pytest.raises(ActuationError):
        actuate(Change("x", START, "", 50), _m("x"), run=bad_run)


def test_command_that_cannot_run_raises():
    def dead_run(argv):
        return None, ""
    with pytest.raises(ActuationError):
        actuate(Change("x", START, "", 50), _m("x"), run=dead_run)


def test_wait_state_converges():
    seq = iter([Actual(active=False), Actual(active=True)])
    ticks = []
    ok = wait_state(_m("x"), True, observe=lambda m: next(seq),
                    sleep=lambda s: ticks.append(s), now=iter([0, 1, 2]).__next__,
                    timeout=30, poll=1)
    assert ok is True


def test_wait_state_times_out():
    ok = wait_state(_m("x"), True, observe=lambda m: Actual(active=False),
                    sleep=lambda s: None, now=iter([0, 10, 20, 31]).__next__,
                    timeout=30, poll=10)
    assert ok is False
```

Note: the portal actuator reads/writes the routes file at `observe.ROUTES_FILE` by default; the tests point it at a tmp file. Add a keyword `routes_path=observe.ROUTES_FILE` to `actuate` so tests can inject it (the tests above write the real key names — the impl must accept `routes_path`). Update the two portal tests to pass `routes_path=routes`.

- [ ] **Step 2: Run — must fail** (`No module named 'api.actuate'`).

Run: `.venv/bin/python -m pytest packages/secubox-profiles/tests/test_actuate.py -q`

- [ ] **Step 3: Implement `api/actuate.py`**

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: profiles — actionneurs (Phase 3a, ÉCRIT sur le système)
CyberMind — https://cybermind.fr

Un module = jusqu'à deux couches : runtime (systemd|lxc) + portail (route WAF).
Ordre intra-module :
  START : runtime d'abord, puis on route le portail (le backend existe avant la route).
  STOP  : portail d'abord (on retire la route), puis on éteint le runtime.
`run` est injecté (rc=None = commande n'a pas pu tourner = échec, jamais un faux succès).
Écriture de la route atomique (temp+rename, mode préservé), comme emit.write_category.
"""
from __future__ import annotations

import json
import os
import stat
import tempfile
import time
from pathlib import Path

from .diff import START, STOP, Change
from .manifest import Manifest
from .observe import ROUTES_FILE, is_on, observe as _observe


class ActuationError(Exception):
    """Une commande d'actionnement a échoué (rc non-nul) ou n'a pas pu tourner (rc=None)."""


def _must(run, argv: list[str]) -> None:
    rc, out = run(argv)
    if rc != 0:
        raise ActuationError(f"{' '.join(argv)} → rc={rc!r} {out.strip()[:200]}")


def _write_routes_atomic(routes_path: Path, data: dict) -> None:
    routes_path = Path(routes_path)
    orig_mode = os.stat(routes_path).st_mode
    fd, tmp = tempfile.mkstemp(dir=routes_path.parent, prefix=".haproxy-routes-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(json.dumps(data, indent=2, ensure_ascii=False) + "\n")
        os.chmod(tmp, stat.S_IMODE(orig_mode))
        os.replace(tmp, routes_path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def _portal_remove(domain: str, routes_path: Path) -> None:
    data = json.loads(Path(routes_path).read_text(encoding="utf-8"))
    if isinstance(data, dict) and domain in data:
        del data[domain]
        _write_routes_atomic(routes_path, data)


def _portal_add(domain: str, value, routes_path: Path) -> None:
    # value = [host, port] restauré depuis le snapshot ; sans valeur on ne crée
    # PAS de route (le backend d'un module portail est géré par secubox-exposure ;
    # 3a restaure ce qu'il a snapshotté, il n'invente pas de backend).
    if value is None:
        return
    data = json.loads(Path(routes_path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        return
    data[domain] = value
    _write_routes_atomic(routes_path, data)


def _lxc_autostart(lxc: str, on: bool, run) -> None:
    _must(run, ["lxc-update-config", "-n", lxc, "-x",
                f"lxc.start.auto={'1' if on else '0'}"])


def actuate(change: Change, m: Manifest, *, run, route_value=None,
            routes_path: Path = ROUTES_FILE) -> list[str]:
    """Exécute UN changement. Retourne la liste ordonnée des labels d'action
    (pour l'audit + les tests). Lève ActuationError au premier échec."""
    done: list[str] = []
    starting = change.action == START

    def runtime_start():
        if m.runtime == "lxc" and m.lxc:
            _must(run, ["lxc-start", "-n", m.lxc]); done.append("lxc:start")
            _lxc_autostart(m.lxc, True, run); done.append("lxc:autostart:1")
        else:
            for u in m.units:
                _must(run, ["systemctl", "enable", "--now", u])
            done.append("systemd:enable")

    def runtime_stop():
        if m.runtime == "lxc" and m.lxc:
            _must(run, ["lxc-stop", "-n", m.lxc]); done.append("lxc:stop")
            _lxc_autostart(m.lxc, False, run); done.append("lxc:autostart:0")
        else:
            for u in m.units:
                _must(run, ["systemctl", "disable", "--now", u])
            done.append("systemd:disable")

    if starting:
        runtime_start()
        if m.portal_domain:
            _portal_add(m.portal_domain, route_value, routes_path)
            done.append("portal:add")
    else:
        if m.portal_domain:
            _portal_remove(m.portal_domain, routes_path)
            done.append("portal:remove")
        runtime_stop()
    return done


def wait_state(m: Manifest, want_on: bool, *, observe=_observe,
               sleep=time.sleep, now=time.monotonic,
               timeout: float = 30.0, poll: float = 1.0) -> bool:
    """Sonde observe(m) jusqu'à is_on == want_on, ou expiration. Injectable."""
    start = now()
    while True:
        if is_on(observe(m)) == want_on:
            return True
        if now() - start >= timeout:
            return False
        sleep(poll)
```

- [ ] **Step 4: Run — must pass** (`.venv/bin/python -m pytest packages/secubox-profiles/tests/test_actuate.py -q`).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-profiles/api/actuate.py packages/secubox-profiles/tests/test_actuate.py
git commit -m "feat(profiles): actuators (systemd/lxc/portal) + state-wait

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

### Task 2: `snapshot.py` (4R) + `audit.py` (append-only)

**Files:**
- Create: `packages/secubox-profiles/api/snapshot.py`
- Create: `packages/secubox-profiles/api/audit.py`
- Test: `packages/secubox-profiles/tests/test_snapshot.py`
- Test: `packages/secubox-profiles/tests/test_audit.py`

**Interfaces:**
- Produces: `snapshot.capture(plan, manifests, actuals, *, now, routes, root=SNAP_DIR) -> dict` (writes R1, rotates R1→R4, returns the snapshot dict `{ts, profile?, modules:{id:{on, route?}}}`); `snapshot.read(target="R1", *, root=SNAP_DIR) -> dict`; `SNAP_DIR = Path("/var/lib/secubox/profiles/rollback")`. `audit.record(entry, *, path=AUDIT_LOG) -> None`; `AUDIT_LOG = Path("/var/log/secubox/audit.log")`.

- [ ] **Step 1: Write the failing tests**

`packages/secubox-profiles/tests/test_snapshot.py`:

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import json

from api.diff import START, STOP, Change
from api.manifest import Manifest
from api.observe import Actual
from api.snapshot import capture, read


def _m(mid, portal=None):
    return Manifest(id=mid, category="infra", runtime="lxc", exposure="lan",
                    units=(f"secubox-{mid}.service",), lxc=mid, portal_domain=portal)


def test_capture_records_prestate_and_portal_value(tmp_path):
    manifests = {"lyrion": _m("lyrion", portal="lyrion.gk2.secubox.in")}
    actuals = {"lyrion": Actual(lxc_running=True, portal_routed=True)}
    plan = [Change("lyrion", STOP, "", 50)]
    snap = capture(plan, manifests, actuals, now="2026-07-19T10:00:00Z",
                   routes={"lyrion.gk2.secubox.in": ["127.0.0.1", 9000]}, root=tmp_path)
    assert snap["modules"]["lyrion"]["on"] is True
    assert snap["modules"]["lyrion"]["route"] == ["127.0.0.1", 9000]
    assert (tmp_path / "R1.json").exists()
    assert read("R1", root=tmp_path)["modules"]["lyrion"]["on"] is True


def test_rotation_shifts_r1_to_r2(tmp_path):
    manifests = {"x": _m("x")}
    actuals = {"x": Actual(lxc_running=True)}
    plan = [Change("x", STOP, "", 50)]
    capture(plan, manifests, actuals, now="t1", routes={}, root=tmp_path)
    capture(plan, manifests, actuals, now="t2", routes={}, root=tmp_path)
    assert read("R1", root=tmp_path)["ts"] == "t2"
    assert read("R2", root=tmp_path)["ts"] == "t1"


def test_capture_only_planned_modules(tmp_path):
    manifests = {"x": _m("x"), "y": _m("y")}
    actuals = {"x": Actual(lxc_running=True), "y": Actual(lxc_running=True)}
    plan = [Change("x", STOP, "", 50)]  # only x
    snap = capture(plan, manifests, actuals, now="t", routes={}, root=tmp_path)
    assert set(snap["modules"]) == {"x"}
```

`packages/secubox-profiles/tests/test_audit.py`:

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import json

from api.audit import record


def test_record_appends_one_json_line(tmp_path):
    log = tmp_path / "audit.log"
    record({"module": "lyrion", "action": "stop", "result": "ok"}, path=log)
    record({"module": "lyrion", "action": "start", "result": "ok"}, path=log)
    lines = log.read_text().strip().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["module"] == "lyrion"
    assert json.loads(lines[1])["action"] == "start"


def test_record_never_raises_on_bad_dir(tmp_path):
    # best-effort: an unwritable path must not crash the caller (audit failure
    # is reported by the orchestrator, never fatal to the apply).
    record({"x": 1}, path=tmp_path / "nope" / "deep" / "audit.log")  # no raise
```

- [ ] **Step 2: Run — must fail.**

- [ ] **Step 3: Implement `api/snapshot.py`**

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: profiles — snapshot 4R (état pré-apply, pour rollback)
CyberMind — https://cybermind.fr

Avant tout apply on capture l'état réel des modules DU PLAN (pas toute la box)
dans R1, en décalant R1→R2→R3→R4 (R1 = le plus récent). Pour un module portail
on capture aussi la valeur de sa route WAF, sinon le rollback ne saurait pas la
recréer.
"""
from __future__ import annotations

import json
import os
import stat
import tempfile
from pathlib import Path

from .observe import is_on

SNAP_DIR = Path("/var/lib/secubox/profiles/rollback")
_SLOTS = ["R1", "R2", "R3", "R4"]


def _write_atomic(path: Path, data: dict) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".snap-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(json.dumps(data, indent=2, ensure_ascii=False) + "\n")
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def capture(plan, manifests, actuals, *, now, routes, root: Path = SNAP_DIR) -> dict:
    root = Path(root)
    ids = [c.id for c in plan]
    modules = {}
    for mid in ids:
        m = manifests.get(mid)
        a = actuals.get(mid)
        if m is None or a is None:
            continue
        entry = {"on": is_on(a)}
        if m.portal_domain:
            entry["route"] = routes.get(m.portal_domain) if isinstance(routes, dict) else None
        modules[mid] = entry
    snap = {"ts": now, "modules": modules}

    # rotate R3→R4, R2→R3, R1→R2 (drop old R4), then write R1.
    for older, newer in zip(reversed(_SLOTS[1:]), reversed(_SLOTS[:-1])):
        src = root / f"{newer}.json"
        if src.exists():
            _write_atomic(root / f"{older}.json", json.loads(src.read_text(encoding="utf-8")))
    _write_atomic(root / "R1.json", snap)
    return snap


def read(target: str = "R1", *, root: Path = SNAP_DIR) -> dict:
    if target not in _SLOTS:
        raise ValueError(f"cible de rollback inconnue: {target} (attendu {_SLOTS})")
    p = Path(root) / f"{target}.json"
    return json.loads(p.read_text(encoding="utf-8"))
```

- [ ] **Step 4: Implement `api/audit.py`**

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: profiles — audit append-only des décisions d'apply (CSPN)
CyberMind — https://cybermind.fr

Une ligne JSON par décision, ajoutée en fin de fichier (jamais réécrite).
Best-effort : un audit qui ne peut pas s'écrire ne doit pas casser l'apply —
l'orchestrateur le signale, mais la sûreté vient de l'action, pas du log.
"""
from __future__ import annotations

import json
from pathlib import Path

AUDIT_LOG = Path("/var/log/secubox/audit.log")


def record(entry: dict, *, path: Path = AUDIT_LOG) -> None:
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError:
        pass  # best-effort — never fatal to the apply
```

- [ ] **Step 5: Run — must pass** (`.venv/bin/python -m pytest packages/secubox-profiles/tests/test_snapshot.py packages/secubox-profiles/tests/test_audit.py -q`).

- [ ] **Step 6: Commit**

```bash
git add packages/secubox-profiles/api/snapshot.py packages/secubox-profiles/api/audit.py packages/secubox-profiles/tests/test_snapshot.py packages/secubox-profiles/tests/test_audit.py
git commit -m "feat(profiles): 4R snapshot (with portal route value) + append-only audit

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

### Task 3: `apply.py` — orchestration + rollback

**Files:**
- Create: `packages/secubox-profiles/api/apply.py`
- Test: `packages/secubox-profiles/tests/test_apply.py`

**Interfaces:**
- Consumes: `actuate`, `wait_state` (Task 1); `snapshot.capture/read` (Task 2); `audit.record`; `diff.START/STOP`, `manifest.Manifest`.
- Produces: `apply_plan(plan, manifests, actuals, *, run, observe, now, routes, snap_root, audit_path, wait_timeout=30) -> ApplyReport`; `rollback_to(snap, manifests, *, run, observe, now, routes, audit_path) -> ApplyReport`; `ApplyReport(status, changed, failed, rolled_back)`; `ApplyError`.

- [ ] **Step 1: Write the failing tests**

`packages/secubox-profiles/tests/test_apply.py`:

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
from api.apply import apply_plan
from api.diff import START, STOP, Change
from api.manifest import Manifest
from api.observe import Actual


def _m(mid, protected=False):
    return Manifest(id=mid, category="infra", runtime="native",
                    exposure="lan", units=(f"{mid}.service",), protected=protected)


def _run_ok(calls):
    def run(argv):
        calls.append(argv)
        return 0, ""
    return run


def test_dry_run_acts_on_nothing(tmp_path):
    calls = []
    plan = [Change("a", STOP, "", 50)]
    rep = apply_plan(plan, {"a": _m("a")}, {"a": Actual(active=True)},
                     run=_run_ok(calls), observe=lambda m: Actual(active=False),
                     now="t", routes={}, snap_root=tmp_path,
                     audit_path=tmp_path / "audit.log", apply=False)
    assert rep.status == "planned"
    assert calls == []  # nothing actuated


def test_apply_stops_then_starts_in_order(tmp_path):
    calls = []
    manifests = {"lo": _m("lo"), "hi": _m("hi")}
    # plan already ordered by plan_changes: stop lo, then start hi
    plan = [Change("lo", STOP, "", 10), Change("hi", START, "", 90)]
    states = {"lo": iter([Actual(active=False)]), "hi": iter([Actual(active=True)])}
    rep = apply_plan(plan, manifests,
                     {"lo": Actual(active=True), "hi": Actual(active=False)},
                     run=_run_ok(calls), observe=lambda m: next(states[m.id]),
                     now="t", routes={}, snap_root=tmp_path,
                     audit_path=tmp_path / "audit.log", apply=True)
    assert rep.status == "applied"
    # disable (stop) issued before enable (start)
    dis = next(i for i, c in enumerate(calls) if c[:2] == ["systemctl", "disable"])
    ena = next(i for i, c in enumerate(calls) if c[:2] == ["systemctl", "enable"])
    assert dis < ena


def test_stop_of_protected_is_refused(tmp_path):
    plan = [Change("auth", STOP, "", 50)]
    import pytest
    from api.apply import ApplyError
    with pytest.raises(ApplyError):
        apply_plan(plan, {"auth": _m("auth", protected=True)},
                   {"auth": Actual(active=True)}, run=_run_ok([]),
                   observe=lambda m: Actual(active=False), now="t", routes={},
                   snap_root=tmp_path, audit_path=tmp_path / "audit.log", apply=True)


def test_failure_at_module_k_rolls_back_prior(tmp_path):
    # plan: stop a (ok), stop b (its wait never converges → failure) → a restored.
    calls = []
    manifests = {"a": _m("a"), "b": _m("b")}
    plan = [Change("a", STOP, "", 10), Change("b", STOP, "", 20)]

    def observe(m):
        if m.id == "a":
            return Actual(active=False)   # a converges to off
        return Actual(active=True)        # b never turns off → timeout

    rep = apply_plan(plan, manifests,
                     {"a": Actual(active=True), "b": Actual(active=True)},
                     run=_run_ok(calls), observe=observe, now="t", routes={},
                     snap_root=tmp_path, audit_path=tmp_path / "audit.log",
                     apply=True, wait_timeout=0)
    assert rep.status == "rolled_back"
    assert "b" in rep.failed
    # a was rolled back → re-enabled (started again)
    assert ["systemctl", "enable", "--now", "a.service"] in calls
```

Note: give `apply_plan` an `apply: bool` keyword (default False = dry-run). `wait_timeout=0` makes the wait fail immediately (one observe, no convergence) to drive the rollback test deterministically without real sleeping — inject `sleep=lambda *_: None` and a `now` counter inside `apply_plan`'s wait call, or pass `wait_timeout=0` and have `wait_state` return False when the first probe misses and `now()-start >= 0`. Ensure the impl threads an injectable `sleep`/`now` into `wait_state` (default real) so tests don't sleep.

- [ ] **Step 2: Run — must fail.**

- [ ] **Step 3: Implement `api/apply.py`**

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: profiles — orchestration de l'apply (Phase 3a)
CyberMind — https://cybermind.fr

Snapshot → exécution séquentielle (stops avant starts, un module à la fois,
attente d'état entre chaque, audit par décision) → rollback si un module échoue.
Ne parallélise jamais. Refuse tout STOP d'un module protégé.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import audit as _audit
from . import snapshot as _snapshot
from .actuate import ActuationError, actuate, wait_state
from .diff import START, STOP, Change
from .manifest import Manifest


class ApplyError(Exception):
    """Refus (ex. STOP d'un module protégé) — rien n'a été appliqué."""


@dataclass
class ApplyReport:
    status: str                       # planned | applied | rolled_back
    changed: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)
    rolled_back: list[str] = field(default_factory=list)


def _want_on(action: str) -> bool:
    return action == START


def _do_change(c: Change, m: Manifest, *, run, observe, routes_value, sleep, now,
               wait_timeout) -> None:
    actuate(c, m, run=run, route_value=routes_value)
    if not wait_state(m, _want_on(c.action), observe=observe, sleep=sleep, now=now,
                      timeout=wait_timeout):
        raise ActuationError(f"{c.id}: état non atteint (timeout)")


def apply_plan(plan, manifests, actuals, *, run, observe, now, routes,
               snap_root, audit_path, apply=False, wait_timeout=30.0,
               sleep=None, clock=None) -> ApplyReport:
    import time
    sleep = sleep if sleep is not None else time.sleep
    clock = clock if clock is not None else time.monotonic

    # Refus AVANT toute action : aucun STOP sur un protégé.
    for c in plan:
        m = manifests.get(c.id)
        if c.action == STOP and m is not None and m.protected:
            raise ApplyError(f"{c.id} est protégé — un STOP est refusé")

    if not apply:
        return ApplyReport(status="planned",
                           changed=[c.id for c in plan])

    snap = _snapshot.capture(plan, manifests, actuals, now=now, routes=routes,
                             root=snap_root)
    applied: list[Change] = []
    for c in plan:
        m = manifests[c.id]
        rv = (snap["modules"].get(c.id, {}).get("route") if c.action == START else None)
        try:
            _do_change(c, m, run=run, observe=observe, routes_value=rv,
                       sleep=sleep, now=clock, wait_timeout=wait_timeout)
            _audit.record({"ts": now, "module": c.id, "action": c.action,
                           "result": "ok", "reason": c.reason}, path=audit_path)
            applied.append(c)
        except (ActuationError, OSError) as exc:
            _audit.record({"ts": now, "module": c.id, "action": c.action,
                           "result": "fail", "error": str(exc)}, path=audit_path)
            rolled = _rollback_applied(applied, manifests, snap, run=run,
                                       observe=observe, sleep=sleep, clock=clock,
                                       now=now, audit_path=audit_path,
                                       wait_timeout=wait_timeout)
            return ApplyReport(status="rolled_back", changed=[x.id for x in applied],
                               failed=[c.id], rolled_back=rolled)
    return ApplyReport(status="applied", changed=[c.id for c in applied])


def _rollback_applied(applied, manifests, snap, *, run, observe, sleep, clock,
                      now, audit_path, wait_timeout) -> list[str]:
    """Inverse les changements déjà appliqués (état pré-apply du snapshot),
    du dernier au premier, best-effort."""
    rolled: list[str] = []
    for c in reversed(applied):
        pre = snap["modules"].get(c.id, {})
        want_on = pre.get("on", False)
        m = manifests[c.id]
        rev = Change(c.id, START if want_on else STOP, "rollback", c.priority)
        rv = pre.get("route") if want_on else None
        try:
            actuate(rev, m, run=run, route_value=rv)
            wait_state(m, want_on, observe=observe, sleep=sleep, now=clock,
                       timeout=wait_timeout)
            _audit.record({"ts": now, "module": c.id, "action": rev.action,
                           "result": "rollback"}, path=audit_path)
            rolled.append(c.id)
        except (ActuationError, OSError) as exc:
            _audit.record({"ts": now, "module": c.id, "action": "rollback",
                           "result": "fail", "error": str(exc)}, path=audit_path)
    return rolled


def rollback_to(snap, manifests, actuals, *, run, observe, now, routes,
                snap_root, audit_path, apply=False, wait_timeout=30.0) -> ApplyReport:
    """Restaure l'état d'un snapshot : construit un plan (start/stop) vers
    snap['modules'][id]['on'] et l'applique avec la même sûreté que apply_plan."""
    from .observe import is_on
    plan: list[Change] = []
    for mid, pre in snap["modules"].items():
        m = manifests.get(mid)
        a = actuals.get(mid)
        if m is None or a is None:
            continue
        want_on = pre.get("on", False)
        if is_on(a) == want_on:
            continue
        plan.append(Change(mid, START if want_on else STOP, "rollback", m.priority))
    plan.sort(key=lambda c: (0 if c.action == STOP else 1,
                             c.priority if c.action == STOP else -c.priority, c.id))
    # route values come from the snapshot, injected via a merged routes map.
    merged = dict(routes) if isinstance(routes, dict) else {}
    for mid, pre in snap["modules"].items():
        m = manifests.get(mid)
        if m is not None and m.portal_domain and pre.get("route") is not None:
            merged[m.portal_domain] = pre["route"]
    return apply_plan(plan, manifests, actuals, run=run, observe=observe, now=now,
                      routes=merged, snap_root=snap_root, audit_path=audit_path,
                      apply=apply, wait_timeout=wait_timeout)
```

- [ ] **Step 4: Run — must pass** (`.venv/bin/python -m pytest packages/secubox-profiles/tests/test_apply.py -q`).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-profiles/api/apply.py packages/secubox-profiles/tests/test_apply.py
git commit -m "feat(profiles): apply orchestration — sequential, protected-guard, rollback-on-failure

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

### Task 4: CLI `apply`/`rollback` (root-only) + version + tests

**Files:**
- Modify: `packages/secubox-profiles/api/cli.py`
- Modify: `packages/secubox-profiles/debian/changelog`
- Test: `packages/secubox-profiles/tests/test_cli.py` (extend)

**Interfaces:**
- Consumes: `apply.apply_plan/rollback_to`, `snapshot.read`, `diff.plan_changes`, existing `_paths`, `_load_profile_or_none`, `load_all`, `load_pins`, `_observe_all`, `observe.load_routes`, `_running_as_root`.

- [ ] **Step 1: Write the failing tests**

Add to `packages/secubox-profiles/tests/test_cli.py`:

```python
def test_apply_requires_root(tmp_path, monkeypatch):
    import api.cli as cli
    monkeypatch.setattr(cli, "_running_as_root", lambda: False)
    root = tmp_path / "etc"
    (root / "modules.d").mkdir(parents=True)
    (root / "profiles").mkdir(parents=True)
    assert cli.main(["--root", str(root), "apply", "--yes"]) == 1


def test_apply_dry_run_default_acts_on_nothing(tmp_path, monkeypatch, capsys):
    import api.cli as cli
    monkeypatch.setattr(cli, "_running_as_root", lambda: True)
    root = tmp_path / "etc"
    (root / "modules.d").mkdir(parents=True)
    (root / "profiles").mkdir(parents=True)
    (root / "modules.d" / "lyrion.toml").write_text(
        'id="lyrion"\ncategory="infra"\nruntime="lxc"\nexposure="lan"\n'
        'units=["secubox-lyrion.service"]\nlxc="lyrion"\nprotected=false\n')
    # observe: lyrion currently on; no profile → desired off → plan = stop lyrion
    monkeypatch.setattr(cli, "_observe_all",
                        lambda mans, routes: {"lyrion": __import__("api.observe", fromlist=["Actual"]).Actual(lxc_running=True)})
    called = {"n": 0}
    import api.apply as ap
    real = ap.apply_plan
    def spy(*a, **k):
        called["n"] += 1
        assert k.get("apply") is False   # dry-run
        return real(*a, **k)
    monkeypatch.setattr(ap, "apply_plan", spy)
    rc = cli.main(["--root", str(root), "apply"])  # no --yes → dry-run
    assert rc == 0 and called["n"] == 1


def test_apply_only_filters_plan(tmp_path, monkeypatch):
    # --only restricts the plan; a plan with x and y, --only x → only x acted.
    import api.cli as cli
    monkeypatch.setattr(cli, "_running_as_root", lambda: True)
    # (build a two-module root; assert the plan passed to apply_plan has only x)
    ...
```

Note: the third test's exact wiring depends on the impl; the reviewer will accept an equivalent assertion that `--only` reduces the plan to the named ids (e.g. spy on `apply_plan` and inspect the `plan` arg). Keep the first two tests as written (root gate + dry-run default).

- [ ] **Step 2: Run — must fail.**

- [ ] **Step 3: Wire `cli.py`**

Add imports:

```python
from .apply import apply_plan, rollback_to
from .snapshot import read as read_snapshot
```

Add handlers (beside `_cmd_diff`), reusing the existing observe/plan path:

```python
def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _cmd_apply(args) -> int:
    if not _running_as_root():
        print("apply doit être lancé en root (il pilote systemd/LXC/haproxy).",
              file=sys.stderr)
        return 1
    root = Path(args.root)
    mod_dir, _, pins_file, _ = _paths(root)
    manifests = load_all(mod_dir)
    profile = _load_profile_or_none(root, _active_profile_name(root, args.profile))
    pins = load_pins(pins_file)
    routes = load_routes()
    actuals = _observe_all(manifests, routes)
    plan = plan_changes(manifests, profile, pins, actuals)
    if args.only:
        keep = set(args.only)
        plan = [c for c in plan if c.id in keep]
    routes_map = routes if isinstance(routes, dict) else {}
    report = apply_plan(plan, manifests, actuals, run=_run, observe=observe,
                        now=_now_iso(), routes=routes_map, snap_root=SNAP_DIR,
                        audit_path=AUDIT_LOG, apply=args.yes)
    if not args.yes:
        if not plan:
            print("✅ rien à changer.")
        else:
            print(f"{len(plan)} changement(s) — dry-run (ajoutez --yes pour appliquer) :")
            for c in plan:
                print(f"  {'⛔ stop ' if c.action == 'stop' else '▶️  start'} {c.id:<20} ({c.reason})")
        return 0
    print(f"apply: {report.status} — changed={report.changed} "
          f"failed={report.failed} rolled_back={report.rolled_back}")
    return 0 if report.status == "applied" else 2


def _cmd_rollback(args) -> int:
    if not _running_as_root():
        print("rollback doit être lancé en root.", file=sys.stderr)
        return 1
    root = Path(args.root)
    mod_dir, _, _, _ = _paths(root)
    manifests = load_all(mod_dir)
    snap = read_snapshot(args.target, root=SNAP_DIR)
    routes = load_routes()
    actuals = _observe_all(manifests, routes)
    report = rollback_to(snap, manifests, actuals, run=_run, observe=observe,
                         now=_now_iso(), routes=routes if isinstance(routes, dict) else {},
                         snap_root=SNAP_DIR, audit_path=AUDIT_LOG, apply=args.yes)
    print(f"rollback[{args.target}]: {report.status} — changed={report.changed}")
    return 0 if report.status in ("applied", "planned") else 2
```

Add the imports for `plan_changes`, `observe`, `load_routes`, `SNAP_DIR`, `AUDIT_LOG` at the top (from `.diff`, `.observe`, `.snapshot`, `.audit`). Register subparsers in `main` (after `scan`):

```python
    sp = sub.add_parser("apply", help="applique un profil (dry-run par défaut ; --yes pour agir)")
    sp.add_argument("--profile", default=None)
    sp.add_argument("--only", action="append", default=[],
                    help="restreindre aux modules nommés (répétable) — validation module par module")
    sp.add_argument("--yes", action="store_true", help="agir réellement")
    sp.set_defaults(func=_cmd_apply)

    sp = sub.add_parser("rollback", help="restaure un snapshot (R1..R4 ; --yes pour agir)")
    sp.add_argument("--target", default="R1", choices=["R1", "R2", "R3", "R4"])
    sp.add_argument("--yes", action="store_true")
    sp.set_defaults(func=_cmd_rollback)
```

- [ ] **Step 4: Run — must pass** (`.venv/bin/python -m pytest packages/secubox-profiles/tests/test_cli.py -q`).

- [ ] **Step 5: Full suite + version + commit**

Run: `.venv/bin/python -m pytest packages/secubox-profiles/tests -q` (all prior + new pass).

Prepend to `debian/changelog`:

```
secubox-profiles (0.4.0-1~bookworm1) bookworm; urgency=medium

  * Phase 3a: apply actuator. `secubox-profilectl apply [--profile X] [--only ID]
    [--yes]` (dry-run by default) and `rollback [--target R1..R4] [--yes]` — root
    only. Actuates systemd/LXC/portal one module at a time (stops before starts),
    waits for state, snapshots pre-state (4R, with portal route values), audits
    each decision, and rolls back on any failure. Boot reconciliation and the
    API/panel surfaces come in a follow-up.

 -- Gerald KERMA <devel@cybermind.fr>  Sun, 19 Jul 2026 16:00:00 +0200

```

```bash
git add packages/secubox-profiles/api/cli.py packages/secubox-profiles/debian/changelog packages/secubox-profiles/tests/test_cli.py
git commit -m "feat(profiles): secubox-profilectl apply/rollback (root-only, dry-run default) — 0.4.0

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

## Auto-revue du plan

- **Couverture** : actuators + wait (T1) ; snapshot 4R + audit (T2) ; orchestration + rollback (T3) ; CLI + version (T4). ✓
- **Sûreté** : refus STOP protégé (T3, testé) ; stops-avant-starts via l'ordre de `plan_changes` (T3, testé) ; un-à-un ; rollback-sur-échec restaure le pré-état (T3, testé) ; dry-run n'agit pas (T3/T4) ; root-only (T4) ; écritures atomiques (T1/T2).
- **Portail** : STOP retire la route avant le backend ; START la restaure depuis le snapshot ; start à froid sans valeur = pas de route (rôle d'exposure), documenté.
- **Types** : `Change`/`Manifest`/`Actual` réutilisés ; `route_value` du snapshot injecté vers `actuate` ; `apply_plan(..., apply=bool)` défaut dry-run.
- **Placeholders** : le 3e test CLI `--only` porte une note d'équivalence (spy sur le plan) — le reste porte code + commande + attendu.
- **Validation réelle** (hors plan, faite par le contrôleur) : sur gk2 root, `apply --only lyrion` (dry-run) → `--yes` (stop) → vérifier + `rollback --yes` (restaure). Jamais un lot.
