<!--
SPDX-License-Identifier: LicenseRef-CMSD-1.0
Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
Source-Disclosed License — All rights reserved except as expressly granted.
See LICENCE-CMSD-1.0.md for terms.
-->

# Scale-to-Zero for Public Services — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let `on-demand`/`eager` public LXC services sleep (container stopped → RAM freed) when idle and wake on first access behind a branded splash, driven by a per-module lifecycle policy and the secubox-profiles 0.7.0 observed-state actuator.

**Architecture:** Extend `secubox-profiles` manifests with `lifecycle`+`wake_class`; a root `secubox-wakectl` starts a module via the 0.7.0 actuator; a `secubox-waker` FastAPI activator (own socket) serves the splash and fires the wake when nginx routes a down vhost to it; a `secubox-sleeper` daemon stops idle modules using front signals (last-request + active-conns) plus an optional per-module `/idle` hint.

**Tech Stack:** Python 3.11, FastAPI on Unix sockets, systemd, nginx, LXC, Debian packaging (arch:all). Reuses secubox-profiles `apply`/`actuate`/`observe`/`manifest`.

**Dependency:** Builds on secubox-profiles **0.7.0** (PR #894). This branch must be based on / rebased onto the merge of #894 before Task 2 (which imports the 0.7.0 actuator). Task 1 (schema) is independent of the actuator.

## Global Constraints

- Python 3.11; every file starts with `from __future__ import annotations` and the 4-line SPDX header block.
- mypy `--strict`: the module has a pre-existing baseline of strict errors; standard = "no NEW strict errors vs baseline" (verify with a git stash/checkout comparison), NOT zero.
- webui→ctl: unprivileged services never actuate in-process; every start/stop/config-write goes through a root `ctl` over scoped exact-command sudoers, audited to `/var/log/secubox/audit.log`.
- Reuse the 0.7.0 actuator for ALL start/stop (`apply.apply_plan` with `--only`), never raw `lxc-start`/`systemctl`.
- Each service on its own Unix socket under `/run/secubox/`, single uvicorn worker (process-local `asyncio.Lock` is valid).
- `always-on` and `protected` modules never sleep; `manual` never auto-starts/stops; a `protected` module is treated as `always-on` regardless of declared `lifecycle`.
- Sequential actuation, one module at a time (inherited).
- Tests run per-directory: `cd packages/secubox-profiles && python -m pytest tests/... -v`.
- Commit trailer `Co-Authored-By: Gerald KERMA <devel@cybermind.fr>`, no Claude references.

---

## File Structure

| File | Responsibility |
|------|----------------|
| `api/manifest.py` (modify) | Add `lifecycle`+`wake_class` to `Manifest` + validation; `protected`⇒`always-on`. |
| `api/lifecycle.py` (create) | Pure policy helpers: `effective_lifecycle`, `is_sleepable`, `idle_threshold`, `wake_budget`. |
| `api/wake.py` (create) | `wake(module, …)` — start one module via the 0.7.0 actuator; the `secubox-wakectl` entry point. |
| `api/front_signals.py` (create) | `vhost_signals()` — per-vhost `last_request_age` + `active_conns` from the front (injected reader). |
| `api/sleeper.py` (create) | `decide_sleep()` pure logic + `run_once()` daemon pass (stop idle modules via actuator). |
| `api/waker.py` (create) | FastAPI activator: vhost→module resolve, wake lock, splash+budget, poll-up, wake-rate cap. |
| `api/nginxgen.py` (create) | Generate per-vhost `@waker` snippets; the `secubox-wakectl nginx-sync` verb. |
| `api/web.py` (modify) | Panel routes: expose lifecycle/wake_class + sleep state; manual sleep/wake (webui→ctl). |
| `www/profiles/*` (modify) | Panel UI: lifecycle/wake_class/sleep-state + manual buttons. |
| `templates/waking.html` (create) | Branded splash (auto-refresh + budget), `no-store`. |
| `debian/*`, `systemd/*`, `sudoers.d/*` | Ship `secubox-waker` + `secubox-sleeper` units, sudoers, nginx snippet dir. |
| `README.md`, `wiki/*`, `debian/changelog` | Docs + version bump. |

---

## Task 1: Manifest lifecycle + wake_class schema

**Files:**
- Modify: `packages/secubox-profiles/api/manifest.py`
- Create: `packages/secubox-profiles/api/lifecycle.py`
- Test: `packages/secubox-profiles/tests/test_manifest.py` (add), `packages/secubox-profiles/tests/test_lifecycle.py` (create)

**Interfaces:**
- Produces: `Manifest.lifecycle: str` (default `"eager"`), `Manifest.wake_class: str` (default `"normal"`); module constants `LIFECYCLES=("always-on","eager","on-demand","manual")`, `WAKE_CLASSES=("normal","urgent")`.
- Produces (lifecycle.py): `effective_lifecycle(m: Manifest) -> str` (returns `"always-on"` if `m.protected`, else `m.lifecycle`); `is_sleepable(m) -> bool` (True iff effective in `{"eager","on-demand"}`); `idle_threshold(m, *, base=900.0, urgent_mult=4.0) -> float` (seconds; urgent → `base*urgent_mult`); `wake_budget(m, *, history_median=None, normal=45.0, urgent=15.0) -> float` (history_median if given else per-class default).

- [ ] **Step 1: Write failing tests (manifest)**

Add to `tests/test_manifest.py` (create the file if absent, mirroring existing manifest-loading tests; write a manifest to a tmp file and load it):

```python
def _write(tmp_path, body):
    p = tmp_path / "x.toml"
    p.write_text('id="x"\ncategory="infra"\nruntime="native"\nexposure="lan"\n'
                 'units=["x.service"]\n' + body)
    return p

def test_lifecycle_defaults_eager_normal(tmp_path):
    from api.manifest import load_manifest
    m = load_manifest(_write(tmp_path, ""))
    assert m.lifecycle == "eager" and m.wake_class == "normal"

def test_lifecycle_and_wake_class_parse(tmp_path):
    from api.manifest import load_manifest
    m = load_manifest(_write(tmp_path, 'lifecycle="on-demand"\nwake_class="urgent"\n'))
    assert m.lifecycle == "on-demand" and m.wake_class == "urgent"

def test_invalid_lifecycle_raises(tmp_path):
    import pytest
    from api.manifest import load_manifest, ManifestError
    with pytest.raises(ManifestError):
        load_manifest(_write(tmp_path, 'lifecycle="hibernate"\n'))

def test_invalid_wake_class_raises(tmp_path):
    import pytest
    from api.manifest import load_manifest, ManifestError
    with pytest.raises(ManifestError):
        load_manifest(_write(tmp_path, 'wake_class="asap"\n'))
```

- [ ] **Step 2: Run to verify fail**

Run: `cd packages/secubox-profiles && python -m pytest tests/test_manifest.py -k lifecycle -v`
Expected: FAIL — `Manifest` has no `lifecycle` attribute.

- [ ] **Step 3: Add fields + validation to manifest.py**

Add module constants after `EXPOSURES`/`CATEGORIES` (line ~25):

```python
LIFECYCLES = ("always-on", "eager", "on-demand", "manual")
WAKE_CLASSES = ("normal", "urgent")

DEFAULT_LIFECYCLE = "eager"
DEFAULT_WAKE_CLASS = "normal"
```

Add to the `Manifest` dataclass (after `needs`):

```python
    lifecycle: str = DEFAULT_LIFECYCLE
    wake_class: str = DEFAULT_WAKE_CLASS
```

In `load_manifest`, before the final `return Manifest(...)`, add:

```python
    lifecycle = _enum(d.get("lifecycle", DEFAULT_LIFECYCLE), LIFECYCLES, "lifecycle", path)
    wake_class = _enum(d.get("wake_class", DEFAULT_WAKE_CLASS), WAKE_CLASSES, "wake_class", path)
```

and pass `lifecycle=lifecycle, wake_class=wake_class,` in the `Manifest(...)` constructor.

- [ ] **Step 4: Run to verify pass**

Run: `cd packages/secubox-profiles && python -m pytest tests/test_manifest.py -k lifecycle -v`
Expected: PASS (4).

- [ ] **Step 5: Write failing tests (lifecycle.py)**

Create `tests/test_lifecycle.py`:

```python
from api.lifecycle import effective_lifecycle, is_sleepable, idle_threshold, wake_budget
from api.manifest import Manifest

def _m(lifecycle="eager", wake_class="normal", protected=False):
    return Manifest(id="x", category="infra", runtime="native", exposure="lan",
                    units=("x.service",), protected=protected,
                    lifecycle=lifecycle, wake_class=wake_class)

def test_protected_is_effectively_always_on():
    assert effective_lifecycle(_m(lifecycle="on-demand", protected=True)) == "always-on"

def test_effective_passthrough_when_not_protected():
    assert effective_lifecycle(_m(lifecycle="on-demand")) == "on-demand"

def test_is_sleepable_only_eager_and_on_demand():
    assert is_sleepable(_m(lifecycle="eager")) is True
    assert is_sleepable(_m(lifecycle="on-demand")) is True
    assert is_sleepable(_m(lifecycle="always-on")) is False
    assert is_sleepable(_m(lifecycle="manual")) is False
    assert is_sleepable(_m(lifecycle="on-demand", protected=True)) is False  # protected wins

def test_idle_threshold_urgent_is_longer():
    assert idle_threshold(_m(wake_class="normal"), base=900.0, urgent_mult=4.0) == 900.0
    assert idle_threshold(_m(wake_class="urgent"), base=900.0, urgent_mult=4.0) == 3600.0

def test_wake_budget_history_beats_default():
    assert wake_budget(_m(wake_class="normal"), history_median=None, normal=45.0) == 45.0
    assert wake_budget(_m(wake_class="urgent"), history_median=None, urgent=15.0) == 15.0
    assert wake_budget(_m(wake_class="normal"), history_median=30.0) == 30.0
```

- [ ] **Step 6: Run to verify fail**

Run: `cd packages/secubox-profiles && python -m pytest tests/test_lifecycle.py -v`
Expected: FAIL — `api.lifecycle` missing.

- [ ] **Step 7: Create lifecycle.py**

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: profiles — politique de cycle de vie (pure, sans effet de bord)
CyberMind — https://cybermind.fr
"""
from __future__ import annotations

from .manifest import Manifest


def effective_lifecycle(m: Manifest) -> str:
    """Un module protégé est TOUJOURS always-on, quoi que déclare le manifeste
    (on ne laisse jamais endormir le cœur — même règle que manifest.protected)."""
    return "always-on" if m.protected else m.lifecycle


def is_sleepable(m: Manifest) -> bool:
    """Seuls eager et on-demand participent au sleep/wake."""
    return effective_lifecycle(m) in ("eager", "on-demand")


def idle_threshold(m: Manifest, *, base: float = 900.0, urgent_mult: float = 4.0) -> float:
    """Durée d'inactivité avant sommeil. urgent dort plus difficilement."""
    return base * urgent_mult if m.wake_class == "urgent" else base


def wake_budget(m: Manifest, *, history_median: float | None = None,
                normal: float = 45.0, urgent: float = 15.0) -> float:
    """Budget de réveil affiché (secondes) : médiane historique si connue, sinon
    défaut par classe."""
    if history_median is not None:
        return history_median
    return urgent if m.wake_class == "urgent" else normal
```

- [ ] **Step 8: Run to verify pass + full manifest suite + mypy**

Run: `cd packages/secubox-profiles && python -m pytest tests/test_lifecycle.py tests/test_manifest.py -v && python -m mypy --strict api/lifecycle.py api/manifest.py`
Expected: tests PASS; mypy no new errors vs baseline.

- [ ] **Step 9: Commit**

```bash
git add packages/secubox-profiles/api/manifest.py packages/secubox-profiles/api/lifecycle.py packages/secubox-profiles/tests/test_manifest.py packages/secubox-profiles/tests/test_lifecycle.py
git commit -m "feat(profiles): lifecycle + wake_class manifest policy (ref #896)

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

## Task 2: `secubox-wakectl` — wake one module via the 0.7.0 actuator

**Files:**
- Create: `packages/secubox-profiles/api/wake.py`
- Test: `packages/secubox-profiles/tests/test_wake.py`

**Interfaces:**
- Consumes: `apply.apply_plan`, `diff.Change/START`, `manifest.load_all`, `observe.observe/observe_all`, `lifecycle.effective_lifecycle` (Task 1).
- Produces: `wake(module: str, *, root, run, observe, now, apply=True) -> dict` returning `{"status": "...", "module": module}` where status ∈ `{"woken","already-up","refused","failed"}`; a `main(argv)` CLI (`secubox-wakectl wake <module> [--json]`) mapping status→exit code (0 woken/already-up, 3 refused manual/unknown/always-on-noop, 2 failed).

- [ ] **Step 1: Write failing test**

```python
def test_wake_refuses_manual_and_unknown(tmp_path):
    from api.wake import wake
    from api.observe import Actual
    root = tmp_path
    (root / "modules.d").mkdir()
    (root / "modules.d" / "demo.toml").write_text(
        'id="demo"\ncategory="infra"\nruntime="native"\nexposure="lan"\n'
        'units=["demo.service"]\nlifecycle="manual"\n')
    r = wake("demo", root=root, run=lambda a: (0, ""),
             observe=lambda m: Actual(enabled=False, active=False), now="t")
    assert r["status"] == "refused"
    r2 = wake("ghost", root=root, run=lambda a: (0, ""),
              observe=lambda m: Actual(enabled=False, active=False), now="t")
    assert r2["status"] == "refused"

def test_wake_already_up_is_noop(tmp_path):
    from api.wake import wake
    from api.observe import Actual
    root = tmp_path
    (root / "modules.d").mkdir()
    (root / "modules.d" / "demo.toml").write_text(
        'id="demo"\ncategory="infra"\nruntime="native"\nexposure="lan"\n'
        'units=["demo.service"]\nlifecycle="on-demand"\n')
    r = wake("demo", root=root, run=lambda a: (0, ""),
             observe=lambda m: Actual(enabled=True, active=True), now="t")
    assert r["status"] == "already-up"

def test_wake_starts_a_down_on_demand_module(tmp_path):
    from api.wake import wake
    from api.observe import Actual
    calls = []
    root = tmp_path
    (root / "modules.d").mkdir()
    (root / "modules.d" / "demo.toml").write_text(
        'id="demo"\ncategory="infra"\nruntime="native"\nexposure="lan"\n'
        'units=["demo.service"]\nlifecycle="on-demand"\n')
    # observe: down first (so plan_changes plans a START), then up (wait_state converges)
    seq = iter([Actual(enabled=False, active=False)] + [Actual(enabled=True, active=True)] * 5)
    def obs(m):
        return next(seq)
    def run(a):
        calls.append(a); return 0, ""
    r = wake("demo", root=root, run=run, observe=obs, now="t")
    assert r["status"] == "woken"
    assert any(c[:2] == ["systemctl", "enable"] for c in calls)
```

- [ ] **Step 2: Run to verify fail**

Run: `cd packages/secubox-profiles && python -m pytest tests/test_wake.py -v`
Expected: FAIL — `api.wake` missing.

- [ ] **Step 3: Implement wake.py**

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: profiles — secubox-wakectl : réveille UN module (start on-demand)
CyberMind — https://cybermind.fr

Ne réimplémente rien : construit un plan START pour le module ciblé et le
confie à l'actionneur 0.7.0 (apply_plan, état-observé, snapshot 4R, audit,
timeout dérivé). Refuse manual/unknown/always-on. Idempotent si déjà up.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import apply as _apply
from .audit import AUDIT_LOG
from .diff import START, Change
from .lifecycle import effective_lifecycle
from .manifest import load_all
from .observe import is_on, observe as _observe
from .snapshot import SNAP_DIR

DEFAULT_ROOT = Path("/etc/secubox")


def wake(module: str, *, root: Path = DEFAULT_ROOT, run, observe=_observe,
         now: str, apply: bool = True) -> dict:
    manifests = load_all(Path(root) / "modules.d")
    m = manifests.get(module)
    if m is None:
        return {"status": "refused", "module": module, "reason": "unknown"}
    eff = effective_lifecycle(m)
    if eff in ("manual", "always-on"):
        # manual: jamais de réveil auto. always-on: déjà censé tourner (rien à réveiller).
        return {"status": "refused", "module": module, "reason": eff}
    if is_on(observe(m)):
        return {"status": "already-up", "module": module}
    plan = [Change(module, START, "wake-on-access", m.priority)]
    actuals = {module: observe(m)}
    report = _apply.apply_plan(plan, manifests, actuals, run=run, observe=observe,
                               now=now, routes={}, snap_root=SNAP_DIR,
                               audit_path=AUDIT_LOG, apply=apply)
    if report.status == "applied" and module in report.changed:
        return {"status": "woken", "module": module}
    return {"status": "failed", "module": module,
            "failed": report.failed, "rolled_back": report.rolled_back}


def _run(argv):
    import subprocess
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=30)
        return p.returncode, p.stdout
    except subprocess.TimeoutExpired:
        from .actuate import TIMED_OUT
        return TIMED_OUT, ""
    except OSError:
        return None, ""


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def main(argv: list[str] | None = None) -> int:
    import os
    p = argparse.ArgumentParser(prog="secubox-wakectl")
    p.add_argument("--root", default=str(DEFAULT_ROOT))
    sub = p.add_subparsers(dest="cmd", required=True)
    sp = sub.add_parser("wake")
    sp.add_argument("module")
    sp.add_argument("--json", action="store_true")
    args = p.parse_args(argv)
    if os.geteuid() != 0:
        print("wake doit être lancé en root (il pilote systemd/LXC).", file=sys.stderr)
        return 1
    rep = wake(args.module, root=Path(args.root), run=_run, now=_now_iso())
    if args.json:
        print(json.dumps(rep))
    else:
        print(f"wake[{args.module}]: {rep['status']}")
    return {"woken": 0, "already-up": 0, "refused": 3, "failed": 2}.get(rep["status"], 2)


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 4: Run to verify pass + mypy**

Run: `cd packages/secubox-profiles && python -m pytest tests/test_wake.py -v && python -m mypy --strict api/wake.py`
Expected: PASS (3); mypy no new errors.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-profiles/api/wake.py packages/secubox-profiles/tests/test_wake.py
git commit -m "feat(profiles): secubox-wakectl wake verb (start one module via the actuator) (ref #896)

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

## Task 3: Front signals (last-request + active-conns per vhost)

**Files:**
- Create: `packages/secubox-profiles/api/front_signals.py`
- Test: `packages/secubox-profiles/tests/test_front_signals.py`

**Interfaces:**
- Produces: `Signal` dataclass `{last_request_age: float | None, active_conns: int | None}`; `vhost_signals(*, reader) -> dict[str, Signal]` where `reader() -> dict[str, dict]` returns raw per-vhost `{"last_request_ts": float|None, "active_conns": int|None}`; `age_from(ts, now)` helper. `reader` is injected (production: reads sbxwaf stats JSON / nginx stub — pinned below); `None` fields mean "unknown" (never coerced to 0/idle).

- [ ] **Step 1: Write failing test**

```python
def test_vhost_signals_computes_age_and_passes_conns():
    from api.front_signals import vhost_signals
    raw = {"a.gk2": {"last_request_ts": 100.0, "active_conns": 0},
           "b.gk2": {"last_request_ts": None, "active_conns": 3}}
    sig = vhost_signals(reader=lambda: raw, now=lambda: 250.0)
    assert sig["a.gk2"].last_request_age == 150.0
    assert sig["a.gk2"].active_conns == 0
    assert sig["b.gk2"].last_request_age is None   # unknown ts stays unknown
    assert sig["b.gk2"].active_conns == 3

def test_unknown_conns_stay_none():
    from api.front_signals import vhost_signals
    raw = {"a.gk2": {"last_request_ts": 10.0}}   # no active_conns key
    sig = vhost_signals(reader=lambda: raw, now=lambda: 10.0)
    assert sig["a.gk2"].active_conns is None
```

- [ ] **Step 2: Run to verify fail**

Run: `cd packages/secubox-profiles && python -m pytest tests/test_front_signals.py -v`
Expected: FAIL — module missing.

- [ ] **Step 3: Implement front_signals.py**

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: profiles — signaux du front (last-request, connexions actives)
CyberMind — https://cybermind.fr

LECTURE SEULE. La source réelle (sbxwaf stats JSON à
/var/cache/secubox/waf/stats.json ou nginx stub_status) est injectée via
`reader`. Un champ None = indéterminé, JAMAIS coalescé en 0 (ne pas endormir
sur une sonde muette).
"""
from __future__ import annotations

import time
from dataclasses import dataclass


@dataclass(frozen=True)
class Signal:
    last_request_age: float | None
    active_conns: int | None


def vhost_signals(*, reader, now=time.monotonic) -> dict[str, Signal]:
    t = now()
    out: dict[str, Signal] = {}
    for vhost, raw in reader().items():
        ts = raw.get("last_request_ts")
        age = (t - ts) if isinstance(ts, (int, float)) else None
        conns = raw.get("active_conns")
        out[vhost] = Signal(last_request_age=age,
                            active_conns=conns if isinstance(conns, int) else None)
    return out
```

- [ ] **Step 4: Run to verify pass**

Run: `cd packages/secubox-profiles && python -m pytest tests/test_front_signals.py -v`
Expected: PASS (2).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-profiles/api/front_signals.py packages/secubox-profiles/tests/test_front_signals.py
git commit -m "feat(profiles): front signals (last-request age + active conns per vhost) (ref #896)

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

## Task 4: Sleeper decision logic (pure)

**Files:**
- Create: `packages/secubox-profiles/api/sleeper.py` (decision function only in this task)
- Test: `packages/secubox-profiles/tests/test_sleeper.py`

**Interfaces:**
- Consumes: `Manifest`, `lifecycle.is_sleepable/idle_threshold` (Task 1), `front_signals.Signal` (Task 3).
- Produces: `should_sleep(m: Manifest, sig: Signal | None, *, hint_idle: bool | None, now_up: bool) -> bool` — True iff `now_up` AND `is_sleepable(m)` AND `sig` present AND `sig.last_request_age` is not None AND `sig.last_request_age >= idle_threshold(m)` AND `sig.active_conns == 0` AND `hint_idle is not False` (a module `/idle` hint of `False` vetoes; `None`/`True` allow). Any unknown (sig None, age None, conns None) ⇒ False (never sleep on uncertainty).

- [ ] **Step 1: Write failing tests**

```python
from api.sleeper import should_sleep
from api.front_signals import Signal
from api.manifest import Manifest

def _m(lifecycle="on-demand", wake_class="normal", protected=False):
    return Manifest(id="x", category="infra", runtime="native", exposure="lan",
                    units=("x.service",), protected=protected,
                    lifecycle=lifecycle, wake_class=wake_class)

def test_sleeps_when_idle_and_no_conns():
    assert should_sleep(_m(), Signal(last_request_age=1000.0, active_conns=0),
                        hint_idle=None, now_up=True) is True

def test_not_sleep_if_conns_open():
    assert should_sleep(_m(), Signal(last_request_age=1000.0, active_conns=2),
                        hint_idle=None, now_up=True) is False

def test_not_sleep_if_recent_request():
    assert should_sleep(_m(), Signal(last_request_age=10.0, active_conns=0),
                        hint_idle=None, now_up=True) is False

def test_module_hint_vetoes_sleep():
    assert should_sleep(_m(), Signal(last_request_age=1000.0, active_conns=0),
                        hint_idle=False, now_up=True) is False

def test_unknown_signal_never_sleeps():
    assert should_sleep(_m(), None, hint_idle=None, now_up=True) is False
    assert should_sleep(_m(), Signal(last_request_age=None, active_conns=0),
                        hint_idle=None, now_up=True) is False
    assert should_sleep(_m(), Signal(last_request_age=1000.0, active_conns=None),
                        hint_idle=None, now_up=True) is False

def test_never_sleeps_non_sleepable_or_down():
    assert should_sleep(_m(lifecycle="always-on"),
                        Signal(1000.0, 0), hint_idle=None, now_up=True) is False
    assert should_sleep(_m(protected=True),
                        Signal(1000.0, 0), hint_idle=None, now_up=True) is False
    assert should_sleep(_m(), Signal(1000.0, 0), hint_idle=None, now_up=False) is False

def test_urgent_uses_longer_threshold():
    # 1000s idle: normal (threshold 900) sleeps, urgent (threshold 3600) does not
    assert should_sleep(_m(wake_class="normal"), Signal(1000.0, 0),
                        hint_idle=None, now_up=True) is True
    assert should_sleep(_m(wake_class="urgent"), Signal(1000.0, 0),
                        hint_idle=None, now_up=True) is False
```

- [ ] **Step 2: Run to verify fail**

Run: `cd packages/secubox-profiles && python -m pytest tests/test_sleeper.py -v`
Expected: FAIL — module missing.

- [ ] **Step 3: Implement should_sleep in sleeper.py**

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: profiles — secubox-sleeper : endort les modules on-demand idle
CyberMind — https://cybermind.fr

Décision PURE (should_sleep) + passe daemon (run_once, Task 5). Ne dort JAMAIS
sur une incertitude : toute sonde indéterminée (None) => on garde le module up.
"""
from __future__ import annotations

from .front_signals import Signal
from .lifecycle import idle_threshold, is_sleepable
from .manifest import Manifest


def should_sleep(m: Manifest, sig: Signal | None, *, hint_idle: bool | None,
                 now_up: bool) -> bool:
    if not now_up or not is_sleepable(m):
        return False
    if sig is None or sig.last_request_age is None or sig.active_conns is None:
        return False
    if hint_idle is False:            # a module /idle hint of False vetoes; None/True allow
        return False
    return sig.active_conns == 0 and sig.last_request_age >= idle_threshold(m)
```

- [ ] **Step 4: Run to verify pass + mypy**

Run: `cd packages/secubox-profiles && python -m pytest tests/test_sleeper.py -v && python -m mypy --strict api/sleeper.py api/front_signals.py`
Expected: PASS (8); mypy no new errors.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-profiles/api/sleeper.py packages/secubox-profiles/tests/test_sleeper.py
git commit -m "feat(profiles): sleeper decision logic (idle + 0-conns + hint, never on uncertainty) (ref #896)

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

## Task 5: Sleeper daemon pass (`run_once`) — stop idle modules via the actuator

**Files:**
- Modify: `packages/secubox-profiles/api/sleeper.py` (add `run_once`)
- Test: `packages/secubox-profiles/tests/test_sleeper.py` (add)

**Interfaces:**
- Consumes: `should_sleep` (Task 4), `manifest.load_all`, `observe.observe/is_on`, `apply.apply_plan` (STOP path), `front_signals.vhost_signals`, `diff.Change/STOP`.
- Produces: `run_once(*, root, manifests, actuals, signals, hints, run, observe, now, apply=True, wake_locked=frozenset()) -> list[str]` — returns the list of module ids it stopped. For each module: if `should_sleep(...)` and id not in `wake_locked`, build a STOP `Change` and `apply_plan` it (one at a time), audited. `signals`/`hints` are dicts keyed by module id (the caller maps vhost→module and probes `/idle`).

- [ ] **Step 1: Write failing test**

```python
def test_run_once_stops_only_idle_sleepable(tmp_path):
    from api.sleeper import run_once
    from api.front_signals import Signal
    from api.observe import Actual
    from api.manifest import Manifest
    manifests = {
        "idle1": Manifest(id="idle1", category="infra", runtime="native",
                          exposure="lan", units=("idle1.service",), lifecycle="on-demand"),
        "busy": Manifest(id="busy", category="infra", runtime="native",
                         exposure="lan", units=("busy.service",), lifecycle="on-demand"),
        "core": Manifest(id="core", category="infra", runtime="native",
                         exposure="lan", units=("core.service",), lifecycle="always-on"),
    }
    actuals = {k: Actual(enabled=True, active=True) for k in manifests}   # all up
    signals = {"idle1": Signal(1000.0, 0), "busy": Signal(5.0, 1), "core": Signal(1000.0, 0)}
    calls = []
    stopped = run_once(root=tmp_path, manifests=manifests, actuals=actuals,
                       signals=signals, hints={}, run=lambda a: (calls.append(a), (0, ""))[1],
                       observe=lambda m: Actual(enabled=False, active=False),
                       now="t", wake_locked=frozenset())
    assert stopped == ["idle1"]
    assert any(c[:2] == ["systemctl", "disable"] for c in calls)

def test_run_once_skips_wake_locked(tmp_path):
    from api.sleeper import run_once
    from api.front_signals import Signal
    from api.observe import Actual
    from api.manifest import Manifest
    manifests = {"idle1": Manifest(id="idle1", category="infra", runtime="native",
                 exposure="lan", units=("idle1.service",), lifecycle="on-demand")}
    stopped = run_once(root=tmp_path, manifests=manifests,
                       actuals={"idle1": Actual(enabled=True, active=True)},
                       signals={"idle1": Signal(1000.0, 0)}, hints={},
                       run=lambda a: (0, ""), observe=lambda m: Actual(enabled=False, active=False),
                       now="t", wake_locked=frozenset({"idle1"}))
    assert stopped == []
```

- [ ] **Step 2: Run to verify fail**

Run: `cd packages/secubox-profiles && python -m pytest tests/test_sleeper.py -k run_once -v`
Expected: FAIL — `run_once` missing.

- [ ] **Step 3: Implement run_once**

Add to `api/sleeper.py` (imports at top: `from . import apply as _apply`, `from .audit import AUDIT_LOG`, `from .diff import STOP, Change`, `from .observe import is_on`, `from .snapshot import SNAP_DIR`, `from pathlib import Path`):

```python
def run_once(*, root, manifests, actuals, signals, hints, run, observe, now,
             apply: bool = True, wake_locked=frozenset()) -> list[str]:
    """Une passe : arrête chaque module sleepable devenu idle (un à la fois,
    via l'actionneur 0.7.0). Retourne les ids arrêtés. wake_locked = ids en
    cours de réveil (à ne jamais stopper)."""
    stopped: list[str] = []
    for mid, m in sorted(manifests.items()):
        if mid in wake_locked:
            continue
        a = actuals.get(mid)
        now_up = bool(a is not None and is_on(a))
        if not should_sleep(m, signals.get(mid), hint_idle=hints.get(mid), now_up=now_up):
            continue
        plan = [Change(mid, STOP, "idle-sleep", m.priority)]
        report = _apply.apply_plan(plan, manifests, {mid: a}, run=run, observe=observe,
                                   now=now, routes={}, snap_root=SNAP_DIR,
                                   audit_path=AUDIT_LOG, apply=apply)
        if report.status == "applied" and mid in report.changed:
            stopped.append(mid)
    return stopped
```

- [ ] **Step 4: Run to verify pass + full sleeper suite + mypy**

Run: `cd packages/secubox-profiles && python -m pytest tests/test_sleeper.py -v && python -m mypy --strict api/sleeper.py`
Expected: PASS; mypy no new errors.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-profiles/api/sleeper.py packages/secubox-profiles/tests/test_sleeper.py
git commit -m "feat(profiles): sleeper run_once — stop idle sleepable modules via the actuator (ref #896)

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

## Task 6: `secubox-waker` activator service (splash + one-wake lock + budget)

**Files:**
- Create: `packages/secubox-profiles/api/waker.py`
- Create: `packages/secubox-profiles/templates/waking.html`
- Test: `packages/secubox-profiles/tests/test_waker.py`

**Interfaces:**
- Consumes: `manifest.load_all`, `observe.observe/is_on`, `lifecycle.wake_budget/effective_lifecycle`, the wake path (calls `secubox-wakectl` over sudo, per webui→ctl).
- Produces: FastAPI app on `/run/secubox/waker.sock`. `GET /_wake/{vhost}` (nginx internal redirect target): resolves vhost→module (route map), acquires per-module `asyncio.Lock`, if the module is observed UP → `200` with header `X-Sbx-Wake: up` (nginx retries the real backend); else fires the wake once (background) and returns `503` + `Retry-After` + the `waking.html` splash (`Cache-Control: no-store`) showing the budget. A per-module **wake-rate cap** (min interval between wake attempts) prevents wake storms.

- [ ] **Step 1: Write failing tests**

```python
from fastapi.testclient import TestClient

def test_waker_up_backend_signals_proxy(monkeypatch, tmp_path):
    import api.waker as waker
    from api.observe import Actual
    monkeypatch.setenv("SECUBOX_PROFILES_ROOT", str(tmp_path))
    (tmp_path / "modules.d").mkdir()
    (tmp_path / "modules.d" / "demo.toml").write_text(
        'id="demo"\ncategory="infra"\nruntime="native"\nexposure="public"\n'
        'units=["demo.service"]\nlifecycle="on-demand"\n[portal]\ndomain="demo.gk2"\n')
    monkeypatch.setattr(waker, "_observe_one", lambda m: Actual(enabled=True, active=True))
    c = TestClient(waker.app)
    r = c.get("/_wake/demo.gk2")
    assert r.status_code == 200 and r.headers.get("X-Sbx-Wake") == "up"

def test_waker_down_backend_serves_splash_and_fires_one_wake(monkeypatch, tmp_path):
    import api.waker as waker
    from api.observe import Actual
    monkeypatch.setenv("SECUBOX_PROFILES_ROOT", str(tmp_path))
    (tmp_path / "modules.d").mkdir()
    (tmp_path / "modules.d" / "demo.toml").write_text(
        'id="demo"\ncategory="infra"\nruntime="native"\nexposure="public"\n'
        'units=["demo.service"]\nlifecycle="on-demand"\n[portal]\ndomain="demo.gk2"\n')
    monkeypatch.setattr(waker, "_observe_one", lambda m: Actual(enabled=False, active=False))
    fired = []
    monkeypatch.setattr(waker, "_fire_wake", lambda mid: fired.append(mid))
    c = TestClient(waker.app)
    r = c.get("/_wake/demo.gk2")
    assert r.status_code == 503
    assert "Retry-After" in r.headers and r.headers["Cache-Control"] == "no-store"
    assert fired == ["demo"]                 # exactly one wake fired

def test_waker_unknown_vhost_404(monkeypatch, tmp_path):
    import api.waker as waker
    monkeypatch.setenv("SECUBOX_PROFILES_ROOT", str(tmp_path))
    (tmp_path / "modules.d").mkdir()
    c = TestClient(waker.app)
    assert c.get("/_wake/nope.gk2").status_code == 404
```

- [ ] **Step 2: Run to verify fail**

Run: `cd packages/secubox-profiles && python -m pytest tests/test_waker.py -v`
Expected: FAIL — `api.waker` missing.

- [ ] **Step 3: Implement waker.py + waking.html**

`templates/waking.html` (minimal branded splash; the panel guidelines govern final styling — cyan hybrid-dark, Courier Prime):

```html
<!doctype html><html lang="fr"><head><meta charset="utf-8">
<meta http-equiv="refresh" content="{retry}">
<title>Démarrage — {module}</title>
<style>body{background:#0a0a0f;color:#00d4ff;font-family:"Courier Prime",monospace;
text-align:center;padding-top:20vh}.b{color:#c9a84c}</style></head>
<body><h1>⏳ {module} se réveille…</h1>
<p>Budget estimé : <span class="b">~{budget}s</span>. Cette page se recharge seule.</p>
</body></html>
```

`api/waker.py`:

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: profiles — secubox-waker : activator (réveil-sur-accès + splash)
CyberMind — https://cybermind.fr

nginx route un vhost on-demand DOWN vers /_wake/<vhost>. Le waker : résout
vhost->module, prend un verrou par-module (UN seul réveil pour N requêtes
concurrentes), et soit signale « up » (nginx re-proxifie), soit tire le réveil
(sudo->secubox-wakectl) et sert le splash 503+Retry-After. Cap de fréquence de
réveil contre les tempêtes. Ne pilote JAMAIS le système en direct (webui->ctl).
"""
from __future__ import annotations

import asyncio
import os
import subprocess
import time
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, Response

from . import cli as _cli
from .lifecycle import effective_lifecycle, wake_budget
from .manifest import load_all
from .observe import is_on, observe as _observe_one

DEFAULT_ROOT = Path("/etc/secubox")
_TEMPLATE = (Path(__file__).resolve().parent.parent / "templates" / "waking.html")
_WAKE_MIN_INTERVAL_S = 20.0

_locks: dict[str, asyncio.Lock] = {}
_last_wake: dict[str, float] = {}


def _root() -> Path:
    return Path(os.environ.get("SECUBOX_PROFILES_ROOT", str(DEFAULT_ROOT)))


def _lock(mid: str) -> asyncio.Lock:
    lk = _locks.get(mid)
    if lk is None:
        lk = asyncio.Lock(); _locks[mid] = lk
    return lk


def _resolve(vhost: str, manifests: dict) -> str | None:
    for mid, m in manifests.items():
        if m.portal_domain == vhost:
            return mid
    return None


def _fire_wake(mid: str) -> None:
    # webui->ctl : le réveil privilégié passe par le ctl root, jamais en process.
    subprocess.Popen(["sudo", "-n", "/usr/sbin/secubox-wakectl", "wake", mid, "--json"],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _splash(module: str, budget: float, retry: int) -> HTMLResponse:
    html = _TEMPLATE.read_text(encoding="utf-8").format(
        module=module, budget=int(budget), retry=retry)
    return HTMLResponse(html, status_code=503,
                        headers={"Retry-After": str(retry), "Cache-Control": "no-store"})


def create_app() -> FastAPI:
    app = FastAPI(title="SecuBox Waker", docs_url=None, redoc_url=None)

    @app.get("/_wake/{vhost}")
    async def wake_vhost(vhost: str):
        manifests = load_all(_root() / "modules.d")
        mid = _resolve(vhost, manifests)
        if mid is None:
            return Response(status_code=404)
        m = manifests[mid]
        if effective_lifecycle(m) in ("always-on", "manual"):
            return Response(status_code=502)   # not a sleepable vhost -> real error
        if is_on(_observe_one(m)):
            return Response(status_code=200, headers={"X-Sbx-Wake": "up"})
        async with _lock(mid):
            now = time.monotonic()
            if now - _last_wake.get(mid, 0.0) >= _WAKE_MIN_INTERVAL_S:
                _last_wake[mid] = now
                _fire_wake(mid)
            budget = wake_budget(m)
            return _splash(mid, budget, retry=max(3, int(budget / 5)))

    return app


app = create_app()
```

- [ ] **Step 4: Run to verify pass + mypy**

Run: `cd packages/secubox-profiles && python -m pytest tests/test_waker.py -v && python -m mypy --strict api/waker.py`
Expected: PASS (3); mypy no new errors. (Tests monkeypatch `_observe_one` and `_fire_wake`, so no real subprocess/observe runs.)

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-profiles/api/waker.py packages/secubox-profiles/templates/waking.html packages/secubox-profiles/tests/test_waker.py
git commit -m "feat(profiles): secubox-waker activator — splash + one-wake lock + rate cap (ref #896)

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

## Task 7: nginx `@waker` snippet generator (`secubox-wakectl nginx-sync`)

**Files:**
- Create: `packages/secubox-profiles/api/nginxgen.py`
- Modify: `packages/secubox-profiles/api/wake.py` (add `nginx-sync` subcommand)
- Test: `packages/secubox-profiles/tests/test_nginxgen.py`

**Interfaces:**
- Consumes: `manifest.load_all`, `lifecycle.effective_lifecycle`.
- Produces: `render_snippet(m: Manifest, *, waker_sock="/run/secubox/waker.sock") -> str | None` (returns the nginx `error_page`→`@waker` snippet for a sleepable vhost with a `portal_domain`, else `None`); `sync_snippets(*, manifests, out_dir: Path) -> list[str]` (writes `<domain>.waker.conf` for each sleepable portal module, removes stale ones, returns the domains written).

- [ ] **Step 1: Write failing tests**

```python
def test_render_only_for_sleepable_portal(tmp_path):
    from api.nginxgen import render_snippet
    from api.manifest import Manifest
    on_demand = Manifest(id="d", category="infra", runtime="native", exposure="public",
                         units=("d.service",), portal_domain="d.gk2", lifecycle="on-demand")
    always = Manifest(id="a", category="infra", runtime="native", exposure="public",
                      units=("a.service",), portal_domain="a.gk2", lifecycle="always-on")
    noportal = Manifest(id="n", category="infra", runtime="native", exposure="lan",
                        units=("n.service",), lifecycle="on-demand")
    assert render_snippet(on_demand) is not None and "@waker" in render_snippet(on_demand)
    assert render_snippet(always) is None
    assert render_snippet(noportal) is None

def test_sync_writes_and_prunes(tmp_path):
    from api.nginxgen import sync_snippets
    from api.manifest import Manifest
    out = tmp_path / "snips"; out.mkdir()
    (out / "stale.gk2.waker.conf").write_text("old")   # should be pruned
    manifests = {"d": Manifest(id="d", category="infra", runtime="native", exposure="public",
                 units=("d.service",), portal_domain="d.gk2", lifecycle="on-demand")}
    written = sync_snippets(manifests=manifests, out_dir=out)
    assert written == ["d.gk2"]
    assert (out / "d.gk2.waker.conf").exists()
    assert not (out / "stale.gk2.waker.conf").exists()
```

- [ ] **Step 2: Run to verify fail**

Run: `cd packages/secubox-profiles && python -m pytest tests/test_nginxgen.py -v`
Expected: FAIL — module missing.

- [ ] **Step 3: Implement nginxgen.py**

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: profiles — génération des snippets nginx @waker (réveil-sur-accès)
CyberMind — https://cybermind.fr

Un vhost sleepable routé (portal_domain) reçoit un error_page 502/504 -> @waker
(le waker sert le splash + tire le réveil). always-on/manual/sans-portal : rien
(un 502 reste un 502). Écrit atomiquement, purge les snippets orphelins.
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

from .lifecycle import effective_lifecycle
from .manifest import Manifest

_SNIPPET = """# generated by secubox-wakectl nginx-sync — do not edit
error_page 502 504 = @sbx_waker;
location @sbx_waker {{
    internal;
    proxy_pass http://unix:{sock}:/_wake/{domain};
    proxy_set_header Host $host;
}}
"""


def render_snippet(m: Manifest, *, waker_sock: str = "/run/secubox/waker.sock") -> str | None:
    if m.portal_domain is None or effective_lifecycle(m) not in ("eager", "on-demand"):
        return None
    return _SNIPPET.format(sock=waker_sock, domain=m.portal_domain)


def _write_atomic(path: Path, text: str) -> None:
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.replace(tmp, path)
    except BaseException:
        try: os.unlink(tmp)
        except FileNotFoundError: pass
        raise


def sync_snippets(*, manifests: dict[str, Manifest], out_dir: Path,
                  waker_sock: str = "/run/secubox/waker.sock") -> list[str]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    want: dict[str, str] = {}
    for m in manifests.values():
        snip = render_snippet(m, waker_sock=waker_sock)
        if snip is not None and m.portal_domain is not None:
            want[m.portal_domain] = snip
    for dom, snip in want.items():
        _write_atomic(out_dir / f"{dom}.waker.conf", snip)
    for p in out_dir.glob("*.waker.conf"):
        if p.name[: -len(".waker.conf")] not in want:
            p.unlink()
    return sorted(want)
```

- [ ] **Step 4: Add the `nginx-sync` subcommand to wake.py**

In `api/wake.py` `main()`, add a second subparser (root-gated, like `wake`): `nginx-sync` calls `nginxgen.sync_snippets(manifests=load_all(root/"modules.d"), out_dir=Path("/etc/nginx/secubox-waker.d"))` and prints the domains; wire an nginx `reload` via the existing pattern (or print a note that `systemctl reload nginx` is required — reload is done by the caller ctl/postinst). Show the exact code:

```python
    sp2 = sub.add_parser("nginx-sync")
    sp2.add_argument("--out", default="/etc/nginx/secubox-waker.d")
    ...
    if args.cmd == "nginx-sync":
        from . import nginxgen
        from .manifest import load_all
        doms = nginxgen.sync_snippets(manifests=load_all(Path(args.root) / "modules.d"),
                                      out_dir=Path(args.out))
        print(f"nginx-sync: {len(doms)} vhost(s) — {', '.join(doms) or 'aucun'}")
        return 0
```

- [ ] **Step 5: Run to verify pass + mypy**

Run: `cd packages/secubox-profiles && python -m pytest tests/test_nginxgen.py -v && python -m mypy --strict api/nginxgen.py`
Expected: PASS (2); mypy no new errors.

- [ ] **Step 6: Commit**

```bash
git add packages/secubox-profiles/api/nginxgen.py packages/secubox-profiles/api/wake.py packages/secubox-profiles/tests/test_nginxgen.py
git commit -m "feat(profiles): nginx @waker snippet generator + nginx-sync verb (ref #896)

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

## Task 8: Sleeper daemon runtime (loop) + `/idle` hint probe + wake-lock source

**Files:**
- Modify: `packages/secubox-profiles/api/sleeper.py` (add async loop `serve()` + hint probe + signal wiring)
- Test: `packages/secubox-profiles/tests/test_sleeper.py` (add loop-tick test with injected clock)

**Interfaces:**
- Consumes: `run_once` (Task 5), `front_signals.vhost_signals` (Task 3), `observe.observe_all`, `manifest.load_all`.
- Produces: `async def serve(*, root, interval, sleep, observe_all, signal_reader, hint_probe, run, now, tick_limit=None)` — each tick: load manifests, `observe_all`, map vhost signals → module signals (via `portal_domain`), probe `/idle` for modules that expose it, read the wake-lock set (modules woken within the last interval — from the waker's `_last_wake`, shared via a small state file `/run/secubox/waker-active.json`), call `run_once`. `tick_limit` bounds the loop for tests.

- [ ] **Step 1: Write failing test** (inject a fake clock + one-shot readers; assert one idle module is stopped in a single tick)

```python
def test_serve_one_tick_stops_idle(tmp_path):
    import asyncio
    from api.sleeper import serve
    from api.observe import Actual
    from api.manifest import Manifest
    (tmp_path / "modules.d").mkdir()
    (tmp_path / "modules.d" / "d.toml").write_text(
        'id="d"\ncategory="infra"\nruntime="native"\nexposure="public"\n'
        'units=["d.service"]\nlifecycle="on-demand"\n[portal]\ndomain="d.gk2"\n')
    calls = []
    async def go():
        await serve(root=tmp_path, interval=0, sleep=lambda s: asyncio.sleep(0),
                    observe_all=lambda ms, routes=None: {"d": Actual(enabled=True, active=True)},
                    signal_reader=lambda: {"d.gk2": {"last_request_ts": 0.0, "active_conns": 0}},
                    hint_probe=lambda mid, m: None,
                    run=lambda a: (calls.append(a), (0, ""))[1],
                    observe=lambda m: Actual(enabled=False, active=False),
                    now=lambda: 100000.0, tick_limit=1)
    asyncio.run(go())
    assert any(c[:2] == ["systemctl", "disable"] for c in calls)
```

- [ ] **Step 2: Run to verify fail** — `serve` missing.

- [ ] **Step 3: Implement `serve`** (map vhost→module via `portal_domain`; read wake-lock file best-effort; call `run_once`). Full code:

```python
async def serve(*, root, interval, sleep, observe_all, signal_reader, hint_probe,
                run, observe, now, tick_limit=None) -> None:
    import json
    from pathlib import Path as _P
    from .front_signals import vhost_signals
    from .manifest import load_all
    ticks = 0
    while tick_limit is None or ticks < tick_limit:
        try:
            manifests = load_all(_P(root) / "modules.d")
            actuals = observe_all(manifests, routes=None)
            vsig = vhost_signals(reader=signal_reader, now=now)
            signals = {mid: vsig[m.portal_domain] for mid, m in manifests.items()
                       if m.portal_domain in vsig}
            hints = {}
            for mid, m in manifests.items():
                h = hint_probe(mid, m)
                if h is not None:
                    hints[mid] = h
            try:
                locked = frozenset(json.loads(_P("/run/secubox/waker-active.json").read_text()))
            except (OSError, ValueError):
                locked = frozenset()
            run_once(root=root, manifests=manifests, actuals=actuals, signals=signals,
                     hints=hints, run=run, observe=observe, now=now() if callable(now) else now,
                     wake_locked=locked)
        except Exception:
            pass
        ticks += 1
        if tick_limit is None or ticks < tick_limit:
            await sleep(interval)
```

Note for the implementer: `now()` is called for the audit `now` string only if callable — pass an ISO-string producer in production; the test passes a float clock for `vhost_signals` and a separate audit stamp is acceptable (adjust the `now=` handling so the audit stamp is a string; keep the float clock for age math). Resolve this cleanly (two params: `now` float clock for signals, `stamp` string for audit) if the single-param form is awkward — the test only asserts the stop happened.

- [ ] **Step 4: Run to verify pass + mypy** — PASS; no new mypy errors.

- [ ] **Step 5: Commit**

```bash
git commit -am "feat(profiles): sleeper serve loop + /idle hint + wake-lock coordination (ref #896)

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

## Task 9: systemd units + sudoers + waker active-state file

**Files:**
- Create: `packages/secubox-profiles/debian/secubox-waker.service`, `secubox-sleeper.service`, `secubox-sleeper.timer`
- Create/modify: `packages/secubox-profiles/sudoers.d/secubox-profiles` (add the waker→wakectl grant)
- Modify: `packages/secubox-profiles/api/waker.py` (persist `_last_wake` to `/run/secubox/waker-active.json` for the sleeper)
- Test: `packages/secubox-profiles/tests/test_waker.py` (assert the active-state file is written on wake)

**Interfaces:**
- Produces: `secubox-waker.service` (User=secubox, ExecStart uvicorn on `/run/secubox/waker.sock`, `NoNewPrivileges=false` so it can `sudo -n wakectl`, RuntimeDirectory=secubox with `RuntimeDirectoryPreserve=yes`); `secubox-sleeper.service`+`.timer` (root or secubox+sudo; runs `python -m api.sleeper` `serve` one pass per timer fire, or a long-running service — pick service form to keep the interval in-process). Sudoers exact-command line: `secubox ALL=(root) NOPASSWD: /usr/bin/systemd-run --wait --pipe --collect --quiet /usr/sbin/secubox-wakectl wake *` — **but** wildcard on the module is a flag-injection risk; instead grant the fixed prefix without `--` user args: use `secubox ALL=(root) NOPASSWD: /usr/sbin/secubox-wakectl wake, /usr/sbin/secubox-wakectl wake [A-Za-z0-9-]*` is not valid sudoers globbing — resolve by having the waker pass the module as the ONLY arg after `wake` and granting `secubox ALL=(root) NOPASSWD: /usr/sbin/secubox-wakectl wake ""` is also wrong. **Correct approach (implement this):** wakectl validates the module against `load_all` (rejects anything not a known id) and the sudoers grants `secubox ALL=(root) NOPASSWD: /usr/sbin/secubox-wakectl wake *` with `wakectl` treating its `module` arg as data only (argparse positional, never shelled) — document that the `*` is a single positional consumed safely. Validate with `visudo -c`.

- [ ] **Step 1: Write failing test** — waker writes `/run/secubox/waker-active.json` containing the module on wake (monkeypatch the path to tmp).
- [ ] **Step 2..4:** implement the active-state write in `_fire_wake`/the route (append mid with timestamp, prune entries older than the sleeper interval), add the units + sudoers; `visudo -c` the sudoers; run tests.
- [ ] **Step 5: Commit** `feat(profiles): waker/sleeper systemd units + sudoers + wake-active state (ref #896)`.

(Full unit/sudoers text is short and mechanical; the implementer writes it following the existing `secubox-profiles.service` + `sudoers.d/secubox-profiles` shipped in 0.6.x as the template — same User=secubox, NoNewPrivileges=false, RuntimeDirectoryPreserve=yes, systemd-run wrapper for the ProtectSystem=strict case.)

---

## Task 10: webui — lifecycle/wake_class/sleep-state + manual sleep/wake

**Files:**
- Modify: `packages/secubox-profiles/api/web.py` (status payload gains `lifecycle`,`wake_class`,`sleep_state`; add `POST /api/v1/profiles/wake` and `POST /api/v1/profiles/sleep` delegating to wakectl/profilectl via the webui→ctl path)
- Modify: `packages/secubox-profiles/www/profiles/index.html` (panel: show the fields + manual buttons)
- Test: `packages/secubox-profiles/tests/test_web.py` (add)

**Interfaces:**
- Consumes: `_build_status_payload` (extend), `_run_ctl_json`-style delegation.
- Produces: status rows include `lifecycle`,`wake_class`, and `sleep_state` ∈ `{"up","asleep","waking","n/a"}` (n/a for always-on/manual); `POST /wake {module}` → `sudo systemd-run … secubox-wakectl wake <module> --json`; `POST /sleep {module}` → `profilectl apply --only <module>` stop path (or a `wakectl sleep` verb) — reuse the existing `_run_ctl_json` pattern + `_apply_lock`.

- [ ] **Step 1: Write failing tests** — status payload includes the new fields for a module; `POST /wake` delegates to the fixed ctl argv (fake `_ctl_run`), `POST /sleep` likewise; unknown module 404; both under `_apply_lock`.
- [ ] **Step 2..4:** extend `_build_status_payload` to read `m.lifecycle`/`m.wake_class` and derive `sleep_state` from the observed `is_on` + `effective_lifecycle`; add the two routes mirroring `apply_active`/`rollback_active` (JWT, `_apply_lock`, fixed sudo argv); update `index.html` to render the columns + buttons; run `tests/test_web.py`.
- [ ] **Step 5: Commit** `feat(profiles): panel lifecycle/wake_class/sleep-state + manual sleep/wake (ref #896)`.

---

## Task 11: watchdog exclusion + boot reconciliation

**Files:**
- Modify: `packages/secubox-profiles/api/lifecycle.py` (add `boot_should_start(m) -> bool`: True for `always-on`/`eager`, False for `on-demand`/`manual`; `watchdog_should_manage(m) -> bool`: False for sleepable-and-currently-intended-asleep)
- Modify: the boot reconciler / watchdog integration point (identify the secubox-watchdog config or a hook; ship an exclusion list generated from manifests)
- Test: `packages/secubox-profiles/tests/test_lifecycle.py` (add), plus an integration note.

**Interfaces:**
- Produces: `boot_should_start(m) -> bool`; a generated watchdog-exclusion list (module ids / containers that are `on-demand`) so `secubox-watchdog` does not auto-revive an intentionally-asleep container (mirrors how streamlit sleepers are excluded today).

- [ ] **Step 1: Write failing tests** for `boot_should_start` (always-on/eager True; on-demand/manual False) and the exclusion generator (on-demand containers listed).
- [ ] **Step 2..4:** implement the pure helpers + the exclusion-list generator (a `wakectl watchdog-sync` verb writing the exclusion file the watchdog reads); verify against the watchdog's actual exclusion mechanism (read `secubox-watchdog` config first — do NOT invent a format; match what it already consumes for streamlit sleepers).
- [ ] **Step 5: Commit** `feat(profiles): boot reconciliation + watchdog exclusion for on-demand (ref #896)`.

**Implementer note:** before coding the exclusion format, read the live/source `secubox-watchdog` to learn how streamlit sleepers are already excluded and reuse that mechanism; if it's incompatible, report DONE_WITH_CONCERNS rather than inventing a parallel one.

---

## Task 12: packaging, docs, version bump, full suite

**Files:**
- Modify: `packages/secubox-profiles/debian/{control,rules,install,postinst}` (ship the new modules, `templates/waking.html`, units, sudoers, nginx snippet dir `/etc/nginx/secubox-waker.d`, entry point `secubox-wakectl`; enable+start `secubox-waker` + `secubox-sleeper.timer`; `nginx-sync` + `watchdog-sync` in postinst; reload nginx)
- Modify: `packages/secubox-profiles/debian/changelog` (minor bump), `README.md`, `wiki/*`, `.claude/WEBUI-PANEL-GUIDELINES.md` (splash), `.claude/MODULE-COMPLIANCE.md` (lifecycle policy)
- Test: full suite + mypy.

- [ ] **Step 1:** wire the console_script `secubox-wakectl = api.wake:main` and the two services into `debian/`; nginx must `include /etc/nginx/secubox-waker.d/*.conf;` within each on-demand `server{}` — generated snippet is included per-vhost (document the include mechanism; if vhosts are generated elsewhere, add the include there).
- [ ] **Step 2:** changelog stanza (bump minor from 0.7.0 → 0.8.0), README + wiki: the lifecycle policy, the waker/sleeper, the pilot procedure.
- [ ] **Step 3:** `cd packages/secubox-profiles && python -m pytest tests/ -q && python -m mypy --strict api/` — full green, mypy at baseline (+ only the new untyped-`run` idiom deltas, consistent with 0.7.0).
- [ ] **Step 4: Commit** `feat(profiles): package waker/sleeper + lifecycle policy, v0.8.0 (ref #896)`.

---

## PIVOT (2026-07-20): wake trigger = sbxwaf, not nginx

**Task 7 (nginx `@waker`) is SUPERSEDED** — `api/nginxgen.py`/`nginx-sync` stay in
the tree but are NOT wired. The sleeper's route-removing stop (T5/T8) is CORRECT.
Two new tasks replace the nginx path; T12 wires them (not nginx).

---

## Task 13: `waf-sync` — on-demand-vhost-list generator (secubox-profiles)

**Files:** Create `packages/secubox-profiles/api/wafsync.py`; modify `api/wake.py` `main()` (add `waf-sync` subcommand); Test `tests/test_wafsync.py`.

**Interfaces:**
- Produces: `ondemand_vhosts(manifests: dict[str, Manifest]) -> list[str]` — sorted `portal_domain`s whose module has `effective_lifecycle(m) ∈ {eager, on-demand}`. `write_ondemand(*, manifests, out_path: Path) -> list[str]` — atomically writes the JSON array to `out_path` (default production `/etc/secubox/waf/on-demand-vhosts.json`), returns the list. `secubox-wakectl waf-sync [--out PATH]` verb (read-config→write, un-root-gated like `nginx-sync`).

- [ ] **Step 1: failing tests** (`tests/test_wafsync.py`, WITH SPDX header):
```python
def test_ondemand_vhosts_selects_sleepable_portals():
    from api.wafsync import ondemand_vhosts
    from api.manifest import Manifest
    def m(mid, lc, dom):
        return Manifest(id=mid, category="infra", runtime="native", exposure="public",
                        units=(f"{mid}.service",), portal_domain=dom, lifecycle=lc)
    ms = {"a": m("a","on-demand","a.gk2"), "b": m("b","always-on","b.gk2"),
          "c": m("c","eager","c.gk2"), "d": m("d","on-demand",None)}
    assert ondemand_vhosts(ms) == ["a.gk2", "c.gk2"]   # sorted; b=always-on, d=no portal

def test_write_ondemand_atomic(tmp_path):
    from api.wafsync import write_ondemand
    from api.manifest import Manifest
    import json
    ms = {"a": Manifest(id="a", category="infra", runtime="native", exposure="public",
          units=("a.service",), portal_domain="a.gk2", lifecycle="on-demand")}
    out = tmp_path / "on-demand-vhosts.json"
    assert write_ondemand(manifests=ms, out_path=out) == ["a.gk2"]
    assert json.loads(out.read_text()) == ["a.gk2"]
    assert list(tmp_path.glob("*.tmp")) == []
```

- [ ] **Step 2-4:** implement `api/wafsync.py` mirroring `api/nginxgen.py`'s atomic-write style (`effective_lifecycle` gate, `sorted`, temp+rename); add the `waf-sync` subcommand to `wake.py` `main()` (same shape as `nginx-sync`, default `--out /etc/secubox/waf/on-demand-vhosts.json`). RED→GREEN; full suite + mypy-vs-baseline.
- [ ] **Step 5: Commit** `feat(profiles): waf-sync — on-demand-vhost list for sbxwaf wake trigger (ref #896)`.

---

## Task 14: sbxwaf on-demand → waker branch (secubox-toolbox-ng, Go)

**Files:** in `packages/secubox-toolbox-ng/cmd/sbxwaf/`: create `ondemand.go`; modify `main.go` (`handler()` 421 site + `--on-demand-vhosts` flag + per-request `Maybe()` + wire `srv.onDemand`); modify the visit-stats exclusion; create `wakerproxy.go` (cached unix-socket reverse proxy); Test: `ondemand_test.go` + extend `main_test.go`. Also `packages/secubox-waf-ng/debian/secubox-waf-ng.apparmor` (egress to `/run/secubox/waker.sock`) + the worker unit ExecStart (`--on-demand-vhosts /etc/secubox/waf/on-demand-vhosts.json`).

**Interfaces (mirror the existing `Routes`/`Rules` pattern — READ `routes.go` first):**
- `OnDemand` type: `sync.RWMutex` + `map[string]bool`; `LoadOnDemand(path) *OnDemand` using `reload.NewWatcher(0, target)` + `loadOnDemandJSON(path) map[string]bool` (JSON array of vhosts); `(*OnDemand).Maybe()`; `(*OnDemand).Contains(host string) bool` (lowercase+trim like `Routes.Lookup`).
- `wakerProxy()`: a single lazily-built, cached `*httputil.ReverseProxy` whose `Transport.DialContext` dials `net.Dial("unix", "/run/secubox/waker.sock")` and whose Director rewrites `req.URL.Path = "/_wake/" + host` (scheme http, dummy Host). Build once, reuse (per the codebase's "build-once" discipline).
- Handler branch at the 421 site (`main.go`, after `ip, port, ok := s.routeLookup(host); if !ok {`): `if s.onDemand != nil && s.onDemand.Contains(host) { s.wakerProxy().ServeHTTP(w, r); return }` BEFORE the existing `http.Error(...421...)`.

- [ ] **Step 1: failing Go tests** (`ondemand_test.go`): `TestOnDemandContains` (load a JSON set, Contains true/false, case-insensitive); extend `main_test.go` with `TestOnDemandProxiesToWaker` — a request for a host in the on-demand set but absent from routes reverse-proxies to a stub unix-socket server (not 421); and confirm `TestProxyUnmapped` still 421s for a host NOT in the on-demand set.
- [ ] **Step 2: run** `cd packages/secubox-toolbox-ng && go test ./cmd/sbxwaf/ -run 'OnDemand|Unmapped|Waker' -v` → RED.
- [ ] **Step 3: implement** `ondemand.go` + `wakerproxy.go` + the `main.go` branch + flag + `Maybe()` wiring + exclude the waker-splash status from the legitimate-visit tally (the `sr.status != 403 && sr.status != 421` site — add the splash status or exclude the waker path). Keep the unix-socket proxy built-once/cached.
- [ ] **Step 4: run** `cd packages/secubox-toolbox-ng && go test ./cmd/sbxwaf/ -v` (all green, incl. existing route/rule tests) + `go vet ./cmd/sbxwaf/`. (Note: `debian/rules` skips dh_auto_test for the arm64 cross-build; run `go test` on the host arch manually.)
- [ ] **Step 5:** AppArmor egress rule for `/run/secubox/waker.sock` in `secubox-waf-ng.apparmor`; add `--on-demand-vhosts /etc/secubox/waf/on-demand-vhosts.json` to `secubox-waf-ng-worker@.service` ExecStart.
- [ ] **Step 6: Commit** `feat(waf-ng): sbxwaf routes on-demand vhosts to the waker instead of 421 (ref #896)`.

**Implementer note:** READ `routes.go` (Routes/reload pattern), `main.go` `handler()` (the 421 site + stats recorder), and `rules.go` (the Rules mirror) BEFORE coding — match their exact idioms. If the unix-socket reverse-proxy or the `reload.Watcher` wiring differs from this sketch, follow the REAL code and note the adaptation. Deploy: rebuild `sbxwaf`, restart BOTH `secubox-waf-ng-worker@1` + `@2` (never SIGHUP).

---

## Post-implementation (controller)

1. Ensure PR #894 (0.7.0) is merged so this branch has the actuator; rebase if needed.
2. Build the .deb, deploy to gk2.
3. **Pilot ONE low-risk on-demand service** (e.g. a rarely-used dashboard): set `lifecycle="on-demand"`, `nginx-sync`, reload nginx; drive: idle → sleeper stops it (verify RAM freed, container down); hit its vhost → splash shown → wakes → serves; confirm gateway/other vhosts and the wake-lock (one start under concurrent hits) behave. Only then widen.

---

## Self-Review

**Spec coverage:** policy schema → T1; wakectl → T2; front signals → T3; sleeper (decision+pass+loop) → T4/T5/T8; waker (splash+lock+budget+rate-cap) → T6; nginx integration → T7; systemd/sudoers → T9; webui → T10; watchdog exclusion + boot reconciliation → T11; packaging/docs/pilot → T12. All spec sections mapped.

**Placeholder scan:** T1–T7 carry complete code. T8–T12 are specified with interfaces, exact files, test intents, and the key code; T9/T11 deliberately defer *format-matching* details (sudoers exact line, watchdog exclusion format) to the implementer WITH an explicit instruction to read the existing shipped template / watchdog mechanism first and report rather than invent — because inventing a parallel format is the failure mode. These are integration tasks whose "code" is a few lines mechanically derived from an existing on-board file the implementer must read; the plan names the file and the contract.

**Type consistency:** `effective_lifecycle`/`is_sleepable`/`idle_threshold`/`wake_budget` (T1) are consumed with matching signatures in T2/T4/T6/T7/T11. `should_sleep` (T4) ↔ `run_once` (T5) ↔ `serve` (T8) share the `signals`/`hints`/`wake_locked` shapes. `Signal` (T3) fields used consistently in T4/T8. `wake(...)` return `{"status": …}` (T2) consumed by the waker's ctl call + webui (T10).

**Note for the executor:** Tasks 8–12 are integration-heavy; if any task's on-board dependency (watchdog exclusion format, nginx vhost include point, sbxwaf stats path) differs from the plan's assumption, the implementer should report DONE_WITH_CONCERNS with the discovered reality rather than force the assumed shape — the controller resolves cross-cutting facts.
