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
