# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: profiles — secubox-sleeper : endort les modules on-demand idle
CyberMind — https://cybermind.fr

Décision PURE (should_sleep) + passe daemon (run_once, Task 5). Ne dort JAMAIS
sur une incertitude : toute sonde indéterminée (None) => on garde le module up.

run_once ne réimplémente rien : pour chaque module devenu idle, elle construit
un plan STOP d'un seul élément et le confie à l'actionneur 0.7.0
(apply.apply_plan — snapshot 4R, état-observé, audit, rollback en cas
d'échec), un module à la fois, jamais en parallèle.
"""
from __future__ import annotations

from pathlib import Path

from . import apply as _apply
from .actuate_paths import audit_path_for as _audit_path_for
from .actuate_paths import snap_root_for as _snap_root_for
from .diff import STOP, Change
from .front_signals import Signal
from .lifecycle import idle_threshold, is_sleepable
from .manifest import Manifest
from .observe import is_on


def should_sleep(m: Manifest, sig: Signal | None, *, hint_idle: bool | None,
                 now_up: bool) -> bool:
    if not now_up or not is_sleepable(m):
        return False
    if sig is None or sig.last_request_age is None or sig.active_conns is None:
        return False
    if hint_idle is False:            # a module /idle hint of False vetoes; None/True allow
        return False
    return sig.active_conns == 0 and sig.last_request_age >= idle_threshold(m)


def run_once(*, root: Path, manifests, actuals, signals, hints, run, observe, now,
             apply: bool = True, wake_locked=frozenset()) -> list[str]:
    """Une passe : arrête chaque module sleepable devenu idle (un à la fois,
    via l'actionneur 0.7.0). Retourne les ids arrêtés. wake_locked = ids en
    cours de réveil (à ne jamais stopper).

    root sert UNIQUEMENT à dériver snap_root/audit_path (voir
    actuate_paths.py) — les manifestes/actuals/signaux sont fournis par
    l'appelant, run_once ne charge rien depuis le disque lui-même."""
    root = Path(root)
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
                                   now=now, routes={}, snap_root=_snap_root_for(root),
                                   audit_path=_audit_path_for(root), apply=apply)
        if report.status == "applied" and mid in report.changed:
            stopped.append(mid)
    return stopped
