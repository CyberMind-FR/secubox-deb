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

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable

from . import apply as _apply
from .actuate_paths import audit_path_for as _audit_path_for
from .actuate_paths import snap_root_for as _snap_root_for
from .diff import STOP, Change
from .front_signals import Signal, vhost_signals
from .lifecycle import idle_threshold, is_sleepable
from .manifest import Manifest, load_all
from .observe import is_on

_LOG = logging.getLogger(__name__)

# Le waker (api/waker.py) écrit son verrou de réveil-en-cours dans ce fichier
# (liste JSON d'ids de module) — lecture au mieux-effort : absent/illisible
# ne bloque jamais la boucle, ça revient juste à "rien n'est verrouillé".
WAKE_LOCK_FILE = Path("/run/secubox/waker-active.json")


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


def _read_wake_locked(path: Path = WAKE_LOCK_FILE) -> frozenset[str]:
    """Lit l'ensemble des ids en cours de réveil, au mieux-effort. Le waker
    écrit ce fichier ; absent/corrompu/illisible => aucun verrou (jamais une
    exception qui ferait mourir la boucle)."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return frozenset()
    if not isinstance(data, list):
        return frozenset()
    return frozenset(x for x in data if isinstance(x, str))


def _default_stamp() -> str:
    return datetime.now(timezone.utc).isoformat()


async def serve(*, root: Path, interval: float,
                sleep: Callable[[float], Awaitable[Any]],
                observe_all: Callable[..., dict[str, Any]],
                signal_reader: Callable[[], dict[str, dict[str, Any]]],
                hint_probe: Callable[[str, Manifest], bool | None],
                run: Callable[..., Any], observe: Callable[[Manifest], Any],
                now: Callable[[], float],
                signals_healthy: Callable[[], bool] = lambda: False,
                stamp: Callable[[], str] | None = None,
                tick_limit: int | None = None) -> None:
    """Boucle daemon du sleeper. Chaque tick : charge les manifestes, observe
    l'état réel, lit les signaux front par vhost et les reprojette par
    module (via portal_domain), sonde le hint /idle optionnel de chaque
    module, lit le verrou de réveil (best-effort), puis délègue à run_once.

    `now` sert d'horloge FLOTTANTE pour l'âge des signaux (même contrat que
    front_signals.vhost_signals — Callable[[], float]) ; `stamp` est un
    producteur de CHAÎNE distinct pour l'horodatage d'audit passé à
    run_once/apply_plan (par défaut une ISO-8601 UTC). Les deux rôles sont
    volontairement séparés : un même paramètre `now` unique serait ambigu
    (l'un exige un float pour l'arithmétique d'âge, l'autre une chaîne
    journalisée telle quelle dans l'audit).

    tick_limit borne la boucle (tests) ; None = tourne indéfiniment.

    Note de conception (suivi, pas résolu ici) : run_once → apply_plan prend
    un snapshot 4R PARTAGÉ par module arrêté. Un sleeper actif peut donc
    faire tourner R1..R4 que `profilectl rollback` (opérateur) utilise aussi.
    Le sommeil auto est réversible par réveil-sur-accès (nginx @waker) donc
    ne devrait sans doute PAS consommer de slot rollback — mais ce n'est pas
    le périmètre de cette tâche ; à traiter séparément (ref #896 follow-up).
    """
    stamp_fn = stamp if stamp is not None else _default_stamp
    # Chrono d'inactivité SANS trafic pour l'idle-sur-absence (voir plus bas) :
    # mid -> instant (horloge `now`) où le module a été vu running+sleepable et
    # ABSENT d'un fichier de signaux SAIN pour la 1re fois. Persiste entre ticks.
    absent_since: dict[str, float] = {}
    ticks = 0
    while tick_limit is None or ticks < tick_limit:
        try:
            manifests = load_all(Path(root) / "modules.d")
            actuals = observe_all(manifests, routes=None)
            vsig = vhost_signals(reader=signal_reader, now=now)
            signals: dict[str, Signal] = {
                mid: vsig[m.portal_domain] for mid, m in manifests.items()
                if m.portal_domain in vsig
            }
            # IDLE-SUR-ABSENCE : un module on-demand qui TOURNE mais est ABSENT
            # d'un fichier de signaux FRAIS n'a AUCUN trafic. Le contrat « pas de
            # signal => on ne dort pas » protège d'un fichier PÉRIMÉ (tout
            # paraîtrait idle → sommeil de masse, incident 2026-08-07) ; il ne
            # doit PAS empêcher d'endormir un conteneur GÉNUINEMENT idle quand le
            # système de signaux est SAIN. On synthétise donc un signal idle
            # (age croissant, 0 conn) après une grâce d'idle_threshold sans
            # trafic — UNIQUEMENT si le fichier est frais (signals_healthy).
            # Fichier incertain => aucune injection, on repart de zéro.
            if signals_healthy():
                t = now()
                for mid, m in manifests.items():
                    if mid in signals:
                        absent_since.pop(mid, None)
                        continue
                    a = actuals.get(mid)
                    if not (is_sleepable(m) and a is not None and is_on(a)):
                        absent_since.pop(mid, None)
                        continue
                    age = t - absent_since.setdefault(mid, t)
                    if age >= idle_threshold(m):
                        signals[mid] = Signal(last_request_age=age, active_conns=0)
            else:
                absent_since.clear()
            hints: dict[str, bool] = {}
            for mid, m in manifests.items():
                h = hint_probe(mid, m)
                if h is not None:
                    hints[mid] = h
            locked = _read_wake_locked()
            run_once(root=root, manifests=manifests, actuals=actuals,
                     signals=signals, hints=hints, run=run, observe=observe,
                     now=stamp_fn(), wake_locked=locked)
        except Exception:
            _LOG.exception("sleeper: tick failed, will retry next interval")
        ticks += 1
        if tick_limit is None or ticks < tick_limit:
            await sleep(interval)
