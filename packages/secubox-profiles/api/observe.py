# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: profiles — sondes d'état réel (LECTURE SEULE)
CyberMind — https://cybermind.fr

Seul fichier du module qui touche le système. Il n'exécute QUE des commandes de
lecture (is-enabled, is-active, show, lxc-info). Aucun enable/disable/start/stop
n'a sa place ici : Phase 1 est en lecture seule.

L'état réel est OBSERVÉ, jamais supposé depuis un état stocké — un paquet
réinstallé ré-`enable` son unit dans son postinst (motif imposé par le CLAUDE.md
du projet), donc un état mémorisé ment.
"""
from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .manifest import Manifest

PROC = Path("/proc")
ROUTES_FILE = Path("/etc/secubox/waf/haproxy-routes.json")

_TIMEOUT = 5


@dataclass(frozen=True)
class Actual:
    enabled: bool | None = None
    active: bool | None = None
    lxc_running: bool | None = None
    lxc_autostart: bool | None = None
    portal_routed: bool | None = None
    rss_kb: int | None = None


def _run_cmd(argv: list[str]) -> tuple[int | None, str]:
    """rc=None signale que la commande n'a PAS pu s'exécuter (OSError, timeout) —
    à distinguer d'un rc non-nul qui est une réponse authentique de la commande."""
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=_TIMEOUT)
        return p.returncode, p.stdout
    except (OSError, subprocess.SubprocessError):
        return None, ""


def load_routes(path: Path = ROUTES_FILE) -> set[str] | None:
    """Domaines routés par le WAF. Fichier absent = aucune route (pas une erreur).

    `.exists()` est DANS le try : il lève PermissionError quand un parent n'est
    pas traversable, et c'est le cas réel sur la board — /etc/secubox/waf est
    0750 root:root alors que haproxy-routes.json est 0644. Le laisser dehors
    faisait remonter un 500 sur /status au lieu d'un « indéterminable ».
    Inconnu ne doit ni mentir NI planter.
    Fichier présent mais illisible/corrompu = indéterminable → None, pas set()."""
    path = Path(path)
    try:
        if not path.exists():
            return set()
        return set(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError):
        return None


def _rss_kb(pid: str) -> int | None:
    if not pid or pid == "0":
        return None
    try:
        for line in (PROC / pid / "status").read_text(encoding="utf-8").splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    except (OSError, ValueError, IndexError):
        return None
    return None


def observe(m: Manifest, *, run=_run_cmd, routes: set[str] | None = None) -> Actual:
    """État réel d'un module. Tout ce qui n'est pas déterminable reste None —
    jamais False : un False inventé produirait une fausse décision."""
    unit = m.units[0] if m.units else None
    enabled = active = rss = None
    if unit:
        rc, _ = run(["systemctl", "is-enabled", unit])
        # rc=None : la commande n'a pas pu s'exécuter (échec d'exécution/timeout),
        # indistinguable d'un rc!=0 authentique si on ne le traite pas à part —
        # rester None, jamais fabriquer un False.
        enabled = None if rc is None else (rc == 0)
        rc, _ = run(["systemctl", "is-active", unit])
        active = None if rc is None else (rc == 0)
        rc, out = run(["systemctl", "show", unit, "-p", "MainPID", "--value"])
        if rc == 0:
            rss = _rss_kb(out.strip())

    lxc_running = lxc_autostart = None
    if m.runtime == "lxc" and m.lxc:
        rc, out = run(["lxc-info", "-n", m.lxc, "-s"])
        # lxc-info échoue depuis le contexte non privilégié de l'API : on laisse
        # None plutôt que d'affirmer "arrêté" à tort.
        if rc == 0:
            lxc_running = "RUNNING" in out.upper()
        rc, out = run(["lxc-info", "-n", m.lxc, "-c", "lxc.start.auto"])
        if rc == 0:
            lxc_autostart = out.strip().endswith("1")

    portal_routed = None
    if m.portal_domain is not None:
        resolved_routes = routes if routes is not None else load_routes()
        if resolved_routes is not None:
            portal_routed = m.portal_domain in resolved_routes

    return Actual(enabled=enabled, active=active, lxc_running=lxc_running,
                  lxc_autostart=lxc_autostart, portal_routed=portal_routed, rss_kb=rss)


def is_on(a: Actual) -> bool:
    """Un module est ON s'il est enabled ET actif. `enabled` seul survit au
    reboot mais ne sert à rien maintenant ; `active` seul ne survit pas."""
    return bool(a.enabled) and bool(a.active)
