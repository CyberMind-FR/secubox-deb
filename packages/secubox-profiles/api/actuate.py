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
