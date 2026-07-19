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


def _write_text_atomic(path: Path, text: str) -> None:
    path = Path(path)
    orig_mode = os.stat(path).st_mode
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".sbxcfg-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.chmod(tmp, stat.S_IMODE(orig_mode))
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def _lxc_root(run) -> Path:
    """Le lxcpath configuré du système. `lxc-config lxc.lxcpath` renvoie /data/lxc
    sur gk2 (pas le défaut /var/lib/lxc). Repli sur le défaut si indéterminable."""
    rc, out = run(["lxc-config", "lxc.lxcpath"])
    if rc == 0 and out.strip():
        return Path(out.strip())
    return Path("/var/lib/lxc")


def _lxc_autostart(lxc: str, on: bool, run, lxc_root: Path | None = None) -> None:
    """Règle lxc.start.auto en ÉDITANT le fichier config du conteneur
    (<lxcpath>/<lxc>/config), atomiquement. `lxc-update-config` N'EST PAS l'outil
    (c'est un migrateur de format de config, il n'accepte ni -n ni -x) — éditer le
    fichier est la seule voie fiable, vérifiée sur la board."""
    root = lxc_root if lxc_root is not None else _lxc_root(run)
    cfg = Path(root) / lxc / "config"
    want = f"lxc.start.auto = {'1' if on else '0'}"
    try:
        lines = cfg.read_text(encoding="utf-8").splitlines()
        out, seen = [], False
        for ln in lines:
            if ln.split("#", 1)[0].strip().startswith("lxc.start.auto"):
                if not seen:
                    out.append(want)
                    seen = True
                # ligne(s) autostart en double : on garde une seule ligne canonique
            else:
                out.append(ln)
        if not seen:
            out.append(want)
        _write_text_atomic(cfg, "\n".join(out) + "\n")
    except OSError as exc:
        raise ActuationError(f"lxc.start.auto {lxc}={'1' if on else '0'}: {exc}") from exc


def actuate(change: Change, m: Manifest, *, run, route_value=None,
            routes_path: Path = ROUTES_FILE, lxc_root: Path | None = None) -> list[str]:
    """Exécute UN changement. Retourne la liste ordonnée des labels d'action
    (pour l'audit + les tests). Lève ActuationError au premier échec."""
    done: list[str] = []
    starting = change.action == START

    def runtime_start():
        if m.runtime == "lxc" and m.lxc:
            # Le conteneur et l'unité systemd hôte sont DÉCOUPLÉS sur la board
            # réelle : is_on() ne reflète que l'unité hôte. On démarre donc le
            # conteneur d'abord, puis l'API hôte qui en dépend.
            _must(run, ["lxc-start", "-n", m.lxc]); done.append("lxc:start")
            _lxc_autostart(m.lxc, True, run, lxc_root); done.append("lxc:autostart:1")
            for u in m.units:
                _must(run, ["systemctl", "enable", "--now", u])
            done.append("systemd:enable")
        else:
            for u in m.units:
                _must(run, ["systemctl", "enable", "--now", u])
            done.append("systemd:enable")

    def runtime_stop():
        if m.runtime == "lxc" and m.lxc:
            # On éteint l'API hôte d'abord (sinon is_on() reste True alors que
            # le conteneur qu'elle sert est mort → wait_state ne converge jamais).
            for u in m.units:
                _must(run, ["systemctl", "disable", "--now", u])
            done.append("systemd:disable")
            # autostart=0 AVANT lxc-stop : sinon secubox-watchdog voit un conteneur
            # arrêté encore marqué autostart=1 et le relance (course observée sur
            # la board). On coupe l'autostart d'abord, puis on arrête.
            _lxc_autostart(m.lxc, False, run, lxc_root); done.append("lxc:autostart:0")
            _must(run, ["lxc-stop", "-n", m.lxc]); done.append("lxc:stop")
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
