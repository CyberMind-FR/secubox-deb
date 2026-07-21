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
import re
import stat
import tempfile
import time
from pathlib import Path

from . import portal_routes as _portal_routes
from .diff import START, STOP, Change
from .manifest import Manifest
from .observe import ROUTES_FILE, is_on, observe as _observe


class ActuationError(Exception):
    """Une commande d'actionnement a échoué (rc non-nul) ou n'a pas pu tourner (rc=None)."""


# Sentinel returncode for a command that RAN but did not return within the
# deadline (subprocess.TimeoutExpired), as opposed to one that could not run at
# all (OSError -> rc is None). The actuator fast-fails only on the latter; a
# timeout on lxc-start/lxc-stop is deferred to wait_state (observed state
# decides). 1000 is outside every real returncode (exit codes 0-255, signal
# codes negative), so `rc != 0` still reads it as "not success".
TIMED_OUT = 1000


def _must(run, argv: list[str]) -> None:
    rc, out = run(argv)
    if rc != 0:
        raise ActuationError(f"{' '.join(argv)} → rc={rc!r} {out.strip()[:200]}")


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


def _current_route(domain: str, routes_path: Path):
    """La valeur de route ([host, port]) actuellement dans haproxy-routes.json
    pour `domaine`, ou None si absente/illisible. Lue AVANT retrait pour la
    confier à la mémoire durable (le réveil la relira)."""
    try:
        data = json.loads(Path(routes_path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data.get(domain) if isinstance(data, dict) else None


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
            routes_path: Path = ROUTES_FILE, lxc_root: Path | None = None,
            remember_path: Path = _portal_routes.REMEMBER_FILE) -> list[str]:
    """Exécute UN changement. Retourne la liste ordonnée des labels d'action
    (pour l'audit + les tests). Lève ActuationError au premier échec."""
    done: list[str] = []
    starting = change.action == START

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
            # On éteint l'API hôte d'abord (sinon is_on reste True alors que
            # le conteneur qu'elle sert va mourir). enable/disable = opérations
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

    if starting:
        runtime_start()
        if m.portal_domain:
            _portal_add(m.portal_domain, route_value, routes_path)
            done.append("portal:add")
    else:
        if m.portal_domain:
            # Mémorise la route AVANT de la retirer : le réveil (potentiellement
            # bien plus tard, snapshot 4R déjà tourné) n'a plus d'autre source.
            _portal_routes.remember(m.portal_domain,
                                    _current_route(m.portal_domain, routes_path),
                                    path=remember_path)
            _portal_remove(m.portal_domain, routes_path)
            done.append("portal:remove")
        runtime_stop()
    return done


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


def condition_failed(m: Manifest, run) -> bool:
    """True si l'unité systemd du module a une Condition= de démarrage qui
    ÉCHOUE : `systemctl enable --now` réussit, mais systemd laisse alors l'unité
    inactive VOLONTAIREMENT (le module ne doit pas tourner dans cet
    environnement — arch, présence d'un chemin, etc.). Ce n'est PAS un échec
    d'actionnement : attendre `active` sur une telle unité timeout à l'infini.
    Ne concerne que les modules natifs (LXC/portail n'ont pas de Condition=)."""
    if m.runtime != "native":
        return False
    for u in m.units:
        rc, out = run(["systemctl", "show", u, "-p", "ConditionResult", "--value"])
        if rc == 0 and out.strip() == "no":
            return True
    return False


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
