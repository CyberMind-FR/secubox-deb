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
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .manifest import Manifest

PROC = Path("/proc")
ROUTES_FILE = Path("/etc/secubox/waf/haproxy-routes.json")

_TIMEOUT = 5
_BATCH_TIMEOUT = 15

# Unit *templates* (bare "name@.service", no instance) are not runnable units:
# `systemctl show` errors out on them ("neither a valid invocation ID nor
# unit name") and — verified on the board — that error ABORTS the whole
# batched invocation after the first bad unit, silently dropping every unit
# that would have come after it in argv. They must never enter the batch;
# they fall out of `unit_props` naturally and are reported unknown (None),
# same as any other unit missing from the batch output.
_TEMPLATE_UNIT_RE = re.compile(r"@\.service$")

# The full, exhaustive set of systemd UnitFileState values that make
# `systemctl is-enabled` exit non-zero (verified against systemd's own
# unit_file_state enum, and against the 4 states actually observed on the
# board: disabled/enabled/masked/static). Everything else — notably
# "static", "indirect", "generated", "alias" — is a genuine is-enabled
# success (rc=0), so it must map to True, not False.
_DISABLED_UNIT_FILE_STATES = frozenset({
    "disabled", "disabled-runtime", "masked", "masked-runtime", "invalid", "bad", "",
})


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


def load_route_values(path: Path = ROUTES_FILE) -> dict:
    """Le mapping COMPLET domaine → valeur ([host, port]) de haproxy-routes.json.
    Utilisé par apply/rollback pour capturer et restaurer la route d'un module
    portail (load_routes() ne renvoie QUE les noms de domaine). Best-effort :
    fichier absent/illisible/corrompu → {} (apply tourne en root, le dir 0750
    est traversable ; on ne veut pas planter l'apply pour ça)."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


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


def _parse_systemctl_show_blocks(output: str) -> dict[str, dict[str, str]]:
    """`systemctl show <unit...> -p A -p B ...` prints one block per unit,
    blocks separated by a blank line. Property order WITHIN a block is not
    stable (observed MainPID before Id on the board) — parse by key, never
    by position. A unit with no `Id=` line (shouldn't happen, but a
    defensive read) contributes nothing rather than a bogus entry."""
    out: dict[str, dict[str, str]] = {}
    for block in output.split("\n\n"):
        props: dict[str, str] = {}
        for line in block.splitlines():
            key, sep, value = line.partition("=")
            if sep:
                props[key] = value
        unit_id = props.get("Id")
        if unit_id:
            out[unit_id] = props
    return out


def _parse_lxc_ls_fancy(output: str) -> dict[str, tuple[bool | None, bool | None]]:
    """`lxc-ls -f` prints a header line (NAME/STATE/AUTOSTART/GROUPS/IPV4/…)
    then one row per container, columns fixed-width-aligned under the
    header. Locate EVERY header column's start offset (not just the 3 we
    need) so each field's slice is bounded by the *next* column, wherever it
    is — bounding AUTOSTART's slice at end-of-line would swallow GROUPS/IPV4/
    IPV6/UNPRIVILEGED into it whenever AUTOSTART isn't the last header word."""
    lines = output.splitlines()
    if not lines:
        return {}
    header = lines[0]
    col_starts = [m.start() for m in re.finditer(r"\S+", header)]
    col_names = [m.group() for m in re.finditer(r"\S+", header)]
    if not {"NAME", "STATE", "AUTOSTART"} <= set(col_names):
        return {}

    out: dict[str, tuple[bool | None, bool | None]] = {}
    for line in lines[1:]:
        if not line.strip():
            continue
        fields: dict[str, str] = {}
        for i, name in enumerate(col_names):
            start = col_starts[i]
            end = col_starts[i + 1] if i + 1 < len(col_starts) else len(line)
            fields[name] = line[start:end].strip()
        cname = fields.get("NAME")
        if not cname:
            continue
        state = fields.get("STATE", "").upper()
        running = ("RUNNING" in state) if state else None
        autostart_raw = fields.get("AUTOSTART", "").upper()
        if autostart_raw in ("1", "YES"):
            autostart: bool | None = True
        elif autostart_raw in ("0", "NO"):
            autostart = False
        else:
            autostart = None
        out[cname] = (running, autostart)
    return out


def _run_batch(argv: list[str]) -> tuple[int | None, str]:
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=_BATCH_TIMEOUT)
        return p.returncode, p.stdout
    except (OSError, subprocess.SubprocessError):
        return None, ""


def observe_all(manifests: dict[str, Manifest], *, run=_run_batch,
                 routes: set[str] | None = None) -> dict[str, Actual]:
    """État réel de TOUS les modules — chemin rapide. Une seule commande
    `systemctl show` batchée pour toutes les units natives, une seule
    énumération `lxc-ls -f` pour tous les conteneurs, routes lues UNE fois
    (par l'appelant, ou ici si non fournies). `observe()` reste la référence
    module-par-module ; ceci ne la remplace pas, c'est le chemin utilisé
    quand on observe la totalité de l'inventaire (187 modules ~46s en boucle
    -> <1s batché, mesuré sur la board).

    Invariant identique à observe() : une unit absente du batch (unit
    inconnue de systemd, template exclu, ou `systemctl show` n'a pas pu
    s'exécuter du tout) laisse enabled/active=None — jamais un False
    fabriqué. Idem lxc_running/lxc_autostart si le conteneur est absent de
    l'énumération lxc-ls."""
    resolved_routes = routes if routes is not None else load_routes()

    units: list[str] = []
    seen: set[str] = set()
    for m in manifests.values():
        unit = m.units[0] if m.units else None
        if unit and unit not in seen and not _TEMPLATE_UNIT_RE.search(unit):
            seen.add(unit)
            units.append(unit)

    unit_props: dict[str, dict[str, str]] = {}
    if units:
        _, out = run(["systemctl", "show", *units, "-p", "Id", "-p", "UnitFileState",
                     "-p", "ActiveState", "-p", "MainPID", "--no-pager"])
        if out:
            unit_props = _parse_systemctl_show_blocks(out)

    lxc_names = {m.lxc for m in manifests.values() if m.runtime == "lxc" and m.lxc}
    lxc_state: dict[str, tuple[bool | None, bool | None]] = {}
    if lxc_names:
        _, out = run(["lxc-ls", "-f"])
        if out:
            lxc_state = _parse_lxc_ls_fancy(out)

    result: dict[str, Actual] = {}
    for mid, m in manifests.items():
        unit = m.units[0] if m.units else None
        enabled = active = rss = None
        if unit:
            props = unit_props.get(unit)
            # `props is None` covers all three "couldn't determine" cases at
            # once: unknown unit, excluded template, or a batch that didn't
            # execute at all (rc=None, out="") — every one of them must stay
            # None, never become a fabricated False.
            if props is not None:
                ufs = props.get("UnitFileState")
                enabled = None if ufs is None else ufs not in _DISABLED_UNIT_FILE_STATES
                astate = props.get("ActiveState")
                active = None if astate is None else astate == "active"
                rss = _rss_kb(props.get("MainPID", ""))

        lxc_running = lxc_autostart = None
        if m.runtime == "lxc" and m.lxc:
            state = lxc_state.get(m.lxc)
            if state is not None:
                lxc_running, lxc_autostart = state

        portal_routed = None
        if m.portal_domain is not None and resolved_routes is not None:
            portal_routed = m.portal_domain in resolved_routes

        result[mid] = Actual(enabled=enabled, active=active, lxc_running=lxc_running,
                             lxc_autostart=lxc_autostart, portal_routed=portal_routed,
                             rss_kb=rss)
    return result


def is_on(a: Actual) -> bool:
    """Un module est ON s'il est enabled ET actif.

    EXCEPTION runtime LXC : un service purement conteneurisé (jellyfin,
    peertube…) n'a PAS de unit systemd hôte (enabled/active restent None) — mais
    le CONTENEUR qui tourne consomme de la mémoire, et c'est LUI que le sleeper
    doit pouvoir éteindre. Pour un module à runtime LXC (lxc_running renseigné,
    ce que observe() ne fait QUE pour runtime=lxc), l'état du conteneur fait
    autorité, indépendamment d'un éventuel service hôte annexe. Sans ça, is_on
    valait toujours False pour ces LXC → le sleeper les croyait déjà endormis et
    ne les arrêtait jamais (scale-to-zero mort pour les médias, #sleeper)."""
    if a.lxc_running is not None:
        return bool(a.lxc_running)
    return bool(a.enabled) and bool(a.active)
