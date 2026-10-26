# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Routes de lecture du réseau (#3190) : GET /reseau/{ports,clients,carte}. Lecture seule, aucune action sur une interface.

Routes `def` (pool de threads) : lire_systeme() appelle subprocess, seul endroit du module à le faire."""
from __future__ import annotations

import json
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends

from secubox_core.auth import require_lecture

from . import reseau_lecture as lect

router = APIRouter(prefix="/reseau")

DELAI = 5            # secondes par commande
TTL_CACHE = 5.0
SYS_NET = Path("/sys/class/net")
BAUX = Path("/var/lib/misc/dnsmasq.leases")
RESEAU_D = Path("/etc/systemd/network")

SOURCES = {          # clé -> argv (lecture seule : ip/bridge en mode show)
    "ip_link": ["ip", "-j", "link"],
    "fdb": ["bridge", "-j", "fdb", "show", "br", lect.PONT_LAN],
    "voisins_lan": ["ip", "-j", "neigh", "show", "dev", lect.PONT_LAN],
    "wan_addr": ["ip", "-j", "-4", "addr", "show", "dev", lect.WAN],
    "route_defaut": ["ip", "-j", "-4", "route", "show", "default"],
    "voisins_wan": ["ip", "-j", "neigh", "show", "dev", lect.WAN],
    "membres_lxc": ["ip", "-j", "link", "show", "master", lect.PONT_LXC],
    "liens_wg": ["ip", "-j", "link", "show", "type", "wireguard"],
}

_cache: dict[str, Any] = {}
_verrou = threading.Lock()


def _json(argv: list[str]):
    r = subprocess.run(argv, timeout=DELAI, capture_output=True, text=True, check=False)
    if r.returncode != 0:
        raise OSError(f"{argv[0]} rc {r.returncode}")
    return json.loads(r.stdout or "[]")


def _sys(port: str, fichier: str) -> str | None:
    try:
        return (SYS_NET / port / fichier).read_text().strip()
    except OSError:
        return None


def lire_systeme() -> dict:
    """Toutes les lectures, cache mémoire de 5 s. Source en échec : clé None et nom dans `pannes`."""
    with _verrou:
        if _cache.get("t") and time.monotonic() - _cache["t"] < TTL_CACHE:
            return _cache["valeur"]
        res: dict[str, Any] = {}
        pannes: list[str] = []
        for cle, argv in SOURCES.items():
            try:
                res[cle] = _json(argv)
            except (OSError, ValueError, subprocess.SubprocessError):
                res[cle] = None
                pannes.append(cle)
        res["sysfs"] = {p: {f: _sys(p, f) for f in ("carrier", "speed", "operstate")} for p in lect.ROLES}
        try:
            res["baux"] = BAUX.read_text()
        except OSError:
            res["baux"] = None
            pannes.append("baux")
        try:
            pref, suf = "04-secubox-port-", ".network"
            res["coupes"] = {f.name[len(pref):-len(suf)] for f in RESEAU_D.glob(pref + "*" + suf)}
        except OSError:
            res["coupes"] = None
            pannes.append("coupes")
        res["pannes"] = pannes
        _cache.update(t=time.monotonic(), valeur=res)
        return res


def _macs_box(s: dict) -> set[str]:
    return {str(l["address"]).lower() for l in s.get("ip_link") or [] if isinstance(l, dict) and l.get("address")}


@router.get("/ports")
def lire_ports(_user: Any = Depends(require_lecture)) -> dict:
    s = lire_systeme()
    return {"ports": lect.ports(s["ip_link"] or [], s["fdb"] or [], s["sysfs"], s["coupes"] or set(), _macs_box(s)),
            "pannes": s["pannes"]}


@router.get("/clients")
def lire_clients(_user: Any = Depends(require_lecture)) -> dict:
    s = lire_systeme()
    return {"clients": lect.clients(s["baux"] or "", s["fdb"] or [], s["voisins_lan"] or []), "pannes": s["pannes"]}


@router.get("/carte")
def lire_carte(_user: Any = Depends(require_lecture)) -> dict:
    s = lire_systeme()
    return {"carte": lect.carte(s["wan_addr"] or [], s["route_defaut"] or [], s["voisins_wan"] or [],
                                s["membres_lxc"] or [], s["liens_wg"] or []), "pannes": s["pannes"]}
