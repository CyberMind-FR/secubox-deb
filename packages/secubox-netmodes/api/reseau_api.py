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

import re

from fastapi import APIRouter, Depends

from secubox_core.auth import est_admin_reel, require_jwt, require_lecture

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


COUPE_RE = re.compile(r"^04-secubox-port-(lan[0-3])-coupe\.network$")


def ports_coupes(noms: list[str]) -> set[str]:
    """Ports coupés d'après les noms de fichiers (contrat avec la tâche 2) ; tout autre nom est ignoré."""
    return {m.group(1) for n in noms if (m := COUPE_RE.fullmatch(n))}


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
            res["coupes"] = ports_coupes([f.name for f in RESEAU_D.iterdir()])
        except OSError:
            res["coupes"] = None
            pannes.append("coupes")
        res["pannes"] = pannes
        _cache.update(t=time.monotonic(), valeur=res)
        return res


def _macs_box(s: dict) -> set[str]:
    return {str(l["address"]).lower() for l in s.get("ip_link") or [] if isinstance(l, dict) and l.get("address")}


def _restreint(user: Any) -> bool:
    """Tout lecteur qui n'est pas un ADMINISTRATEUR RÉEL (`est_admin_reel` du socle, #1581) : anonyme du tableau de
    bord, usager, appareil enrôlé, invité. Il reçoit des comptes, jamais les MAC apprises ni les voisins du WAN."""
    return not (isinstance(user, dict) and est_admin_reel(user))


def _pannes(s: dict, cles: tuple[str, ...]) -> list[str]:
    return [p for p in s["pannes"] if p in cles]


@router.get("/ports")
def lire_ports(user: Any = Depends(require_lecture)) -> dict:
    s = lire_systeme()
    if s["ip_link"] is None:
        liste = None
    else:
        liste = lect.ports(s["ip_link"], s["fdb"], s["sysfs"], s["coupes"], _macs_box(s))
        if _restreint(user):                    # pas un administrateur réel : ni MAC apprises, des comptes seulement
            for p in liste:
                p["nb_appareils"] = None if p["macs"] is None else len(p["macs"])
                del p["macs"]
    return {"ports": liste, "pannes": _pannes(s, ("ip_link", "fdb", "coupes"))}


@router.get("/clients")
def lire_clients(_user: Any = Depends(require_jwt)) -> dict:
    s = lire_systeme()
    return {"clients": lect.clients(s["baux"], s["fdb"], s["voisins_lan"]),
            "pannes": _pannes(s, ("baux", "voisins_lan", "fdb"))}


@router.get("/carte")
def lire_carte(user: Any = Depends(require_lecture)) -> dict:
    s = lire_systeme()
    c = lect.carte(s["wan_addr"], s["route_defaut"], s["voisins_wan"], s["membres_lxc"], s["liens_wg"])
    if _restreint(user) and c["wan"] and c["wan"]["voisins"] is not None:
        c["wan"]["nb_voisins"] = len(c["wan"]["voisins"])
        del c["wan"]["voisins"]
    return {"carte": c, "pannes": _pannes(s, ("wan_addr", "route_defaut", "voisins_wan", "membres_lxc", "liens_wg"))}
