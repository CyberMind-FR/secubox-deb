# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Actions sur les ports du switch (#3190, #3201) : POST /ports/{port}/couper, /retablir, /isoler et /rattacher, par
netmodesctl (root, sudo -n). Isoler met le port dans son propre réseau (hors du pont, sans accès au LAN) ; rattacher le
remet au pont.

Routes `def` (pool de threads) : elles appellent subprocess. Seuls lan0..lan3 (PORTS_LAN), jamais eth* ni br-lan.
Couper et isoler refusent (409) le port derrière lequel se trouve le poste de l'administrateur, AVANT tout appel au contrôleur :
adresse du poste → MAC (`ip -j neigh show dev br-lan`) → port où cette MAC est apprise (`bridge -j fdb show br br-lan`),
lus frais (pas le cache de 5 s de /reseau : un poste qui vient de changer de port doit être vu là où il est)."""
from __future__ import annotations

import subprocess
from ipaddress import IPv6Address, ip_address
from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, Request

from secubox_core.auth import require_jwt
from secubox_core.logger import get_logger

from . import reseau_api as reseau
from . import reseau_lecture as lect
from .routeur_api import _acteur, _ctl, adresses_client, bascule_lancee
from .routeur_config import PORTS_LAN

DELAI_PORT = 60                                 # le contrôleur relit le port 15 s au plus après networkd
PONT_SYS = reseau.SYS_NET / lect.PONT_LAN

log = get_logger("netmodes")
router = APIRouter(prefix="/ports")


def _verifier(port: str, corps: Any) -> None:
    if port not in PORTS_LAN:                   # liste blanche d'abord, avant même de lire le corps
        raise HTTPException(400, f"port refusé : seuls {', '.join(PORTS_LAN)} sont actionnables")
    if not isinstance(corps, dict) or corps.get("confirmer") != port:
        raise HTTPException(400, f'confirmation requise : "confirmer": "{port}"')


def _pas_pendant_une_bascule() -> None:
    if bascule_lancee():
        raise HTTPException(409, "une bascule du mode routeur est en cours : attendre sa fin")


def _ip(brute: Any):
    try:
        ip = ip_address(str(brute).strip())
    except ValueError:
        return None
    return ip.ipv4_mapped if isinstance(ip, IPv6Address) and ip.ipv4_mapped is not None else ip


def _ports_du_poste(request: Request) -> set[str]:
    """Ports derrière lesquels la MAC du poste est apprise. Aucun si br-lan n'existe pas, si le poste n'est pas un voisin
    de br-lan (maillage, WAN) ou si sa MAC n'est apprise sur aucun port. Lecture en échec : 503, rien n'est coupé."""
    if not PONT_SYS.exists():                   # sans pont, personne n'est derrière l'un de ses ports
        return set()
    adresses = adresses_client(request)
    try:
        voisins = reseau._json(reseau.SOURCES["voisins_lan"])
        macs = {str(v["lladdr"]).lower() for v in voisins or []
                if isinstance(v, dict) and v.get("lladdr") and _ip(v.get("dst")) in adresses
                and "FAILED" not in (v.get("state") or [])}
        if not macs:
            return set()
        fdb = reseau._json(reseau.SOURCES["fdb"])
    except (OSError, ValueError, subprocess.SubprocessError) as e:
        log.warning("anti-coupure : voisins ou table de pont de br-lan illisibles : %s", e)
        raise HTTPException(503, "impossible de vérifier que vous ne couperiez pas votre propre accès (voisins ou "
                                 "table de pont de br-lan illisibles) : rien n'a été coupé")
    return {e["ifname"] for e in lect._fdb_apprises(fdb) if str(e["mac"]).lower() in macs}


def _apres_action() -> None:
    reseau.invalider()                          # l'onglet Switch relit l'état réel, pas une lecture d'avant l'action


@router.post("/{port}/couper")
def couper(port: str, request: Request, corps: Any = Body(default=None), user=Depends(require_jwt)):
    _verifier(port, corps)
    acteur = _acteur(user)
    _pas_pendant_une_bascule()
    if port in _ports_du_poste(request):
        raise HTTPException(409, f"vous couperiez votre propre accès (votre poste est derrière {port})")
    res = _ctl("port-couper", port, acteur, delai=DELAI_PORT)
    _apres_action()
    return res


@router.post("/{port}/retablir")
def retablir(port: str, corps: Any = Body(default=None), user=Depends(require_jwt)):
    _verifier(port, corps)
    acteur = _acteur(user)
    _pas_pendant_une_bascule()
    res = _ctl("port-retablir", port, acteur, delai=DELAI_PORT)
    _apres_action()
    return res


@router.post("/{port}/isoler")
def isoler(port: str, request: Request, corps: Any = Body(default=None), user=Depends(require_jwt)):
    _verifier(port, corps)
    acteur = _acteur(user)
    _pas_pendant_une_bascule()
    if port in _ports_du_poste(request):
        raise HTTPException(409, f"vous perdriez votre propre accès (votre poste est derrière {port})")
    res = _ctl("port-isoler", port, acteur, delai=DELAI_PORT)
    _apres_action()
    return res


@router.post("/{port}/rattacher")
def rattacher(port: str, corps: Any = Body(default=None), user=Depends(require_jwt)):
    _verifier(port, corps)
    acteur = _acteur(user)
    _pas_pendant_une_bascule()
    res = _ctl("port-rattacher", port, acteur, delai=DELAI_PORT)
    _apres_action()
    return res
