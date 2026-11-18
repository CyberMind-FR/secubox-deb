# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: WAF :: routes de la mémoire des leurres (#3734)

Toutes en `require_jwt` : la mémoire porte les mots de passe tentés EN CLAIR (décision du propriétaire, #3728), aucune
lecture anonyme ni de tableau de bord. Les gestes (prolonger, lever) passent par `wafctl`, qui refuse le privé et les
adresses protégées ; une adresse hors mémoire n'est pas bannissable d'ici (la page générale des bans existe pour ça).
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import time
from pathlib import Path
from typing import Any, Callable, Dict, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator
from secubox_core.auth import require_jwt

try:
    from api.leurres_memoire import Memoire
except ImportError:  # standalone
    from leurres_memoire import Memoire

BASE = Path("/var/lib/secubox-waf-leurres/leurres.db")
JOURNAL = Path(os.environ.get("SECUBOX_WAF_THREATS_LOG") or "/var/log/secubox/waf/waf-threats.log")
_memoire = Memoire(BASE, JOURNAL)
# Branchés par api.main : bans actifs (cache chaud), ban/levée par wafctl, audit.
_config: Dict[str, Callable[..., Any]] = {}
_INTERNES = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
                                               "fc00::/7")]
log = logging.getLogger("secubox.waf.leurres")
router = APIRouter(prefix="/leurres", dependencies=[Depends(require_jwt)])


def configurer(**fonctions: Callable[..., Any]) -> None:
    _config.update(fonctions)


def ingerer() -> int:
    """Appelé par la boucle de fond et avant chaque lecture : lit la suite du journal."""
    return _memoire.ingerer(int(time.time()))


def purger() -> int:
    return _memoire.purger(int(time.time()))


def _bans() -> Optional[Dict[str, Any]]:
    """Bans actifs par adresse, ou None s'ils sont ILLISIBLES : la page affiche alors « — », jamais « non banni »."""
    try:
        return {b["ip"]: b.get("expires_in") for b in _config["bans"]()}
    except Exception as e:  # noqa: BLE001 — nft muet ou table absente : état inconnu, la mémoire reste lisible
        log.warning("leurres : bans illisibles : %s", e)
        return None


def _lu(fonction: Callable[..., Any], *args: Any, **kw: Any) -> Any:
    ingerer()
    return fonction(int(time.time()), *args, **kw)


@router.get("/resume")
async def resume() -> Dict[str, Any]:
    def faire() -> Dict[str, Any]:
        r = _lu(_memoire.resume)
        bans = _bans()
        r["bans_actifs"] = None if bans is None else sum(1 for ip in _memoire.adresses(int(time.time())) if ip in bans)
        return r
    return await asyncio.to_thread(faire)


@router.get("/attaquants")
async def attaquants(filtre: str = "", profil: str = "", limite: int = 200) -> Dict[str, Any]:
    def faire() -> Dict[str, Any]:
        lignes = _lu(_memoire.attaquants, filtre=filtre[:128], profil=profil[:16], limite=max(1, min(limite, 1000)))
        bans = _bans()
        for a in lignes:
            if a["ip"] == "local":
                a["ban"] = None                                   # LAN : jamais bannissable
            elif bans is None:
                a["ban"] = {"actif": None, "expire_dans": None}   # inconnu
            else:
                a["ban"] = {"actif": a["ip"] in bans, "expire_dans": bans.get(a["ip"])}
        return {"attaquants": lignes, "total": len(lignes)}
    return await asyncio.to_thread(faire)


@router.get("/attaquant/{ip}")
async def attaquant(ip: str) -> Dict[str, Any]:
    return await asyncio.to_thread(lambda: _lu(lambda t: _memoire.fiche(ip[:64], t)))


@router.get("/dictionnaire")
async def dictionnaire(limite: int = 50) -> Dict[str, Any]:
    return await asyncio.to_thread(lambda: _lu(_memoire.dictionnaire, limite=max(1, min(limite, 100_000))))


@router.get("/rejeux")
async def rejeux() -> Dict[str, Any]:
    return await asyncio.to_thread(lambda: _lu(_memoire.rejeux))


class Cible(BaseModel):
    ip: str

    @field_validator("ip")
    @classmethod
    def _globale(cls, v: str) -> str:
        a = ipaddress.ip_address(v)          # ValueError → 422
        if a.is_loopback or a.is_link_local or a.is_multicast or a.is_unspecified or any(a in r for r in _INTERNES):
            raise ValueError("adresse interne")   # LAN et maillage : jamais bannis (wafctl le refuse aussi)
        return str(a)


class Ban(Cible):
    duree: Literal["4h", "24h", "7d"]       # jamais de ban permanent


def _en_memoire(ip: str) -> None:
    ingerer()
    if not _memoire.fiche(ip, int(time.time()))["visites"]:
        raise HTTPException(404, detail={"motif": "hors_memoire"})


def _geste(action: str, ip: str, detail: str, user: dict, appel: Callable[[], tuple]) -> Dict[str, Any]:
    ok, message = appel()
    _config["audit"](action if ok else action + "-echec", f"{detail} — {message}"[:300], user)
    if not ok:
        raise HTTPException(502, detail={"motif": "wafctl", "message": str(message)[:200]})
    return {"success": True, "ip": ip, "message": message}


@router.post("/ban")
def ban(corps: Ban, user: dict = Depends(require_jwt)) -> Dict[str, Any]:
    """Pose ou prolonge le ban d'une adresse vue par un leurre. `nft add element` ne change pas l'échéance d'un élément
    déjà présent : pour PROLONGER, le ban est levé puis reposé (sinon le geste répondrait « fait » sans rien faire)."""
    _en_memoire(corps.ip)

    def appel() -> tuple:
        bans = _bans()
        if bans is None or corps.ip in bans:
            ok, message = _config["unban"](corps.ip)
            if not ok and bans is not None:
                return False, f"levée avant prolongation refusée : {message}"
        return _config["ban"](corps.ip, corps.duree)
    return _geste("leurre-ban", corps.ip, f"{corps.ip} {corps.duree}", user, appel)


@router.post("/unban")
def unban(corps: Cible, user: dict = Depends(require_jwt)) -> Dict[str, Any]:
    _en_memoire(corps.ip)
    return _geste("leurre-unban", corps.ip, corps.ip, user, lambda: _config["unban"](corps.ip))
