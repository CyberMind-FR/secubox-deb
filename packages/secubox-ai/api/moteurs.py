# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Moteurs d'inférence de secubox-ai : local (llama-server sur socket Unix) et distant (#3583).

Le moteur local est piloté par un contrôleur root : le module dépose une demande
`$SECUBOX_AI_RUN/demandes/<action>.demande` (jamais de systemctl). Le moteur distant n'est utilisé que si
`config()["distant"]["url"]` est déclarée ET si la clé `$SECUBOX_AI_CLE` est lisible et non vide ; sans clé,
aucune requête n'est émise vers l'adresse distante. La clé n'apparaît ni dans les journaux, ni dans les
exceptions, ni dans `etat()`, ni dans `repr(Moteur)`.
"""
import asyncio
import logging
import os
import time
from pathlib import Path
from typing import Callable, Literal

import httpx
from fastapi import APIRouter, Depends, HTTPException

from secubox_core.auth import require_jwt

from api import reglages

log = logging.getLogger("secubox.ai.moteurs")

RUN_DEFAUT = "/run/secubox-ai"
CLE_DEFAUT = "/etc/secubox/secrets/ai/distant.key"
ACTIONS = ("demarrer", "arreter", "redemarrer")
CTX_AUTO_MIN = 4096
DELAI_SONDE_S = 2.0       # sonde /health du moteur distant
CACHE_SONDE_S = 10.0      # une sonde récente évite de re-sonder à chaque requête
DELAI_DEMARRAGE_S = 180

# Point d'injection des tests : fabrique(nom) -> transport httpx (ou None = transport réel).
FABRIQUE_TRANSPORT: Callable[[str], httpx.AsyncBaseTransport | None] | None = None
_cache_sonde: dict = {}


def run_dir() -> Path:
    return Path(os.environ.get("SECUBOX_AI_RUN", RUN_DEFAUT))


def _lire_cle() -> str | None:
    """Clé distante lue à l'appel ; None si absente, vide ou illisible."""
    try:
        cle = Path(os.environ.get("SECUBOX_AI_CLE", CLE_DEFAUT)).read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError):
        return None
    return cle or None


def _url_distante() -> str:
    url = reglages.config().get("distant", {}).get("url")
    return url.strip().rstrip("/") if isinstance(url, str) else ""


def deposer_demande(action: str) -> None:
    """Dépose une demande au contrôleur root (écriture .tmp puis os.replace)."""
    if action not in ACTIONS:
        raise ValueError(f"action inconnue : {action}")
    dossier = run_dir() / "demandes"
    dossier.mkdir(parents=True, exist_ok=True)
    cible = dossier / f"{action}.demande"
    tmp = dossier / f"{action}.demande.tmp"
    tmp.write_text("", encoding="utf-8")
    os.replace(tmp, cible)


class Moteur:
    """Un moteur choisi : `nom` vaut "local" ou "distant"."""

    def __init__(self, nom: str, url: str = "", cle: str | None = None):
        self.nom = nom
        self._url = url
        self._cle = cle

    def __repr__(self) -> str:
        return f"Moteur({self.nom!r})"

    def client(self, delai: float = 300) -> httpx.AsyncClient:
        transport = FABRIQUE_TRANSPORT(self.nom) if FABRIQUE_TRANSPORT else None
        if self.nom == "local":
            if transport is None:
                transport = httpx.AsyncHTTPTransport(uds=str(run_dir() / "moteur.sock"))
            return httpx.AsyncClient(transport=transport, base_url="http://moteur", timeout=delai)
        if not self._cle:
            raise HTTPException(503, "moteur distant non configuré")
        return httpx.AsyncClient(transport=transport, base_url=self._url, timeout=delai,
                                 headers={"Authorization": f"Bearer {self._cle}"})


def _local() -> Moteur:
    return Moteur("local")


def _distant() -> Moteur | None:
    """Le moteur distant, ou None s'il n'est pas déclaré ou si la clé manque."""
    url, cle = _url_distante(), _lire_cle()
    return Moteur("distant", url, cle) if url and cle else None


async def _sonde(m: Moteur, delai: float) -> bool:
    try:
        async with m.client(delai) as c:
            return (await c.get("/health")).status_code == 200
    except (httpx.HTTPError, HTTPException):
        return False


async def _distant_joignable(m: Moteur) -> bool:
    """Sonde /health (2 s), résultat gardé 10 s."""
    maintenant = time.monotonic()
    vu = _cache_sonde.get(m._url)
    if vu and maintenant - vu[0] < CACHE_SONDE_S:
        return vu[1]
    ok = await _sonde(m, DELAI_SONDE_S)
    _cache_sonde[m._url] = (maintenant, ok)
    return ok


async def choisir(force: str | None = None) -> Moteur:
    """Moteur à utiliser. `force` : auto/local/distant, sinon la préférence `moteur.force`."""
    force = force or reglages.lire_prefs()["moteur"]["force"]
    if force == "local":
        return _local()
    distant = _distant()
    if force == "distant":
        if distant is None:
            raise HTTPException(503, "moteur distant non configuré")
        return distant
    if distant is not None and await _distant_joignable(distant):
        return distant
    return _local()


async def attendre_moteur(m: Moteur, delai: float = DELAI_DEMARRAGE_S, pas: float = 1.0) -> bool:
    limite = time.monotonic() + delai
    while True:
        if await _sonde(m, 5):
            return True
        if time.monotonic() >= limite:
            return False
        await asyncio.sleep(pas)


async def assurer_moteur(delai: float = DELAI_DEMARRAGE_S, pas: float = 1.0) -> Moteur:
    """Choisit le moteur, le démarre au besoin et attend qu'il réponde."""
    m = await choisir()
    if await _sonde(m, 5):
        return m
    if m.nom == "local":
        await asyncio.to_thread(deposer_demande, "demarrer")
    else:
        try:
            async with m.client(10) as c:
                await c.post("/moteur/demarrer")
        except httpx.HTTPError:
            pass
    if not await attendre_moteur(m, delai, pas):
        raise HTTPException(503, f"le moteur {m.nom} n'a pas démarré")
    return m


async def contexte_reel(m: Moteur | None = None) -> int:
    """Le contexte du moteur EN MARCHE : des préférences changées ne s'appliquent qu'à son redémarrage."""
    m = m or await choisir()
    async with m.client(10) as c:
        r = await c.get("/props")
        r.raise_for_status()
    return int(r.json()["default_generation_settings"]["n_ctx"]) or \
        reglages.lire_prefs()["moteur"]["contexte"] or CTX_AUTO_MIN


async def compter_tokens(texte: str, m: Moteur | None = None) -> int:
    m = m or await choisir()
    async with m.client(20) as c:
        r = await c.post("/tokenize", json={"content": texte})
        r.raise_for_status()
    return len(r.json()["tokens"])


async def etat() -> dict:
    """Résumé sans secret : quel moteur répondrait, et l'état de chacun. Ne lève jamais."""
    force = reglages.lire_prefs()["moteur"]["force"]
    url, cle = _url_distante(), _lire_cle()
    distant = _distant()
    joignable = await _distant_joignable(distant) if distant else False
    local_pret = await _sonde(_local(), 2)
    if force == "local" or (force == "auto" and not joignable):
        actif = "local"
    elif force == "distant" and distant is None:
        actif = None
    else:
        actif = "distant"
    return {"force": force, "actif": actif,
            "local": {"pret": local_pret},
            "distant": {"declare": bool(url), "configure": bool(url and cle), "joignable": joignable}}


routeur = APIRouter(prefix="")


@routeur.get("/moteur", dependencies=[Depends(require_jwt)])
async def get_moteur():
    return await etat()


@routeur.post("/moteur/{choix}", dependencies=[Depends(require_jwt)])
async def post_moteur(choix: Literal["local", "distant", "auto"]):
    prefs = reglages.valider({"moteur": {"force": choix}})
    reglages.ecrire_prefs(prefs)
    return await etat()
