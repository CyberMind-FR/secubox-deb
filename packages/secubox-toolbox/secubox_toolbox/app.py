# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

"""ToolBoX entry point (uvicorn)."""
from __future__ import annotations

import asyncio
import logging
from pathlib import Path

import hmac
import re

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from . import __version__, social, store, threat_intel
from .api import router as toolbox_router

_log = logging.getLogger("secubox.toolbox")
if not _log.handlers:
    _log.setLevel(logging.INFO)
    _log.addHandler(logging.StreamHandler())

app = FastAPI(
    title="SecuBox ToolBoX",
    version=__version__,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
app.include_router(toolbox_router)

# ── ROUTES D'ADMINISTRATION : SEULEMENT PAR LA GARDE NGINX (#1783) ──────────
# uvicorn écoute sur 0.0.0.0:8088 : le LAN l'atteint en direct, les pairs du
# tunnel par le DNAT, kbin par sbxwaf — trois chemins sans nginx, donc sans
# authentification. Et derrière un mandataire de confiance, uvicorn remplace
# `request.client` par X-Forwarded-For : l'adresse ne dit pas par où la requête
# est passée. Seule preuve retenue : l'en-tête que nginx pose APRÈS
# `auth_request` sur /auth/verify?exige=admin (administrateur réel), porteur
# d'un jeton tiré à l'installation et lisible de root et de ce service seuls.
GARDE_EN_TETE = "x-sbx-garde-admin"
GARDE_JETON = Path("/etc/secubox/toolbox/garde-admin.jeton")
_PREFIXES_ADMIN = ("/admin/", "/rlevel/peer", "/exit_country", "/vpn/", "/tor/bridge")
# Vues publiques en lecture seule par conception (Phase 6.J, _is_public_kbin) :
# listes de filtres et de domaines épargnés, rien sur les clients.
_LECTURES_PUBLIQUES = frozenset({
    "/admin/filter-control", "/admin/filter-control/list",
    "/admin/filter-control/regex", "/admin/splice-whitelist",
    "/admin/splice-whitelist/list",
})


def _chemin_admin(chemin: str) -> bool:
    return chemin == "/admin" or chemin.startswith(_PREFIXES_ADMIN)


def _jeton_garde() -> bytes:
    try:
        return GARDE_JETON.read_bytes().strip()
    except OSError:
        return b""


def _garde_admise(request: Request) -> bool:
    attendu = _jeton_garde()
    recu = (request.headers.get(GARDE_EN_TETE) or "").encode()
    # Sans jeton sur disque, personne n'entre : jamais « vide == vide ».
    return len(attendu) >= 32 and hmac.compare_digest(recu, attendu)


@app.middleware("http")
async def _garde_routes_admin(request: Request, call_next):
    chemin = re.sub(r"/{2,}", "/", request.url.path)
    if _chemin_admin(chemin):
        if request.method in ("GET", "HEAD") and chemin in _LECTURES_PUBLIQUES:
            return await call_next(request)
        if not _garde_admise(request):
            return JSONResponse(
                {"detail": "administration réservée : passer par l'interface d'administration"},
                status_code=403,
            )
    return await call_next(request)

# Phase 11.B (#507) — serve the WebUI assets on the same origin as
# the FastAPI HTML pages.  Required because the kbin vhost routes
# through HAProxy directly to uvicorn (bypassing nginx), so the
# nginx /toolbox/ alias never gets a chance to match.
_TOOLBOX_WWW = Path("/usr/share/secubox/www/toolbox")
if _TOOLBOX_WWW.is_dir():
    app.mount("/toolbox", StaticFiles(directory=_TOOLBOX_WWW), name="toolbox-www")


@app.on_event("startup")
async def _startup() -> None:
    """Spawn periodic purge task + threat-intel refresh loop."""
    async def purge_loop() -> None:
        while True:
            try:
                store.purge_expired()
            except Exception as e:
                _log.error("purge failed: %s", e)
            await asyncio.sleep(3600)
    asyncio.create_task(purge_loop())
    # Threat-intel feeds : kick off immediate refresh + hourly loop
    asyncio.create_task(threat_intel.refresh_loop())
    # Phase 11.A (#505) — social-mapping fold + retention purge.
    # Fold every 5 min : raw edges → aggregate nodes + links.
    # Purge raw edges older than 7 d once an hour.
    async def social_fold_loop() -> None:
        while True:
            try:
                social.fold_recent(window_seconds=600)
            except Exception as e:
                _log.error("social.fold_recent failed: %s", e)
            await asyncio.sleep(300)

    async def social_purge_loop() -> None:
        while True:
            try:
                social.purge_older_than(days=7)
                # Phase 13.C (#524) — device-blocks retention.
                try:
                    from . import device_blocks as _db
                    _db.purge_older_than(days=7)
                except Exception:
                    pass
            except Exception as e:
                _log.error("social.purge_older_than failed: %s", e)
            await asyncio.sleep(3600)

    asyncio.create_task(social_fold_loop())
    asyncio.create_task(social_purge_loop())
