# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

"""ToolBoX entry point (uvicorn)."""
from __future__ import annotations

import asyncio
import logging
from pathlib import Path

from fastapi import FastAPI
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
            except Exception as e:
                _log.error("social.purge_older_than failed: %s", e)
            await asyncio.sleep(3600)

    asyncio.create_task(social_fold_loop())
    asyncio.create_task(social_purge_loop())
