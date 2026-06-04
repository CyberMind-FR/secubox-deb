# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

"""ToolBoX entry point (uvicorn)."""
from __future__ import annotations

import asyncio
import logging

from fastapi import FastAPI

from . import __version__, store
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


@app.on_event("startup")
async def _startup() -> None:
    """Spawn periodic purge task."""
    async def loop() -> None:
        while True:
            try:
                store.purge_expired()
            except Exception as e:
                _log.error("purge failed: %s", e)
            await asyncio.sleep(3600)
    asyncio.create_task(loop())
