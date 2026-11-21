# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""API de DataScope (#3853) sur /run/secubox/datascope.sock — lecture seule, aucune route mutante.

V0.1, tâche 1 : sonde publique et état. Les routes de graphe viennent aux tâches suivantes.
Les lectures de fichier passent par `asyncio.to_thread` : jamais d'E/S bloquante sur la boucle.
"""
from __future__ import annotations

import asyncio
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, FastAPI

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from secubox_core.auth import require_lecture  # noqa: E402

from secubox_datascope import VERSION, config  # noqa: E402

CFG = config.charger()
router = APIRouter(prefix="/api/v1/datascope")


def _etat(cfg: config.Config) -> Dict[str, Any]:
    try:
        st = cfg.base.stat()
    except OSError:
        return {"module": "datascope", "base": "absente", "derniere_passe": None}
    passe: Optional[str] = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {"module": "datascope", "base": "ok", "derniere_passe": passe}


def status() -> Dict[str, Any]:
    return _etat(CFG)


@router.get("/health")
async def health() -> Dict[str, str]:
    return {"status": "ok", "module": "datascope", "version": VERSION}


@router.get("/status", dependencies=[Depends(require_lecture)])
async def status_route() -> Dict[str, Any]:
    return await asyncio.to_thread(status)


app = FastAPI(title="SecuBox DataScope", docs_url=None, redoc_url=None, openapi_url=None)
app.include_router(router)
