# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""API locale de secubox-garde (#3794) sur /run/secubox/garde.sock.

Squelette : la sonde /health est ouverte, /etat exige la garde de lecture. Les routes d'action
(libérer, débannir, réglages) viendront avec `require_jwt`.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict

from fastapi import APIRouter, Depends, FastAPI

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from secubox_core.auth import require_jwt, require_lecture  # noqa: E402,F401

from garde import base  # noqa: E402

router = APIRouter(prefix="/api/v1/garde")


@router.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok", "module": "garde"}


@router.get("/etat", dependencies=[Depends(require_lecture)])
def etat() -> Dict[str, Any]:
    r = base.reglages()
    return {"automatique": r["automatique"]}


app = FastAPI(title="SecuBox Garde", docs_url=None, redoc_url=None, openapi_url=None)
app.include_router(router)
