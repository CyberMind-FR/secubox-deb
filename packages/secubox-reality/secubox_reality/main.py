# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: Reality — ASGI entry point
CyberMind — https://cybermind.fr

Not part of the module spec's explicit file list, but required as the
uvicorn target referenced by ``debian/secubox-reality.service``
(``uvicorn secubox_reality.main:app``). Kept minimal on purpose: all
behaviour lives in ``router.py``.
"""
from __future__ import annotations

from fastapi import FastAPI

from . import store
from .router import router

app = FastAPI(title="SecuBox Reality", version="0.1.0")
app.include_router(router)


@app.on_event("startup")
def _startup() -> None:
    store.init_db()


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok", "module": "reality"}
