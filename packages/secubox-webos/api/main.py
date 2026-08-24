# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: WebOS — API registre normalisé (P1)."""
from fastapi import FastAPI

app = FastAPI(title="SecuBox WebOS", root_path="/api/v1/webos")

@app.get("/healthz")
async def healthz():
    return {"status": "ok"}
