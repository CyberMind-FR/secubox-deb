# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""secubox-crowdsec — metrics router"""
from fastapi import APIRouter, Depends
import subprocess, json
from secubox_core.auth import require_jwt

router = APIRouter()


@router.get("/metrics")
async def metrics(user=Depends(require_jwt)):
    r = subprocess.run(
        ["cscli", "metrics", "--output", "json"],
        capture_output=True, text=True, timeout=15
    )
    try:
        return json.loads(r.stdout)
    except Exception:
        return {"raw": r.stdout[:2000]}
