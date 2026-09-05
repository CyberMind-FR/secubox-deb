# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Service-restart route — allow-listed systemd unit names only."""
from __future__ import annotations

import subprocess

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

router = APIRouter(prefix="/service", tags=["service"])

# Strict allow-list. Match systemd unit names; no patterns, no wildcards.
ALLOWED_UNITS = frozenset({
    "secubox-hub",
    "secubox-auth",
    "secubox-system",
    "secubox-wireguard",
    "secubox-dpi",
    "secubox-dns",
})

# Unit-name regex: lowercase alnum + dot/dash/underscore, must start and end with alnum
_UNIT_PATTERN = r"^[a-z0-9][a-z0-9._-]*[a-z0-9]$"


class RestartRequest(BaseModel):
    unit: str = Field(..., min_length=3, max_length=128, pattern=_UNIT_PATTERN)


def _run_systemctl(verb: str, unit: str) -> tuple[str, int]:
    """Run `systemctl <verb> <unit>`. Returns (stdout, rc)."""
    result = subprocess.run(
        ["systemctl", verb, unit],
        capture_output=True,
        text=True,
        timeout=30,
    )
    return result.stdout.strip(), result.returncode


@router.post("/restart")
async def restart_service(request: RestartRequest):
    if request.unit not in ALLOWED_UNITS:
        raise HTTPException(status_code=403, detail=f"unit '{request.unit}' not in allow-list")
    stdout, rc = _run_systemctl("restart", request.unit)
    if rc != 0:
        raise HTTPException(status_code=500, detail=f"systemctl restart failed: {stdout}")
    return {"unit": request.unit, "verb": "restart", "exit_code": rc}
