# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Lockdown route — atomic nftables ruleset swap to deny-all. Audit-logged."""
from __future__ import annotations

import logging
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/lockdown", tags=["lockdown"])
log = logging.getLogger("eye_square_helper.lockdown")

LOCKDOWN_RULESET = os.environ.get(
    "EYE_SQUARE_LOCKDOWN_RULESET",
    "/etc/secubox/firewall/lockdown.nft",
)
AUDIT_LOG = Path(os.environ.get(
    "EYE_SQUARE_AUDIT_LOG",
    "/var/log/secubox/audit.log",
))


class LockdownRequest(BaseModel):
    confirm: Literal["lockdown"]


def _apply_lockdown() -> tuple[str, int]:
    """Run `nft -f LOCKDOWN_RULESET` and audit-log the action."""
    result = subprocess.run(
        ["nft", "-f", LOCKDOWN_RULESET],
        capture_output=True,
        text=True,
        timeout=30,
    )
    stdout = result.stdout.strip() or result.stderr.strip()
    rc = result.returncode
    ts = datetime.now(timezone.utc).isoformat()
    line = f"{ts} lockdown applied via eye-square-helper rc={rc}\n"
    try:
        AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
        with AUDIT_LOG.open("a") as f:
            f.write(line)
    except OSError as e:
        log.error("audit log write failed: %s", e)
    return stdout, rc


@router.post("")
async def lockdown(request: LockdownRequest):
    stdout, rc = _apply_lockdown()
    if rc != 0:
        raise HTTPException(status_code=500, detail=f"nft -f failed: {stdout}")
    return {"applied": True, "exit_code": rc}
