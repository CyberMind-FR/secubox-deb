# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""USB gadget mode switching routes.

Wraps invocations of secubox-otg-gadget.sh with VARIANT=square and
GADGET_NAME=secubox-square so the configfs gadget directory is variant-specific.
"""
from __future__ import annotations

import os
import subprocess
from typing import Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/usb-gadget", tags=["usb-gadget"])

GadgetMode = Literal["normal", "flash", "debug", "tty", "auth"]
_GADGET_SCRIPT = os.environ.get(
    "EYE_SQUARE_GADGET_SCRIPT",
    "/usr/local/sbin/secubox-otg-gadget.sh",
)


class ModeRequest(BaseModel):
    mode: GadgetMode


def _run_gadget_script(argv: list[str]) -> tuple[str, int]:
    """Run secubox-otg-gadget.sh with GADGET_NAME=secubox-square. Returns (stdout, rc)."""
    env = os.environ.copy()
    env["GADGET_NAME"] = "secubox-square"
    env["VARIANT"] = "square"
    result = subprocess.run(
        [_GADGET_SCRIPT, *argv],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return result.stdout.strip(), result.returncode


@router.get("/state")
async def get_state():
    """Return the current USB gadget mode (parsed from script status)."""
    stdout, rc = _run_gadget_script(["status"])
    mode = "unknown"
    for line in stdout.splitlines():
        if line.lower().startswith("mode:"):
            mode = line.split(":", 1)[1].strip()
            break
    return {"mode": mode, "exit_code": rc}


@router.post("/mode")
async def set_mode(request: ModeRequest):
    """Atomically switch the USB gadget composite to the requested mode."""
    stdout, rc = _run_gadget_script([request.mode])
    if rc != 0:
        raise HTTPException(status_code=500, detail=f"gadget script failed: {stdout}")
    return {"mode": request.mode, "exit_code": rc}
