# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""secubox-crowdsec — bouncers and machines management"""
import subprocess
import json
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional
from secubox_core.auth import require_jwt

router = APIRouter()


class BouncerAdd(BaseModel):
    name: str


@router.get("/bouncers")
async def bouncers():
    """Get bouncers for dashboard (public)."""
    try:
        r = subprocess.run(
            "sudo cscli bouncers list -o json 2>/dev/null",
            shell=True, capture_output=True, text=True, timeout=10
        )
        if r.returncode == 0 and r.stdout.strip():
            data = json.loads(r.stdout)
            return {"bouncers": data if isinstance(data, list) else []}
    except Exception:
        pass
    return {"bouncers": []}


@router.post("/bouncers/add")
async def add_bouncer(req: BouncerAdd, user=Depends(require_jwt)):
    """Add a new bouncer."""
    try:
        r = subprocess.run(
            f"sudo cscli bouncers add {req.name} -o json 2>&1",
            shell=True, capture_output=True, text=True, timeout=10
        )
        if r.returncode == 0:
            return {"success": True, "output": r.stdout}
        return {"success": False, "error": r.stdout + r.stderr}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/bouncers/{name}")
async def delete_bouncer(name: str, user=Depends(require_jwt)):
    """Delete a bouncer."""
    try:
        r = subprocess.run(
            f"sudo cscli bouncers delete {name} 2>&1",
            shell=True, capture_output=True, text=True, timeout=10
        )
        if r.returncode == 0:
            return {"success": True}
        return {"success": False, "error": r.stdout + r.stderr}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/machines")
async def machines(user=Depends(require_jwt)):
    """Get machines list."""
    try:
        r = subprocess.run(
            "sudo cscli machines list -o json 2>/dev/null",
            shell=True, capture_output=True, text=True, timeout=10
        )
        if r.returncode == 0 and r.stdout.strip():
            return json.loads(r.stdout)
    except Exception:
        pass
    return []
