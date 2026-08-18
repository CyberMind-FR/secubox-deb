# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Phase 2 deprecation shims. Each handler forwards to a Rspamd-equivalent
and emits the `X-Deprecated-Endpoint: rspamd` header. Removed in v3.0.
"""
from __future__ import annotations

import pathlib
import subprocess

from fastapi import APIRouter, Depends, Response
from secubox_core.auth import require_jwt

from .. import rspamd_client

router = APIRouter(tags=["legacy-deprecated"])


def _depr(resp: Response) -> None:
    resp.headers["x-deprecated-endpoint"] = "rspamd"


# ─── /dkim/* ──────────────────────────────────────────────────────────────────

@router.get("/dkim/status", dependencies=[Depends(require_jwt)])
async def dkim_status(response: Response) -> dict:
    _depr(response)
    return await rspamd_client.get("/stat")


@router.get("/dkim/record", dependencies=[Depends(require_jwt)])
async def dkim_record(response: Response) -> dict:
    _depr(response)
    txt = pathlib.Path("/data/volumes/mail/rspamd/dkim/secubox.in/default.txt")
    return {"record": txt.read_text() if txt.exists() else None}


@router.post("/dkim/setup", dependencies=[Depends(require_jwt)])
async def dkim_setup(response: Response) -> dict:
    _depr(response)
    proc = subprocess.run(
        ["/usr/sbin/mailctl", "rspamd", "dkim-keygen", "secubox.in", "default"],
        capture_output=True, text=True, timeout=60,
    )
    return {"success": proc.returncode == 0, "stdout": proc.stdout[-500:]}


@router.post("/dkim/keygen", dependencies=[Depends(require_jwt)])
async def dkim_keygen(response: Response) -> dict:
    _depr(response)
    return await dkim_setup(response)


@router.post("/dkim/sync", dependencies=[Depends(require_jwt)])
async def dkim_sync(response: Response) -> dict:
    _depr(response)
    return {"success": True, "note": "Rspamd reads DKIM keys via bind-mount — no sync needed"}


# ─── /spam/* ──────────────────────────────────────────────────────────────────

@router.get("/spam/status", dependencies=[Depends(require_jwt)])
async def spam_status(response: Response) -> dict:
    _depr(response)
    r = await rspamd_client.get("/stat")
    return {
        "installed": True,
        "configured": True,
        "enabled": "error" not in r,
        "via": "rspamd",
        "rspamd_stat": r,
    }


@router.post("/spam/setup", dependencies=[Depends(require_jwt)])
async def spam_setup(response: Response) -> dict:
    _depr(response)
    return {"success": True, "note": "Rspamd is configured at install time"}


@router.post("/spam/enable", dependencies=[Depends(require_jwt)])
async def spam_enable(response: Response) -> dict:
    _depr(response)
    return await rspamd_client.post("/reload")


@router.post("/spam/disable", dependencies=[Depends(require_jwt)])
async def spam_disable(response: Response) -> dict:
    _depr(response)
    return {"success": False, "error": "disabling Rspamd requires lxc-attach systemctl stop rspamd"}


@router.post("/spam/update", dependencies=[Depends(require_jwt)])
async def spam_update(response: Response) -> dict:
    _depr(response)
    return {"success": True, "note": "Rspamd updates via apt-get"}


# ─── /grey/* ──────────────────────────────────────────────────────────────────

@router.get("/grey/status", dependencies=[Depends(require_jwt)])
async def grey_status(response: Response) -> dict:
    _depr(response)
    return await rspamd_client.get("/stat")


@router.post("/grey/setup", dependencies=[Depends(require_jwt)])
async def grey_setup(response: Response) -> dict:
    _depr(response)
    return {"success": True, "note": "Greylist module lives inside Rspamd (see greylist.conf)"}


@router.post("/grey/enable", dependencies=[Depends(require_jwt)])
async def grey_enable(response: Response) -> dict:
    _depr(response)
    return await rspamd_client.post("/reload")


@router.post("/grey/disable", dependencies=[Depends(require_jwt)])
async def grey_disable(response: Response) -> dict:
    _depr(response)
    return {"success": False, "error": "set greylist.conf disabled=true via mailctl rspamd reload"}
