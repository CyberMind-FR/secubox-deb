# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Phase 2 Rspamd router. JWT-protected via Depends(require_jwt)."""
from __future__ import annotations

import pathlib
import subprocess

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from secubox_core.auth import require_jwt

from .. import rspamd_client

router = APIRouter(prefix="/rspamd", tags=["rspamd"])


# ─── Read endpoints ───────────────────────────────────────────────────────────

@router.get("/status", dependencies=[Depends(require_jwt)])
async def status() -> dict:
    """Rspamd stat + module summary."""
    return await rspamd_client.get("/stat")


@router.get("/history", dependencies=[Depends(require_jwt)])
async def history(limit: int = 100) -> dict:
    """Recent scan history (truncated)."""
    return await rspamd_client.get(f"/history?limit={limit}")


@router.get("/scores", dependencies=[Depends(require_jwt)])
async def scores() -> dict:
    """Top-N rule contributions to recent scores."""
    return await rspamd_client.get("/graph")


# ─── Write endpoints ──────────────────────────────────────────────────────────

@router.post("/reload", dependencies=[Depends(require_jwt)])
async def reload_rspamd() -> dict:
    """Graceful Rspamd reload."""
    return await rspamd_client.post("/reload")


class LearnRequest(BaseModel):
    raw_eml: str | None = None
    message_id: str | None = None


@router.post("/learn-spam", dependencies=[Depends(require_jwt)])
async def learn_spam(req: LearnRequest) -> dict:
    if req.raw_eml:
        return await rspamd_client.post("/learnspam", body=req.raw_eml.encode())
    if req.message_id:
        return {"error": "message_id learning requires Phase 5 Roundcube integration"}
    return {"error": "either raw_eml or message_id required"}


@router.post("/learn-ham", dependencies=[Depends(require_jwt)])
async def learn_ham(req: LearnRequest) -> dict:
    if req.raw_eml:
        return await rspamd_client.post("/learnham", body=req.raw_eml.encode())
    if req.message_id:
        return {"error": "message_id learning requires Phase 5 Roundcube integration"}
    return {"error": "either raw_eml or message_id required"}


# ─── Whitelist (Phase 2 = read; write deferred to Phase 8) ───────────────────

class WhitelistEntry(BaseModel):
    address: str
    type: str = "from"   # from | rcpt | ip


@router.get("/whitelist", dependencies=[Depends(require_jwt)])
async def whitelist_list() -> dict:
    return await rspamd_client.get("/maps")


@router.post("/whitelist", dependencies=[Depends(require_jwt)])
async def whitelist_add(entry: WhitelistEntry) -> dict:
    return {"error": "whitelist add requires Phase 8 admin UI", "entry": entry.model_dump()}


@router.delete("/whitelist/{entry_id}", dependencies=[Depends(require_jwt)])
async def whitelist_del(entry_id: str) -> dict:
    return {"error": "whitelist delete requires Phase 8 admin UI", "id": entry_id}


# ─── DKIM ─────────────────────────────────────────────────────────────────────

@router.get("/dkim/{domain}", dependencies=[Depends(require_jwt)])
async def dkim_status(domain: str) -> dict:
    """Show DKIM key info for a domain."""
    base = pathlib.Path(f"/data/volumes/mail/rspamd/dkim/{domain}")
    key = base / "default.key"
    txt = base / "default.txt"
    return {
        "domain": domain,
        "selector": "default",
        "key_present": key.exists(),
        "dns_txt": txt.read_text() if txt.exists() else None,
    }


@router.post("/dkim/{domain}/keygen", dependencies=[Depends(require_jwt)])
async def dkim_keygen(domain: str) -> dict:
    """Run mailctl rspamd dkim-keygen for the given domain."""
    proc = subprocess.run(
        ["/usr/sbin/mailctl", "rspamd", "dkim-keygen", domain, "default"],
        capture_output=True, text=True, timeout=60,
    )
    return {
        "success": proc.returncode == 0,
        "stdout": proc.stdout[-500:],
        "stderr": proc.stderr[-500:],
    }
