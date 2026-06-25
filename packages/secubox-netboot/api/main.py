# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-netboot (#737, Phase 2)
Provisioning réseau + overlay U-Boot. API de suivi/contrôle.
CyberMind — https://cybermind.fr

Servi en STANDALONE (socket /run/secubox/netboot.sock) car les opérations sont
privilégiées (fw_setenv) et bloquantes — jamais in-process dans l'aggregator.
Aucune opération destructive (overlay apply/revert, flash) sans confirm=true.
"""
from fastapi import FastAPI, APIRouter, Depends, HTTPException
from pydantic import BaseModel
import asyncio
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from secubox_core.auth import router as auth_router, require_jwt

app = FastAPI(title="secubox-netboot", version="0.2.0", root_path="/api/v1/netboot")

PROBE = "/usr/sbin/secubox-netboot-probe"
OVERLAY = "/usr/sbin/secubox-netboot-overlay"
TRIGGERS = "/usr/sbin/secubox-netboot-triggers"
SHADOW = Path("/boot/secubox-netboot/shadow")
CATALOG = Path("/var/lib/secubox/netboot/images.json")     # catalogue release signées
AUDIT = Path("/var/log/secubox/netboot/audit.log")


@app.get("/health")
async def health():
    """Public health check (sidebar status)."""
    return {"status": "ok", "module": "netboot"}


app.include_router(auth_router, prefix="/auth")
router = APIRouter()


async def _run(*argv: str, timeout: int = 60) -> Dict[str, Any]:
    """Run a privileged sbin helper; return {rc, stdout, stderr}."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return {"rc": proc.returncode,
                "stdout": (out or b"").decode("utf-8", "ignore"),
                "stderr": (err or b"").decode("utf-8", "ignore")}
    except asyncio.TimeoutError:
        return {"rc": 124, "stdout": "", "stderr": f"timeout after {timeout}s"}
    except FileNotFoundError:
        return {"rc": 127, "stdout": "", "stderr": f"helper absent: {argv[0]}"}


def _json_or_raw(s: str) -> Any:
    try:
        return json.loads(s)
    except Exception:
        return {"raw": s.strip()}


# ── lecture (read-only) ──────────────────────────────────────────────────────

@router.get("/probe")
async def probe(user=Depends(require_jwt)):
    """Détection read-only du board/boot-stack (board, média, capacités U-Boot)."""
    r = await _run(PROBE, timeout=30)
    return {"probe": _json_or_raw(r["stdout"]), "error": r["stderr"] or None}


@router.get("/status")
async def status(user=Depends(require_jwt)):
    """État de l'overlay (env_ok, overlay_active, bootcount, backup usine)."""
    r = await _run(OVERLAY, "status", timeout=20)
    return {"status": _json_or_raw(r["stdout"]), "error": r["stderr"] or None}


@router.get("/inventory")
async def inventory(user=Depends(require_jwt)):
    """Vue board = probe + état overlay (1 board ici ; multi-board en P3)."""
    p = await _run(PROBE, timeout=30)
    s = await _run(OVERLAY, "status", timeout=20)
    return {"board": _json_or_raw(p["stdout"]), "overlay": _json_or_raw(s["stdout"])}


@router.get("/images")
async def images(user=Depends(require_jwt)):
    """Catalogue des images release signées (version, board, url, sig)."""
    if CATALOG.exists():
        try:
            return {"images": json.loads(CATALOG.read_text())}
        except Exception:
            pass
    return {"images": []}


@router.get("/audit")
async def audit(limit: int = 200, user=Depends(require_jwt)):
    """Journal d'audit (append-only) — derniers événements."""
    if not AUDIT.exists():
        return {"audit": []}
    try:
        lines = AUDIT.read_text(errors="ignore").splitlines()[-limit:]
        return {"audit": list(reversed(lines))}
    except Exception:
        return {"audit": []}


# ── contrôle (gated par confirm=true) ────────────────────────────────────────

class OverlayAction(BaseModel):
    confirm: bool = False     # sans confirm → DRY-RUN uniquement


@router.post("/overlay/apply")
async def overlay_apply(req: OverlayAction, user=Depends(require_jwt)):
    """Pose l'overlay 2ᵉ U-Boot. confirm=false → DRY-RUN ; confirm=true → --commit.
    Refusé si l'env n'est pas calibré ou le FIT shadow non signé (côté helper)."""
    args = [OVERLAY, "apply"] + (["--commit"] if req.confirm else [])
    r = await _run(*args, timeout=120)
    if r["rc"] != 0 and req.confirm:
        raise HTTPException(409, r["stderr"].strip() or "apply échoué")
    await _run(TRIGGERS, "post-overlay", timeout=30)
    return {"committed": req.confirm, "result": r["stdout"], "error": r["stderr"] or None}


@router.post("/overlay/revert")
async def overlay_revert(req: OverlayAction, user=Depends(require_jwt)):
    """Retire l'overlay → restaure l'amorce usine. confirm=true requis pour agir."""
    args = [OVERLAY, "revert"] + (["--commit"] if req.confirm else [])
    r = await _run(*args, timeout=60)
    if r["rc"] != 0 and req.confirm:
        raise HTTPException(409, r["stderr"].strip() or "revert échoué")
    return {"committed": req.confirm, "result": r["stdout"], "error": r["stderr"] or None}


@router.post("/overlay/confirm-healthy")
async def overlay_confirm_healthy(user=Depends(require_jwt)):
    """Marque le boot courant comme sain (bootcount=0)."""
    r = await _run(OVERLAY, "confirm-healthy", timeout=20)
    return {"ok": r["rc"] == 0, "error": r["stderr"] or None}


@router.get("/shadow")
async def shadow(user=Depends(require_jwt)):
    """Contenu du shadow buffer (artefacts overlay prêts à poser)."""
    items = []
    if SHADOW.exists():
        for p in sorted(SHADOW.glob("*")):
            items.append({"name": p.name, "size": p.stat().st_size})
    return {"shadow_dir": str(SHADOW), "items": items}


app.include_router(router)
