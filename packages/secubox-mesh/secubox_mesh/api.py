# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: MESH — router FastAPI (5 endpoints, asyncio.to_thread).
Spec : CM-MESH-MPCIE-2026-06 §5.
CyberMind — https://cybermind.fr
"""
from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter, HTTPException

from . import ap, mesh, rf
from .config import load_config
from .models import APClient, Config, Peer, RegRequest, RFState

log = logging.getLogger("secubox.mesh")

router = APIRouter(tags=["mesh"])

# Lazy : la config se charge à la première requête, pas à l'import.
# Évite de crasher Uvicorn / les tests si /etc/secubox/mesh.toml manque.
_cfg: Config | None = None


def _get_cfg() -> Config:
    global _cfg
    if _cfg is None:
        _cfg = load_config()
    return _cfg


@router.get("/mesh/peers", response_model=list[Peer])
async def mesh_peers() -> list[Peer]:
    cfg = _get_cfg()
    return await asyncio.to_thread(mesh.list_peers, cfg.radio.iface)


@router.get("/mesh/rf", response_model=RFState)
async def mesh_rf() -> RFState:
    cfg = _get_cfg()
    return await asyncio.to_thread(rf.state, cfg.radio.iface)


@router.post("/mesh/key/rotate")
async def mesh_key_rotate() -> dict:
    # PFS 24h logique métier — l'effet réel dépend du chipset (cf. WARN startup).
    return await asyncio.to_thread(mesh.rotate_key, _get_cfg())


@router.get("/ap/clients", response_model=list[APClient])
async def ap_clients() -> list[APClient]:
    cfg = _get_cfg()
    if not cfg.ap.enabled:
        return []
    return await asyncio.to_thread(ap.clients, cfg.radio.iface)


@router.post("/reg/domain")
async def reg_domain(req: RegRequest) -> dict:
    log.warning("REG override request: country=%s reason=%s", req.country, req.reason)
    try:
        return await asyncio.to_thread(rf.set_domain, req.country, _get_cfg())
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/health")
async def health() -> dict:
    """Liveness — pas de dépendance externe."""
    return {"status": "ok", "module": "mesh", "version": "2.0.0"}
