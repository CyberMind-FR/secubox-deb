# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: Reality — REST surface (/api/mesh/reality)
CyberMind — https://cybermind.fr

===============================================================================
Hamiltonian path: AUTH -> WALL -> BOOT -> MIND -> ROOT -> MESH
===============================================================================

  AUTH   xray.auth_provision_identity()   x25519 keypair + UUID + shortIds,
                                          invoked from POST /servers
  WALL   xray.wall_build_routing_rules()  split-tunnel routing rules baked
                                          into every generated config
  BOOT   service.boot_provision()         (re)start of secubox-xray@<id>,
                                          invoked from POST /apply
  MIND   validator.validate_target() +    target sanity gate (POST
         monitor.check_volume_guard()     /validate-target, POST /apply) and
                                          volume-guard decisioning (GET /stats)
  ROOT   store.*                          SQLite WAL persistence for every
                                          servers/clients/stats_samples read
                                          and write below
  MESH   xray.mesh_build_stream_settings() Reality transport, composed into
                                          the config written by BOOT

Every route in this router is JWT-gated via ``secubox_core.auth.require_jwt``
(router-level dependency — no route can accidentally skip it). Handlers that
shell out to xray/openssl/systemctl (directly, or transitively through
``xray.py`` / ``validator.py`` / ``service.py`` / ``monitor.py``) are declared
as plain ``def`` so FastAPI/Starlette runs them in a threadpool instead of on
the shared asyncio event loop.
"""
from __future__ import annotations

import uuid as _uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from secubox_core.auth import require_jwt

from . import monitor, service, store, validator, xray
from .models import (
    ApplyRequest,
    Client,
    ClientCreate,
    GuardConfig,
    Server,
    ServerCreate,
    ValidateTargetRequest,
)

router = APIRouter(prefix="/api/mesh/reality", dependencies=[Depends(require_jwt)])


def _ensure_db() -> None:
    store.init_db()


def _require_server(server_id: str) -> Dict[str, Any]:
    _ensure_db()
    srv = store.get_server(server_id)
    if srv is None:
        raise HTTPException(status_code=404, detail=f"server {server_id!r} not found")
    return srv


# --- servers (ROOT + AUTH) ---------------------------------------------------


@router.post("/servers", response_model=Server)
def create_server(payload: ServerCreate) -> Dict[str, Any]:
    """AUTH stage: provision x25519 keys + UUID + shortIds, then persist."""
    _ensure_db()
    try:
        identity = xray.auth_provision_identity(short_id_count=payload.short_id_count)
    except xray.XrayError as exc:
        raise HTTPException(status_code=502, detail=f"xray x25519 failed: {exc}") from exc

    server = {
        "id": str(_uuid.uuid4()),
        "remark": payload.remark,
        "private_key": identity["private_key"],
        "public_key": identity["public_key"],
        "uuid": identity["uuid"],
        "dest": payload.dest,
        "sni": payload.sni,
        "listen_port": payload.listen_port,
        "dest_port": payload.dest_port,
        "flow": payload.flow,
        "short_ids": identity["short_ids"],
        "status": "new",
    }
    return store.create_server(server)


@router.get("/servers", response_model=List[Server])
def list_servers() -> List[Dict[str, Any]]:
    _ensure_db()
    return store.list_servers()


@router.get("/servers/{server_id}", response_model=Server)
def get_server(server_id: str) -> Dict[str, Any]:
    return _require_server(server_id)


@router.delete("/servers/{server_id}")
def delete_server(server_id: str) -> Dict[str, str]:
    _require_server(server_id)
    # Best-effort: stop the running instance before dropping its state.
    service.stop_instance(server_id)
    service.disable_instance(server_id)
    store.delete_server(server_id)
    return {"status": "deleted", "id": server_id}


# --- MIND: target validation --------------------------------------------


@router.post("/validate-target")
def validate_target(payload: ValidateTargetRequest) -> Dict[str, Any]:
    try:
        return validator.validate_target(payload.host, payload.port)
    except validator.ValidatorError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


# --- BOOT: apply (write config + start instance) ----------------------------


@router.post("/apply")
def apply_server(payload: ApplyRequest, force: bool = Query(False)) -> Dict[str, Any]:
    srv = _require_server(payload.server_id)

    validation = None
    try:
        validation = validator.validate_target(srv["dest"], srv["dest_port"])
        validator.refuse_apply_if_insane(validation, force=force)
    except validator.ValidatorError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    clients = store.list_clients(server_id=srv["id"])
    config = xray.build_server_config(srv, clients=clients)

    try:
        status_snapshot = service.boot_provision(srv["id"], config)
    except service.ServiceError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    new_status = "running" if status_snapshot["running"] else "applied"
    store.update_server_status(srv["id"], new_status)

    return {"server": store.get_server(srv["id"]), "validation": validation, "instance": status_snapshot}


# --- clients (ROOT) ----------------------------------------------------


@router.post("/clients", response_model=Client)
def create_client(payload: ClientCreate) -> Dict[str, Any]:
    _require_server(payload.server_id)
    client = {
        "id": str(_uuid.uuid4()),
        "server_id": payload.server_id,
        "uuid": xray.generate_uuid(),
        "email": payload.email,
        "short_id": xray.generate_short_ids(1)[0],
        "flow": payload.flow,
    }
    return store.create_client(client)


@router.get("/clients", response_model=List[Client])
def list_clients(server_id: Optional[str] = Query(None)) -> List[Dict[str, Any]]:
    _ensure_db()
    return store.list_clients(server_id=server_id)


@router.delete("/clients/{client_id}")
def delete_client(client_id: str) -> Dict[str, str]:
    _ensure_db()
    client = store.get_client(client_id)
    if client is None:
        raise HTTPException(status_code=404, detail=f"client {client_id!r} not found")
    store.delete_client(client_id)
    return {"status": "deleted", "id": client_id}


# --- link + QR ---------------------------------------------------------


@router.get("/link")
def get_link(client_id: str = Query(...)) -> Dict[str, Any]:
    _ensure_db()
    client = store.get_client(client_id)
    if client is None:
        raise HTTPException(status_code=404, detail=f"client {client_id!r} not found")
    srv = _require_server(client["server_id"])

    uri = xray.build_vless_uri(
        uuid_value=client["uuid"],
        host=srv["sni"],
        port=srv["listen_port"],
        public_key=srv["public_key"],
        short_id=client["short_id"],
        sni=srv["sni"],
        flow=client.get("flow") or srv.get("flow") or "xtls-rprx-vision",
        remark=f"{srv['remark']}-{client['email']}",
    )
    try:
        qr_svg = xray.generate_qr_svg(uri)
    except ImportError:
        qr_svg = None

    return {"uri": uri, "qr_svg": qr_svg}


# --- MIND: volume guard --------------------------------------------------


@router.get("/guard", response_model=GuardConfig)
def get_guard() -> GuardConfig:
    return monitor.load_guard_config()


@router.put("/guard", response_model=GuardConfig)
def put_guard(payload: GuardConfig) -> GuardConfig:
    monitor.save_guard_config(payload)
    return payload


@router.get("/stats")
def get_stats(server_id: Optional[str] = Query(None)) -> Dict[str, Any]:
    _ensure_db()
    guard = monitor.load_guard_config()
    if server_id:
        _require_server(server_id)
        monitor.sample_server(server_id)
        return monitor.check_volume_guard(server_id, guard)
    return {"servers": monitor.run_all(guard)}
