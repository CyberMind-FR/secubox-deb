# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: meshtastic — API web (webui backend)
CyberMind — https://cybermind.fr

Thin FastAPI factory over three injected collaborators — mirrors the
webui-delegates-to-ctl pattern from packages/secubox-profiles/api/web.py
(see .claude/MODULE-COMPLIANCE.md → Privileged Operations):

  * `cache`   — a StateCache-like object (api/cache.py); `.get()` returns the
    mesh snapshot (radio/mode/nodes/messages_by_channel/census/channel_stats).
    Read routes only ever serve this dict — never touch the radio directly.
  * `send_cb(channel, text) -> dict`   — the daemon's own send path (real-time
    action, deliberately NOT delegated to the privileged ctl: sending a text
    message needs no root and no config write).
  * `ctl_cb(verb, **kwargs) -> dict`   — privileged config change, delegated
    to secubox-meshtasticctl (in prod: sudo -n systemd-run ... ctl; in tests:
    a fake). Both action endpoints VALIDATE the request against the same
    enums the ctl itself enforces (config.MODES / config.GRIDS) BEFORE
    calling out — a bad value must never reach send_cb/ctl_cb (422, not a
    ctl-side rejection), exactly like profiles' set_pin/set_lifecycle refuse
    structurally before any sudo.

This module only ever READS cache and calls the two injected callables —
it never shells out itself (see test_web.py's grep-level guard, mirroring
profiles' test_web_module_has_no_actuation_helper).
"""
from __future__ import annotations

import sys
from typing import Any, Callable

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel

# secubox_core is a Debian dist-packages module, never a venv (see
# secubox-profiles/api/web.py, same topology: dedicated socket, system
# python3). Fallback keeps `import api.web` usable in a dev/test env where
# secubox_core is not installed system-wide but IS on sys.path via
# tests/conftest.py + the repo's common/ dir (see tests/test_web.py).
sys.path.insert(0, "/usr/lib/python3/dist-packages")
try:
    from secubox_core.auth import require_jwt
except ImportError:  # pragma: no cover - dev sans secubox_core installé
    async def require_jwt():
        return {"sub": "admin"}

from .config import GRIDS, MODES

PREFIX = "/api/v1/meshtastic"


class SendBody(BaseModel):
    channel: int
    text: str


class ModeBody(BaseModel):
    mode: str


class GridBody(BaseModel):
    channel: str
    grid: list[str]


def create_app(
    cache: Any,
    send_cb: Callable[[int, str], dict],
    ctl_cb: Callable[..., dict],
    channel_url_cb: Callable[[], dict] | None = None,
) -> FastAPI:
    app = FastAPI(
        title="SecuBox Meshtastic API",
        description="Radio Meshtastic — statut, nœuds, messages, feed passif, "
                     "envoi et config privilégiée (déléguée au ctl).",
        version="1.0.0",
        docs_url="/docs",
        redoc_url=None,
    )

    @app.get(f"{PREFIX}/status")
    async def get_status(_claims=Depends(require_jwt)):
        return cache.get()

    @app.get(f"{PREFIX}/nodes")
    async def get_nodes(_claims=Depends(require_jwt)):
        return cache.get().get("nodes", [])

    @app.get(f"{PREFIX}/messages")
    async def get_messages(_claims=Depends(require_jwt)):
        return cache.get().get("messages_by_channel", {})

    @app.get(f"{PREFIX}/packets")
    async def get_packets(_claims=Depends(require_jwt)):
        state = cache.get()
        return {
            "census": state.get("census", []),
            "channel_stats": state.get("channel_stats", {}),
        }

    @app.post(f"{PREFIX}/send")
    async def send_message(body: SendBody, _claims=Depends(require_jwt)):
        return send_cb(body.channel, body.text)

    @app.get(f"{PREFIX}/channel-url")
    async def get_channel_url(_claims=Depends(require_jwt)):
        # Sharable Meshtastic channel URL (encodes name + PSK + LoRa config) so
        # another device / phone can JOIN this mesh. It reveals the channel key
        # by design — JWT-gated, and the daemon audit-logs each disclosure.
        if channel_url_cb is None:
            raise HTTPException(status_code=503, detail="radio absent")
        return channel_url_cb()

    @app.post(f"{PREFIX}/mode")
    async def set_mode(body: ModeBody, _claims=Depends(require_jwt)):
        # Refus STRUCTUREL avant tout ctl_cb (comme set_pin/set_lifecycle
        # dans secubox-profiles) : une valeur hors énum ne doit jamais
        # atteindre le ctl privilégié.
        if body.mode not in MODES:
            raise HTTPException(
                status_code=422,
                detail=f"mode invalide: {body.mode!r} (attendu {MODES})",
            )
        return ctl_cb("set-mode", mode=body.mode)

    @app.post(f"{PREFIX}/grid")
    async def set_grid(body: GridBody, _claims=Depends(require_jwt)):
        bad = [g for g in body.grid if g not in GRIDS]
        if bad:
            raise HTTPException(
                status_code=422,
                detail=f"grid inconnu {bad} (attendu {GRIDS})",
            )
        return ctl_cb("set-grid", channel=body.channel, grid=body.grid)

    return app
