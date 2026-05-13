# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""FastAPI application factory for the eye-square helper.

Binds to a Unix socket (set in __main__.py) and rejects any client whose
SO_PEERCRED UID is not in ALLOWED_UIDS. Routers will be added in Tasks 3-5.
"""
from __future__ import annotations

import logging
import os
import socket

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .auth import ALLOWED_UIDS, get_peer_uid

log = logging.getLogger("eye_square_helper")


def create_app() -> FastAPI:
    """Build the FastAPI app. Tasks 3-5 will add routers."""
    app = FastAPI(
        title="SecuBox Eye Square Helper",
        description="Privileged local operations for remote-ui/square/. Unix-socket only, SO_PEERCRED-authenticated.",
        version="0.1.0",
    )

    @app.middleware("http")
    async def peercred_auth(request: Request, call_next):
        # Best-effort peer-cred check. uvicorn over UDS exposes the underlying
        # transport via request.scope['transport'] or request['transport'] in
        # Starlette terms. We try a few paths to be resilient to version drift.
        #
        # NOTE: HTTPException raised inside @app.middleware("http") is NOT
        # caught by FastAPI's exception handlers — it propagates as a 500.
        # We must return a JSONResponse directly.
        sock = _extract_peer_socket(request)
        if sock is None:
            log.warning("No transport socket on request; rejecting")
            return JSONResponse(status_code=401, content={"detail": "cannot resolve peer"})
        try:
            uid = get_peer_uid(sock)
        except OSError as e:
            log.warning("SO_PEERCRED failed: %s", e)
            return JSONResponse(status_code=401, content={"detail": "peer credentials unavailable"})
        if uid not in ALLOWED_UIDS:
            log.warning("Rejecting UID %d (allowed: %s)", uid, sorted(ALLOWED_UIDS))
            return JSONResponse(status_code=403, content={"detail": "UID not allowed"})
        return await call_next(request)

    @app.get("/health")
    async def health():
        return {"status": "ok", "uid": os.getuid()}

    from .routes.usb_gadget import router as usb_gadget_router
    app.include_router(usb_gadget_router)

    return app


def _extract_peer_socket(request: Request) -> socket.socket | None:
    """Try several Starlette/uvicorn paths to find the connected peer socket."""
    scope = request.scope
    # uvicorn over UDS, modern Starlette: scope['extensions']['transport'] or similar
    for key in ("transport", "asgi-transport"):
        ts = scope.get(key)
        if ts is not None and hasattr(ts, "get_extra_info"):
            sock = ts.get_extra_info("socket")
            if sock is not None:
                return sock
    # Newer uvicorn versions expose the socket via the underlying transport
    # accessible through the protocol; the TestClient path won't have one.
    return None


app = create_app()
