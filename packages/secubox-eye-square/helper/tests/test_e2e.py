# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""E2E: spin up helper FastAPI on a Unix socket, call it via HelperClient."""
from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

import pytest
import uvicorn

# Make helper + right_panel importable
HELPER_PKG = Path(__file__).resolve().parent.parent
RP_PKG = Path(__file__).resolve().parent.parent.parent / "right_panel"
if str(HELPER_PKG) not in sys.path:
    sys.path.insert(0, str(HELPER_PKG))
if str(RP_PKG) not in sys.path:
    sys.path.insert(0, str(RP_PKG))

from eye_square_helper.app import create_app
from secubox_eye_square_right_panel.helper_client import HelperClient


@pytest.mark.asyncio
async def test_e2e_helper_accepts_uds_connection(tmp_path):
    """Boot uvicorn on a UDS, verify HelperClient can reach the socket."""
    sock = tmp_path / "helper.sock"
    app = create_app()
    config = uvicorn.Config(app, uds=str(sock), log_level="warning")
    server = uvicorn.Server(config)
    server_task = asyncio.create_task(server.serve())
    # wait for socket
    for _ in range(50):
        await asyncio.sleep(0.05)
        if sock.exists():
            break

    client = HelperClient(str(sock))
    try:
        # /health will hit peer-cred middleware. On a real UDS the calling
        # process's UID is read; if our UID isn't in ALLOWED_UIDS (which it
        # likely isn't in CI since secubox-eye-square isn't installed),
        # we get a 403 — not 401. Either way the socket and routing work.
        try:
            await client._get("/health")
        except Exception as e:
            # Acceptable: 401 (no socket), 403 (UID rejected). Confirms
            # the server is up and routing requests through middleware.
            msg = str(e).lower()
            assert "401" in msg or "403" in msg or "client error" in msg, f"unexpected: {e}"
    finally:
        server.should_exit = True
        try:
            await asyncio.wait_for(server_task, timeout=5.0)
        except asyncio.TimeoutError:
            server_task.cancel()
