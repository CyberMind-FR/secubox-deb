# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Console WebSocket stream — tails /dev/ttyACM0 (satellite mode) or journalctl (kiosk mode)."""
from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path
from typing import AsyncIterator

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

router = APIRouter(prefix="/console", tags=["console"])
log = logging.getLogger("eye_square_helper.console")

TTY_DEVICE = os.environ.get("EYE_SQUARE_TTY_DEVICE", "/dev/ttyACM0")
TRANSPORT_STATE_FILE = Path(os.environ.get(
    "EYE_SQUARE_TRANSPORT_STATE",
    "/run/secubox/transport.state",
))


def _read_transport() -> str:
    """Read the current TransportManager state from the cache file."""
    try:
        return TRANSPORT_STATE_FILE.read_text().strip()
    except OSError:
        return "SIM"


def _select_source() -> str:
    """Choose source: tty device when OTG + present; otherwise journalctl."""
    if _read_transport() == "OTG" and os.path.exists(TTY_DEVICE):
        return TTY_DEVICE
    return "journalctl"


async def _spawn_tail(source: str) -> AsyncIterator[str]:
    """Spawn tail process and yield decoded lines."""
    if source == "journalctl":
        cmd = ["journalctl", "-u", "secubox-*", "-f", "--no-pager", "-o", "short"]
    else:
        cmd = ["cat", source]
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    assert proc.stdout is not None
    try:
        while True:
            line = await proc.stdout.readline()
            if not line:
                break
            yield line.decode("utf-8", errors="replace").rstrip()
    finally:
        if proc.returncode is None:
            try:
                proc.terminate()
            except ProcessLookupError:
                pass
            await proc.wait()


@router.websocket("/stream")
async def stream(ws: WebSocket):
    """Pump lines from the current source to the connected client."""
    await ws.accept()
    source = _select_source()
    log.info("console stream source: %s", source)
    try:
        async for line in _spawn_tail(source):
            await ws.send_text(line)
    except WebSocketDisconnect:
        log.debug("client disconnected")
