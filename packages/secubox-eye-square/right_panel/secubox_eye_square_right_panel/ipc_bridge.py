# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""WebSocket bridge — receives Chromium TM events, dispatches to registered hooks.

Hosted by the PySide6 right-panel process (via qasync event-loop integration).
Chromium's `square-bridge.js` connects to ws://127.0.0.1:9090/eye-square and
sends JSON events `{event: "module:tap", module: "AUTH"}` and
`{event: "transport:status", active: "WiFi"}`.
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Callable

import websockets

log = logging.getLogger("eye_square_right_panel.ipc_bridge")


class IPCBridge:
    """WS server. Bind to host:port (defaults 127.0.0.1:9090). Listens for events."""

    def __init__(self, host: str = "127.0.0.1", port: int = 9090):
        self.host = host
        self.port = port
        # Default no-op hooks — overridden by RightPanelWindow at construction time
        self.on_module_tap: Callable[[str], None] = lambda mod: None
        self.on_transport_change: Callable[[str], None] = lambda active: None
        self._stop = asyncio.Event()

    async def _handler(self, ws):
        async for message in ws:
            try:
                msg = json.loads(message)
            except (json.JSONDecodeError, TypeError):
                log.warning("ignored non-JSON message")
                continue
            if not isinstance(msg, dict):
                log.warning("ignored non-dict payload")
                continue
            evt = msg.get("event")
            if evt == "module:tap":
                module = msg.get("module", "")
                try:
                    self.on_module_tap(module)
                except Exception as e:
                    log.warning("on_module_tap raised: %s", e)
            elif evt == "transport:status":
                active = msg.get("active", "")
                try:
                    self.on_transport_change(active)
                except Exception as e:
                    log.warning("on_transport_change raised: %s", e)
            else:
                log.debug("unknown event %s", evt)

    async def serve(self):
        async with websockets.serve(self._handler, self.host, self.port):
            log.info("IPCBridge listening on ws://%s:%s/eye-square", self.host, self.port)
            await self._stop.wait()

    def stop(self):
        self._stop.set()
