# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Async client for the eye-square-helper FastAPI over its Unix socket."""
from __future__ import annotations

import logging
from typing import Any

import httpx

log = logging.getLogger("eye_square_right_panel.helper_client")


class HelperClient:
    """Calls the privileged helper at /run/secubox/eye-square-helper.sock.

    All methods are async. Each method does one POST or GET and returns the
    parsed JSON response. Failures propagate as httpx exceptions.
    """

    def __init__(self, socket_path: str, timeout: float = 10.0):
        self.socket_path = socket_path
        self.timeout = timeout

    async def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        transport = httpx.AsyncHTTPTransport(uds=self.socket_path)
        async with httpx.AsyncClient(transport=transport, base_url="http://localhost") as c:
            r = await c.post(path, json=payload, timeout=self.timeout)
            r.raise_for_status()
            return r.json()

    async def _get(self, path: str) -> dict[str, Any]:
        transport = httpx.AsyncHTTPTransport(uds=self.socket_path)
        async with httpx.AsyncClient(transport=transport, base_url="http://localhost") as c:
            r = await c.get(path, timeout=self.timeout)
            r.raise_for_status()
            return r.json()

    async def set_usb_mode(self, mode: str) -> dict[str, Any]:
        return await self._post("/usb-gadget/mode", {"mode": mode})

    async def get_usb_state(self) -> dict[str, Any]:
        return await self._get("/usb-gadget/state")

    async def restart_service(self, unit: str) -> dict[str, Any]:
        return await self._post("/service/restart", {"unit": unit})

    async def lockdown(self) -> dict[str, Any]:
        return await self._post("/lockdown", {"confirm": "lockdown"})
