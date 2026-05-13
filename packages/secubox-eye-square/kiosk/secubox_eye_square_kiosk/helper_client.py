# packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/helper_client.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Sync httpx client for the eye-square-helper FastAPI Unix socket.

The kiosk is a single-threaded Python process; the helper exposes
privileged ops over /run/secubox/eye-square-helper.sock. All calls are
synchronous and propagate httpx exceptions to the caller.
"""
from __future__ import annotations

import logging
from typing import Any

import httpx

log = logging.getLogger("secubox_eye_square_kiosk.helper_client")


class HelperClient:
    """Calls the privileged helper. Construct once per process; thread-safe enough for kiosk."""

    def __init__(self, socket_path: str, timeout: float = 10.0):
        self.socket_path = socket_path
        self.timeout = timeout

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        transport = httpx.HTTPTransport(uds=self.socket_path)
        with httpx.Client(transport=transport, base_url="http://localhost",
                          timeout=self.timeout) as c:
            r = c.post(path, json=payload)
            r.raise_for_status()
            return r.json()

    def _get(self, path: str) -> dict[str, Any]:
        transport = httpx.HTTPTransport(uds=self.socket_path)
        with httpx.Client(transport=transport, base_url="http://localhost",
                          timeout=self.timeout) as c:
            r = c.get(path)
            r.raise_for_status()
            return r.json()

    def set_usb_mode(self, mode: str) -> dict[str, Any]:
        return self._post("/usb-gadget/mode", {"mode": mode})

    def get_usb_state(self) -> dict[str, Any]:
        return self._get("/usb-gadget/state")

    def restart_service(self, unit: str) -> dict[str, Any]:
        return self._post("/service/restart", {"unit": unit})

    def lockdown(self) -> dict[str, Any]:
        return self._post("/lockdown", {"confirm": "lockdown"})
