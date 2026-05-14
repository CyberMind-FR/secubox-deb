# packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/transport_manager.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""TransportManager — probe OTG → WiFi → SIM, manage JWT, fetch metrics.

Python port of Phase 1's remote-ui/common/js/transport-manager.js.
Single-process kiosk uses this directly (no WebSocket bridge needed).
"""
from __future__ import annotations

import base64
import json
import logging
import time
from dataclasses import dataclass
from typing import Callable, Optional

import httpx

log = logging.getLogger("secubox_eye_square_kiosk.transport_manager")

PROBE_TIMEOUT_S = 2.0
LOGIN_TIMEOUT_S = 3.0
FETCH_TIMEOUT_S = 3.0
JWT_RENEW_BEFORE_S = 30.0


class TransportManager:
    """Probe OTG/WiFi/SIM, fetch metrics, renew JWT. Hooks for module:tap and
    transport change events (in-process callbacks)."""

    def __init__(
        self,
        simulate: bool = True,
        otg_base: str = "http://10.55.0.1:8000",
        wifi_base: str = "http://secubox.local:8000",
        login_user: str = "dashboard",
        login_pass: str = "secubox-square",
    ):
        self.simulate = simulate
        self.otg_base = otg_base
        self.wifi_base = wifi_base
        self.login_user = login_user
        self.login_pass = login_pass
        self.active = "SIM"
        self.jwt: Optional[str] = None
        self.jwt_exp: float = 0.0
        self.otg_fails = 0
        self.on_transport_change: Callable[[str], None] = lambda _: None
        self.on_module_tap: Callable[[str], None] = lambda _: None
        self._client = httpx.Client(timeout=PROBE_TIMEOUT_S)

    @property
    def base(self) -> Optional[str]:
        if self.active == "OTG":
            return self.otg_base
        if self.active == "WiFi":
            return self.wifi_base
        return None

    def _set_active(self, new_active: str) -> None:
        """Set self.active and fire hook on transitions only."""
        if self.active == new_active:
            return
        self.active = new_active
        try:
            self.on_transport_change(new_active)
        except Exception as e:
            log.warning("on_transport_change raised: %s", e)

    def probe(self) -> None:
        """Probe OTG → WiFi → SIM. Updates self.active."""
        if self.simulate:
            self._set_active("SIM")
            return
        for name, url in [("OTG", self.otg_base), ("WiFi", self.wifi_base)]:
            try:
                r = self._client.get(url + "/api/v1/health", timeout=PROBE_TIMEOUT_S)
                if r.status_code == 200:
                    if self.active != name:
                        self._set_active(name)
                        self.jwt = None  # force re-login on transport change
                    self.otg_fails = 0
                    return
            except Exception as e:
                if name == "OTG":
                    self.otg_fails += 1
                log.debug("%s probe failed: %s", name, e)
        self._set_active("SIM")

    def login(self) -> bool:
        """POST /api/v1/auth/token with username+password. Cache JWT + exp."""
        if self.simulate or not self.base:
            self.jwt = "SIM"
            self.jwt_exp = time.time() + 3600
            return True
        try:
            r = self._client.post(
                self.base + "/api/v1/auth/token",
                data={"username": self.login_user, "password": self.login_pass,
                      "grant_type": "password"},
                timeout=LOGIN_TIMEOUT_S,
            )
            r.raise_for_status()
            data = r.json()
            self.jwt = data["access_token"]
            payload = json.loads(base64.urlsafe_b64decode(
                self.jwt.split(".")[1] + "==").decode())
            self.jwt_exp = payload["exp"]
            return True
        except Exception as e:
            log.warning("login failed: %s", e)
            return False

    def ensure_jwt(self) -> bool:
        if not self.jwt or time.time() >= (self.jwt_exp - JWT_RENEW_BEFORE_S):
            return self.login()
        return True

    def fetch_metrics(self) -> Optional[dict]:
        if self.simulate or self.active == "SIM" or not self.base:
            return None
        if not self.ensure_jwt():
            return None
        try:
            r = self._client.get(
                self.base + "/api/v1/system/metrics",
                headers={"Authorization": f"Bearer {self.jwt}"},
                timeout=FETCH_TIMEOUT_S,
            )
            r.raise_for_status()
            return r.json()
        except Exception as e:
            log.debug("fetch_metrics failed: %s", e)
            if self.active == "OTG":
                self.otg_fails += 1
            return None
