# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

"""mitmproxy addon :: DPI classification hint relay → /api/v1/dpi/classify."""
from __future__ import annotations

from mitmproxy import http

from _common import fire_forget_post, mac_of, queue_async

TARGET = "http+unix:///run/secubox/dpi.sock/classify"


class DPIRelay:
    def request(self, flow: http.HTTPFlow) -> None:
        host = flow.request.host
        client_ip = flow.client_conn.peername[0] if flow.client_conn.peername else None
        payload = {
            "ts_ms": int(flow.timestamp_start * 1000),
            "client_ip": client_ip,
            "client_mac": mac_of(client_ip) if client_ip else None,
            "host": host,
            "scheme": flow.request.scheme,
            "method": flow.request.method,
            "user_agent": flow.request.headers.get("user-agent"),
            "sni": flow.client_conn.sni if hasattr(flow.client_conn, "sni") else None,
        }
        queue_async(fire_forget_post(TARGET, payload))


addons = [DPIRelay()]
