# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

"""mitmproxy addon :: device fingerprint (UA + Client Hints + screen) → /api/v1/avatar/fingerprint."""
from __future__ import annotations

from mitmproxy import http

from _common import fire_forget_post, mac_of, queue_async

TARGET = "http+unix:///run/secubox/avatar.sock/fingerprint"

# Client Hints headers that reveal hardware/OS without JS
CH_HEADERS = (
    "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
    "sec-ch-ua-platform-version", "sec-ch-ua-model", "sec-ch-ua-arch",
    "sec-ch-ua-full-version", "sec-ch-ua-full-version-list",
    "sec-ch-ua-bitness", "sec-ch-ua-wow64",
    "viewport-width", "device-memory", "downlink", "ect", "rtt",
)


class AvatarRelay:
    def request(self, flow: http.HTTPFlow) -> None:
        ua = flow.request.headers.get("user-agent")
        if not ua:
            return
        client_ip = flow.client_conn.peername[0] if flow.client_conn.peername else None
        chints = {h: flow.request.headers.get(h) for h in CH_HEADERS if h in flow.request.headers}
        payload = {
            "ts_ms": int(flow.timestamp_start * 1000),
            "client_ip": client_ip,
            "client_mac": mac_of(client_ip) if client_ip else None,
            "user_agent": ua,
            "accept_language": flow.request.headers.get("accept-language"),
            "accept": flow.request.headers.get("accept"),
            "client_hints": chints,
        }
        queue_async(fire_forget_post(TARGET, payload))


addons = [AvatarRelay()]
