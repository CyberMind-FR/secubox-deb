# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

"""mitmproxy addon :: cookies relay → /api/v1/cookies/inject."""
from __future__ import annotations

from mitmproxy import http

from _common import fire_forget_post, mac_of, queue_async

TARGET = "http+unix:///run/secubox/cookies.sock/inject"


class CookiesRelay:
    def response(self, flow: http.HTTPFlow) -> None:
        if not flow.response:
            return
        set_cookies = flow.response.headers.get_all("set-cookie") or []
        req_cookies = flow.request.headers.get_all("cookie") or []
        if not (set_cookies or req_cookies):
            return
        payload = {
            "ts_ms": int(flow.timestamp_start * 1000),
            "client_ip": flow.client_conn.peername[0] if flow.client_conn.peername else None,
            "client_mac": mac_of(flow.client_conn.peername[0]) if flow.client_conn.peername else None,
            "url": flow.request.pretty_url,
            "method": flow.request.method,
            "set_cookie": set_cookies,
            "cookie": req_cookies,
            "status": flow.response.status_code,
        }
        queue_async(fire_forget_post(TARGET, payload))


addons = [CookiesRelay()]
