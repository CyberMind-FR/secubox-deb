# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

"""mitmproxy addon :: cookies relay → /api/v1/cookies/inject."""
from __future__ import annotations

from mitmproxy import http

from _common import fire_forget_post, mac_hash_of, queue_async

TARGET = "http+unix:///run/secubox/cookies.sock/inject"


def _names_only(headers: list[str], cap: int = 50) -> list[str]:
    """Extract cookie/Set-Cookie NAMES (not values) — privacy-safe metadata."""
    out: list[str] = []
    for h in headers[:cap]:
        head = h.split(";", 1)[0]
        if "=" in head:
            n = head.split("=", 1)[0].strip()[:32]
            if n:
                out.append(n)
    return out


def _parse_cookie_header(value: str) -> list[str]:
    """Split 'Cookie:' header into list of names."""
    names: list[str] = []
    for part in value.split(";"):
        if "=" in part:
            n = part.split("=", 1)[0].strip()[:32]
            if n:
                names.append(n)
    return names


class CookiesRelay:
    def response(self, flow: http.HTTPFlow) -> None:
        if not flow.response:
            return
        set_cookies = flow.response.headers.get_all("set-cookie") or []
        req_cookies = flow.request.headers.get_all("cookie") or []
        if not (set_cookies or req_cookies):
            return
        client_ip = flow.client_conn.peername[0] if flow.client_conn.peername else None
        # Names only, never values (privacy + CSPN)
        sent_names: list[str] = []
        for ch in req_cookies:
            sent_names.extend(_parse_cookie_header(ch))
        payload = {
            "ts_ms": int(flow.timestamp_start * 1000),
            "client_ip": client_ip,
            "client_mac_hash": mac_hash_of(client_ip),
            "url": flow.request.pretty_url[:300],
            "method": flow.request.method,
            "set_cookie_names": _names_only(set_cookies, cap=30),
            "cookie_names": sent_names[:50],
            "set_cookie_count": len(set_cookies),
            "cookie_count": len(req_cookies),
            "status": flow.response.status_code,
        }
        queue_async(fire_forget_post(TARGET, payload))


addons = [CookiesRelay()]
