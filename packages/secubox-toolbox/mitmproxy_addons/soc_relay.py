# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

"""mitmproxy addon :: SOC compromise indicator relay → /api/v1/soc/event.

Phase 1: skeleton that emits SOC events on basic indicators (suspicious DNS,
malware feed match, beaconing pattern). Real scoring happens in Phase 2 (secubox-soc).
"""
from __future__ import annotations

import re

from mitmproxy import http

from _common import fire_forget_post, mac_of, queue_async

TARGET = "http+unix:///run/secubox/soc.sock/event"

# Trivial indicators for Phase 1 (Phase 2 = full feed-driven correlation)
_SUSPICIOUS_DOMAIN_RE = re.compile(
    r"\.(tk|ml|ga|cf|gq|onion)$"            # cheap TLDs / Tor
    r"|^[a-z0-9]{20,}\."                     # super-long random subdomain (DGA hint)
    r"|\.dyndns\.|\.no-ip\.|duckdns\.",      # dynamic DNS
    re.I,
)


class SOCRelay:
    def request(self, flow: http.HTTPFlow) -> None:
        host = flow.request.host
        client_ip = flow.client_conn.peername[0] if flow.client_conn.peername else None
        indicators: list[dict] = []
        if _SUSPICIOUS_DOMAIN_RE.search(host):
            indicators.append({
                "kind": "suspicious_host_pattern",
                "host": host,
                "regex": _SUSPICIOUS_DOMAIN_RE.pattern,
                "weight": 15,
            })
        if not indicators:
            return
        payload = {
            "ts_ms": int(flow.timestamp_start * 1000),
            "client_ip": client_ip,
            "client_mac": mac_of(client_ip) if client_ip else None,
            "indicators": indicators,
            "source": "toolbox-mitm",
        }
        queue_async(fire_forget_post(TARGET, payload))


addons = [SOCRelay()]
