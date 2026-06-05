# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

"""mitmproxy addon :: TLS fingerprint relay → /api/v1/threat-analyst/ja4.

Phase 1: relay raw TLS ClientHello bytes + SNI to threat-analyst.
Phase 2: compute JA4/JA4S server-side.
"""
from __future__ import annotations

import time

from mitmproxy import tls

from _common import fire_forget_post, mac_hash_of, queue_async

TARGET = "http+unix:///run/secubox/threat-analyst.sock/ja4"


class JA4Relay:
    def tls_clienthello(self, data: tls.ClientHelloData) -> None:
        ch = data.client_hello
        client_ip = data.context.client.peername[0] if data.context.client.peername else None
        payload = {
            "ts_ms": int(time.time() * 1000),
            "client_ip": client_ip,
            "client_mac_hash": mac_hash_of(client_ip),
            "sni": ch.sni,
            "alpn_protocols": list(ch.alpn_protocols or []),
            "cipher_suites": list(ch.cipher_suites or []),
            "extensions": list(ch.extensions or []) if hasattr(ch, "extensions") else None,
        }
        queue_async(fire_forget_post(TARGET, payload))


addons = [JA4Relay()]
