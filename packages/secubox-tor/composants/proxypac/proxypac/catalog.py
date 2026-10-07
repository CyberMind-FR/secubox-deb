# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: proxypac.catalog — read p2p /services, map to service Rules."""
import json
import socket
from urllib.parse import urlparse

from .pac_template import directive
from .rules import Rule


def _endpoint_host(endpoint):
    return urlparse(endpoint or "").hostname or ""


def service_rules(services):
    """Map active services carrying a `pac` descriptor to routing Rules."""
    out = []
    for s in services:
        if not s.get("enabled"):
            continue
        pac = s.get("pac")
        if not pac:
            continue
        proxy = pac.get("proxy", "direct")
        host = _endpoint_host(s.get("endpoint"))
        if proxy == "socks5":
            port = (s.get("macro") or {}).get("params", {}).get("socks_port", 9050)
            addr = f"{host}:{port}"
        else:  # http | gateway use the endpoint host as-is
            addr = host
        d = directive(proxy, addr)
        for m in pac.get("match", []):
            out.append(Rule(m, d, f"service:{s['service_id']}"))
    return out


def read_services(sock="/run/secubox/p2p.sock"):
    """GET /services over the p2p unix socket. Returns the services list (fail-open: [])."""
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as c:
            c.settimeout(5)
            c.connect(sock)
            c.sendall(b"GET /services HTTP/1.0\r\nHost: x\r\n\r\n")
            buf = b""
            while True:
                chunk = c.recv(65536)
                if not chunk:
                    break
                buf += chunk
        body = buf.split(b"\r\n\r\n", 1)[1]
        return json.loads(body).get("services", [])
    except Exception:
        return []
