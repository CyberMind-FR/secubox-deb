# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

"""mitmproxy addon :: local SQLite event store.

Phase 1.5 : capture flows directly into toolbox.db so the WebUI dashboard,
PDF report, and live HTML report can show DPI/SOC/cookies/JA4 data WITHOUT
the receiving modules (cookies.sock, dpi.sock, soc.sock, ...) being wired up.

The dedicated addons (cookies/dpi/avatar/ja4/soc_relay) still fire their
own POSTs as best-effort fan-out — they become no-op until those endpoints
exist (Phase 2). This local_store.py is the source of truth for Phase 1.5.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import re
import sqlite3
import subprocess
import time
from datetime import date
from pathlib import Path

from mitmproxy import http, tls

log = logging.getLogger("secubox.toolbox.local_store")

DB = Path("/var/lib/secubox/toolbox/toolbox.db")
SALT_FILE = Path("/etc/secubox/secrets/toolbox-mac-salt")
_RE_MAC = re.compile(r"lladdr\s+([0-9a-f:]{17})", re.I)
_SALT_CACHE: str | None = None


def _salt() -> str:
    global _SALT_CACHE
    if _SALT_CACHE is None:
        try:
            _SALT_CACHE = SALT_FILE.read_text().strip()
        except Exception as e:
            log.warning("salt unavailable, hashing disabled: %s", e)
            _SALT_CACHE = ""
    return _SALT_CACHE


def _hash_mac(mac: str | None) -> str | None:
    if not mac:
        return None
    s = _salt()
    if not s:
        return None
    key = (s + ":" + date.today().isoformat()).encode()
    return hmac.new(key, mac.lower().encode(), hashlib.sha256).hexdigest()[:16]


def _mac_of(ip: str | None) -> str | None:
    if not ip:
        return None
    try:
        out = subprocess.run(
            ["ip", "neigh", "show", ip],
            capture_output=True, text=True, timeout=1, check=False,
        ).stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    m = _RE_MAC.search(out)
    return m.group(1).lower() if m else None


def _peer_ip(flow) -> str | None:
    if flow.client_conn and flow.client_conn.peername:
        return flow.client_conn.peername[0]
    return None


def _insert(mac_hash: str | None, source: str, payload: dict) -> None:
    if not mac_hash:
        return
    try:
        with sqlite3.connect(DB, timeout=2) as c:
            c.execute(
                "INSERT INTO events(mac_hash, ts, source, payload) VALUES (?,?,?,?)",
                (mac_hash, int(time.time()), source, json.dumps(payload)[:8000]),
            )
            c.execute(
                "INSERT INTO clients(mac_hash, ip, first_seen, last_seen) VALUES (?,?,?,?) "
                "ON CONFLICT(mac_hash) DO UPDATE SET last_seen=excluded.last_seen",
                (mac_hash, payload.get("client_ip", ""), int(time.time()), int(time.time())),
            )
    except Exception as e:
        log.debug("sqlite insert failed: %s", e)


# ──────────────── mitmproxy hooks ────────────────

class LocalStore:
    def request(self, flow: http.HTTPFlow) -> None:
        """Capture every request as a DPI hint event."""
        ip = _peer_ip(flow)
        mac_hash = _hash_mac(_mac_of(ip))
        if not mac_hash:
            return
        host = flow.request.host
        _insert(mac_hash, "dpi", {
            "client_ip": ip,
            "host": host,
            "scheme": flow.request.scheme,
            "method": flow.request.method,
            "path": flow.request.path[:200],
            "user_agent": flow.request.headers.get("user-agent"),
        })

    def response(self, flow: http.HTTPFlow) -> None:
        if not flow.response:
            return
        ip = _peer_ip(flow)
        mac_hash = _hash_mac(_mac_of(ip))
        if not mac_hash:
            return
        # Cookies event — Phase 2a+ : capture names (NOT values) for provider mapping
        set_cookies = flow.response.headers.get_all("set-cookie") or []
        req_cookies = flow.request.headers.get_all("cookie") or []
        if set_cookies or req_cookies:
            # Extract names only (truncated, max 32 chars each) — privacy-safe metadata
            set_names = []
            for sc in set_cookies[:30]:
                # Set-Cookie format: "name=value; Path=/; ..."
                head = sc.split(";", 1)[0]
                if "=" in head:
                    n = head.split("=", 1)[0].strip()[:32]
                    if n:
                        set_names.append(n)
            sent_names = []
            for cookie_hdr in req_cookies:
                # Cookie format: "name1=v1; name2=v2; ..."
                for part in cookie_hdr.split(";"):
                    if "=" in part:
                        n = part.split("=", 1)[0].strip()[:32]
                        if n and len(sent_names) < 50:
                            sent_names.append(n)
            _insert(mac_hash, "cookies", {
                "url": flow.request.pretty_url[:300],
                "set_cookie_count": len(set_cookies),
                "cookie_count": len(req_cookies),
                "set_cookie_names": set_names,
                "cookie_names": sent_names,
                "status": flow.response.status_code,
            })
        # SOC trivial indicator (suspicious patterns)
        suspicious = False
        host = flow.request.host
        if re.search(r"\.(tk|ml|ga|cf|gq|onion)$|^[a-z0-9]{20,}\.|\.dyndns\.|\.no-ip\.|duckdns\.", host, re.I):
            suspicious = True
            _insert(mac_hash, "soc", {
                "client_ip": ip,
                "host": host,
                "kind": "suspicious_host_pattern",
                "weight": 15,
            })

    def tls_clienthello(self, data) -> None:
        ip = data.context.client.peername[0] if data.context.client.peername else None
        mac_hash = _hash_mac(_mac_of(ip))
        if not mac_hash:
            return
        ch = data.client_hello
        _insert(mac_hash, "ja4", {
            "client_ip": ip,
            "sni": ch.sni,
            "alpn_protocols": list(ch.alpn_protocols or []),
            "cipher_suites_count": len(ch.cipher_suites or []),
        })


addons = [LocalStore()]
