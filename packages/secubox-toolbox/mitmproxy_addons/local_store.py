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

# Phase 3 (#492) : analysis_status tagging on every event
# Soft import : whitelist may not be installed yet (older boards)
try:
    from secubox_core import whitelist as _whitelist
except Exception:
    _whitelist = None

# Known E2E SNI suffixes — content opaque by design
_E2E_SNI_PATTERNS = re.compile(
    r"(\.signal\.org|\.whispersystems\.org|\.threema\.|\.simplex\.|"
    r"\.matrix\.org|\.proton\.me|\.protonmail\.|\.tutanota\.)$",
    re.I,
)


def _analysis_status(host: str | None, sni: str | None, decrypted: bool) -> tuple[str, str]:
    """Return (status, reason) for an observed flow.

    Order :
      1. decrypted -> inspected
      2. whitelist match -> bypassed-whitelist + reason from yaml
      3. E2E SNI pattern -> e2e-opaque
      4. fallback -> pinned-failed-mitm
    """
    if decrypted:
        return ("inspected", "MITM decryption succeeded via ToolBoX CA")
    target = (sni or host or "").lower()
    if _whitelist is not None and target:
        m = _whitelist.match(target)
        if m:
            return ("bypassed-whitelist", m.get("reason", "whitelisted"))
    if target and _E2E_SNI_PATTERNS.search(target):
        return ("e2e-opaque", "E2E messenger : content opaque by design")
    return ("pinned-failed-mitm", "TLS handshake failed (cert-pinning detected)")


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


# Phase 6 (#496) : WG peer hash lookup (R3 clients have no ARP entry).
import json as _jsonmod
_WG_PEERS_DB = Path("/var/lib/secubox/toolbox/wg-peers.json")
_WG_PEERS_CACHE: dict[str, str] = {}
_WG_PEERS_MTIME: float = 0.0


def _wg_hash_of(ip: str) -> str | None:
    global _WG_PEERS_MTIME
    try:
        if not _WG_PEERS_DB.exists():
            return None
        mtime = _WG_PEERS_DB.stat().st_mtime
        if mtime != _WG_PEERS_MTIME or not _WG_PEERS_CACHE:
            data = _jsonmod.loads(_WG_PEERS_DB.read_text()).get("peers", {})
            _WG_PEERS_CACHE.clear()
            for pubkey, meta in data.items():
                peer_ip = meta.get("ip")
                if peer_ip:
                    _WG_PEERS_CACHE[peer_ip] = hashlib.sha256(pubkey.encode()).hexdigest()[:16]
            _WG_PEERS_MTIME = mtime
        return _WG_PEERS_CACHE.get(ip)
    except Exception:
        return None


def _client_hash(ip: str | None) -> str | None:
    """Single entry point : WG IP → wg_hash, else MAC→hash via ARP."""
    if not ip:
        return None
    if ip.startswith("10.99.1."):
        return _wg_hash_of(ip)
    return _hash_mac(_mac_of(ip))


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
        mac_hash = _client_hash(ip)
        if not mac_hash:
            return
        host = flow.request.host
        sni = getattr(flow.client_conn, "sni", None)
        # If we got here with a parsed request, decryption succeeded.
        status, reason = _analysis_status(host, sni, decrypted=True)
        _insert(mac_hash, "dpi", {
            "client_ip": ip,
            "host": host,
            "scheme": flow.request.scheme,
            "method": flow.request.method,
            "path": flow.request.path[:200],
            "user_agent": flow.request.headers.get("user-agent"),
            "analysis_status": status,
            "analysis_reason": reason,
        })

    def response(self, flow: http.HTTPFlow) -> None:
        if not flow.response:
            return
        ip = _peer_ip(flow)
        mac_hash = _client_hash(ip)
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

    def tls_failed_clienthello(self, data) -> None:
        """Phase 3 (#492) : record cert-pinning / whitelisted bypasses.

        Fires when TLS handshake fails (cert-pinning) OR when we deliberately
        skipped MITM (whitelist). We log the SNI + status so the report can
        be honest about what we didn't inspect.
        """
        ip = data.context.client.peername[0] if data.context.client.peername else None
        mac_hash = _client_hash(ip)
        if not mac_hash:
            return
        sni = getattr(data.client_hello, "sni", None) if hasattr(data, "client_hello") else None
        status, reason = _analysis_status(host=None, sni=sni, decrypted=False)
        _insert(mac_hash, "dpi", {
            "client_ip": ip,
            "host": sni or "?",
            "sni": sni,
            "analysis_status": status,
            "analysis_reason": reason,
        })

    def tls_clienthello(self, data) -> None:
        ip = data.context.client.peername[0] if data.context.client.peername else None
        mac_hash = _client_hash(ip)
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
