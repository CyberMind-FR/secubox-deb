# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

"""mitmproxy addons :: common helpers (fire-and-forget POST + MAC lookup)."""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
import re
import subprocess
from datetime import date
from pathlib import Path
from urllib.parse import urlparse

try:
    import httpx
except ImportError:
    httpx = None

log = logging.getLogger("secubox.toolbox.addons")
_RE_MAC = re.compile(r"lladdr\s+([0-9a-f:]{17})", re.I)
_SALT_FILE = Path("/etc/secubox/secrets/toolbox-mac-salt")
_SALT_CACHE: str | None = None


def mac_of(ip: str) -> str | None:
    try:
        out = subprocess.run(
            ["ip", "neigh", "show", ip],
            capture_output=True, text=True, timeout=1, check=False,
        ).stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    m = _RE_MAC.search(out)
    return m.group(1).lower() if m else None


def _salt() -> str:
    """Read MAC anonymization salt once, cache in-process."""
    global _SALT_CACHE
    if _SALT_CACHE is None:
        try:
            _SALT_CACHE = _SALT_FILE.read_text().strip()
        except Exception as e:
            log.warning("salt unavailable, MAC hashing disabled: %s", e)
            _SALT_CACHE = ""
    return _SALT_CACHE


def hash_mac(mac: str | None) -> str | None:
    """HMAC-SHA256 of MAC with salt + day rotation. 16-char hex digest.

    Same algorithm as secubox_toolbox.mac.hash_mac and local_store._hash_mac
    so events from all addons cross-reference the same mac_hash.
    """
    if not mac:
        return None
    s = _salt()
    if not s:
        return None
    key = (s + ":" + date.today().isoformat()).encode()
    return hmac.new(key, mac.lower().encode(), hashlib.sha256).hexdigest()[:16]


# ── Phase 6 (#496) : WG peer identity (10.99.1.0/24) ───────────────
import json as _jsonmod
import hashlib as _hashlib
from pathlib import Path as _Path

_WG_PEERS_DB = _Path("/var/lib/secubox/toolbox/wg-peers.json")
_WG_PEERS_CACHE: dict[str, str] = {}    # ip → wg_hash
_WG_PEERS_MTIME: float = 0.0


def _wg_hash_of(ip: str) -> str | None:
    """Map 10.99.1.X → sha256(peer_pubkey)[:16]. Cached, reloaded on mtime
    change. R3 clients have NO ARP entry on captive subnet, so we identify
    them by their WG public key (one peer → one IP, deterministic)."""
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
                    _WG_PEERS_CACHE[peer_ip] = _hashlib.sha256(pubkey.encode()).hexdigest()[:16]
            _WG_PEERS_MTIME = mtime
        return _WG_PEERS_CACHE.get(ip)
    except Exception:
        return None


def mac_hash_of(ip: str | None) -> str | None:
    """Resolve IP to a stable per-client identity hash.

    - 10.99.1.0/24 (WG peer)   → sha256(peer_pubkey)[:16]   (Phase 6/R3)
    - Captive subnet            → HMAC(salt, MAC from ARP)   (R0/R1/R2)
    - Else                      → None
    """
    if not ip:
        return None
    # Phase 6 : WG peers identified by pubkey hash, not ARP
    if ip.startswith("10.99.1."):
        return _wg_hash_of(ip)
    raw = mac_of(ip)
    return hash_mac(raw) if raw else None


def _resolve_socket_url(target: str) -> tuple[str, str]:
    """
    Parse 'http+unix:///path/to.sock/route' → ('/path/to.sock', '/route').
    """
    if target.startswith("http+unix://"):
        rest = target[len("http+unix://"):]
        slash_idx = rest.find("/", 1)
        sock = rest[:slash_idx] if slash_idx > 0 else rest
        path = rest[slash_idx:] if slash_idx > 0 else "/"
        return sock, path
    raise ValueError(f"unsupported target {target!r}")


async def fire_forget_post(target: str, payload: dict) -> None:
    """Fire-and-forget POST to a unix-socket'd endpoint. Never blocks the proxy flow."""
    if httpx is None:
        log.warning("httpx not available — addon POST skipped")
        return
    try:
        sock, path = _resolve_socket_url(target)
        transport = httpx.AsyncHTTPTransport(uds=sock)
        async with httpx.AsyncClient(transport=transport, timeout=2) as client:
            await client.post(f"http://localhost{path}", json=payload)
    except Exception as e:
        log.debug("addon POST to %s failed: %s", target, e)


def queue_async(coro) -> None:
    """Wrap coro in create_task at the mitmproxy event loop. Never raise."""
    try:
        loop = asyncio.get_event_loop()
        loop.create_task(coro)
    except RuntimeError:
        pass
