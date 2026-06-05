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


def mac_hash_of(ip: str | None) -> str | None:
    """Resolve IP to MAC via neighbour table then hash. Returns None on failure."""
    if not ip:
        return None
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
