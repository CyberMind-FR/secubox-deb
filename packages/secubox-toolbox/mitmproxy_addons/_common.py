# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

"""mitmproxy addons :: common helpers (fire-and-forget POST + MAC lookup)."""
from __future__ import annotations

import asyncio
import logging
import re
import subprocess
from urllib.parse import urlparse

try:
    import httpx
except ImportError:
    httpx = None

log = logging.getLogger("secubox.toolbox.addons")
_RE_MAC = re.compile(r"lladdr\s+([0-9a-f:]{17})", re.I)


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
