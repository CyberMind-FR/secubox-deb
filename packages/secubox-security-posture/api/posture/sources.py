# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: Security Posture — low-level data sources
CyberMind — https://cybermind.fr

Thin, side-effecting helpers that fetch raw signal from the board with the
minimal-privilege rule (sibling public sockets > CrowdSec Prometheus >
unprivileged /proc reads). Every helper degrades gracefully: it returns
``None`` / ``(False, None)`` instead of raising, so collectors can mark the
indicator UNKNOWN rather than crashing the whole refresh.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Optional, Tuple

import httpx

RUN_DIR = "/run/secubox"
CROWDSEC_PROM = "http://127.0.0.1:6060/metrics"
DEFAULT_TIMEOUT = 3.0


async def socket_get(name: str, path: str,
                     timeout: float = DEFAULT_TIMEOUT) -> Tuple[bool, Optional[dict]]:
    """GET a JSON document from a sibling module's unix socket (public route).

    ``name`` is the module id (socket = /run/secubox/<name>.sock); ``path`` is
    the raw route (e.g. "/status"). Returns ``(ok, data)``; ``ok`` is False on
    any transport/HTTP/JSON error so the caller can record UNKNOWN.
    """
    sock = f"{RUN_DIR}/{name}.sock"
    if not os.path.exists(sock):
        return False, None
    try:
        transport = httpx.AsyncHTTPTransport(uds=sock)
        async with httpx.AsyncClient(transport=transport, timeout=timeout) as client:
            resp = await client.get(f"http://{name}{path}")
            if resp.status_code != 200:
                return False, None
            return True, resp.json()
    except Exception:
        return False, None


async def http_get_text(url: str, timeout: float = DEFAULT_TIMEOUT) -> Optional[str]:
    """GET a plain-text body (e.g. Prometheus exposition). None on failure."""
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(url)
            if resp.status_code != 200:
                return None
            return resp.text
    except Exception:
        return None


def prom_value(text: str, metric: str) -> Optional[float]:
    """Sum all samples of a Prometheus metric (ignoring labels). None if absent."""
    if not text:
        return None
    total = None
    pat = re.compile(r"^" + re.escape(metric) + r"(?:\{[^}]*\})?\s+([0-9.eE+-]+)\s*$")
    for line in text.splitlines():
        if line.startswith("#"):
            continue
        m = pat.match(line.strip())
        if m:
            try:
                total = (total or 0.0) + float(m.group(1))
            except ValueError:
                continue
    return total


async def crowdsec_prom() -> dict:
    """Fetch active decisions / alerts from CrowdSec's Prometheus endpoint."""
    text = await http_get_text(CROWDSEC_PROM)
    if text is None:
        return {}
    out = {}
    for key, metric in (("active_decisions", "cs_active_decisions"),
                        ("active_alerts", "cs_active_alerts")):
        val = prom_value(text, metric)
        if val is not None:
            out[key] = val
    return out


# ---- unprivileged /proc fallbacks -----------------------------------------

def read_loadavg() -> Optional[float]:
    """1-minute load average from /proc/loadavg. None on failure."""
    try:
        return float(Path("/proc/loadavg").read_text().split()[0])
    except Exception:
        return None


def read_mem_available_ratio() -> Optional[float]:
    """MemAvailable / MemTotal from /proc/meminfo (0..1). None on failure."""
    try:
        fields = {}
        for line in Path("/proc/meminfo").read_text().splitlines():
            k, _, rest = line.partition(":")
            fields[k.strip()] = float(rest.strip().split()[0])
        total = fields.get("MemTotal")
        avail = fields.get("MemAvailable")
        if total and avail is not None and total > 0:
            return avail / total
    except Exception:
        return None
    return None


def cpu_count() -> int:
    """Online CPU count (>=1)."""
    try:
        return max(1, os.cpu_count() or 1)
    except Exception:
        return 1
