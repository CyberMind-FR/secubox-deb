# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

"""IP→MAC + hash MAC avec sel rotatif daily (anonymisation pour storage)."""
from __future__ import annotations

import hashlib
import hmac
import logging
import re
import subprocess
from datetime import date

log = logging.getLogger("secubox.toolbox")

_RE_MAC = re.compile(r"lladdr\s+([0-9a-f:]{17})", re.I)


def mac_of(ip: str) -> str | None:
    """Lookup MAC via `ip neigh show <ip>`. Returns lowercase MAC or None."""
    try:
        out = subprocess.run(
            ["ip", "neigh", "show", ip],
            capture_output=True, text=True, timeout=2, check=False,
        ).stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    m = _RE_MAC.search(out)
    return m.group(1).lower() if m else None


def hash_mac(mac: str, salt: str, day_seed: str | None = None) -> str:
    """
    HMAC-SHA256(salt + day_seed, mac).
    `day_seed` permet rotation quotidienne (default = today YYYY-MM-DD).
    Renvoie un hex court (16 chars) pour storage.
    """
    if day_seed is None:
        day_seed = date.today().isoformat()
    key = (salt + ":" + day_seed).encode()
    h = hmac.new(key, mac.lower().encode(), hashlib.sha256)
    return h.hexdigest()[:16]
