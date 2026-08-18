# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""NTP health probe — read chronyc tracking. Used to widen TOTP window on drift."""
from __future__ import annotations

import logging
import re
import subprocess
import time
from typing import Dict

log = logging.getLogger("secubox.ntp_health")

_OFFSET_RE = re.compile(r"^System time\s*:\s*([\d.eE+-]+)\s*seconds", re.MULTILINE)
_LEAP_RE = re.compile(r"^Leap status\s*:\s*(\S.*)$", re.MULTILINE)
_REF_RE = re.compile(r"^Reference ID\s*:\s*(\S+)", re.MULTILINE)

_cache: Dict[str, object] = {"ts": 0, "result": None}
_CACHE_TTL = 30  # seconds


def probe() -> Dict[str, object]:
    """Return {synced, drift_seconds, leap_status, reference_id} or {synced: False, error: ...}.

    Cached for _CACHE_TTL seconds so the auth path doesn't spawn chronyc on every call.
    """
    now = time.time()
    if now - _cache["ts"] < _CACHE_TTL and _cache["result"] is not None:
        return dict(_cache["result"])
    result = _probe_uncached()
    _cache.update({"ts": now, "result": result})
    return dict(result)


def _probe_uncached() -> Dict[str, object]:
    """Try chrony first, fall back to systemd-timesyncd (timedatectl).

    SecuBox boxes ship with systemd-timesyncd by default ; chrony is the
    operator-installed alternative. Phase 7 (#498) — the chrony-only
    probe always returned `synced: False` on stock installs, which made
    the auth UI permanently flag "Clock not synced" even when the system
    clock was within a few microseconds of NTP.
    """
    # ── 1. chronyc tracking ──
    try:
        out = subprocess.run(
            ["chronyc", "-n", "tracking"],
            capture_output=True, text=True, timeout=2, check=False,
        )
        if out.returncode == 0:
            m_offset = _OFFSET_RE.search(out.stdout)
            m_leap = _LEAP_RE.search(out.stdout)
            m_ref = _REF_RE.search(out.stdout)
            drift = float(m_offset.group(1)) if m_offset else None
            leap = m_leap.group(1).strip() if m_leap else "Unknown"
            ref = m_ref.group(1) if m_ref else "?"
            synced = leap.lower().startswith("normal") and ref != "7F7F0101"
            return {
                "synced": synced,
                "drift_seconds": drift,
                "leap_status": leap,
                "reference_id": ref,
                "source": "chrony",
            }
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # ── 2. timedatectl (systemd-timesyncd) ──
    try:
        out = subprocess.run(
            ["timedatectl", "show",
             "--property=NTPSynchronized",
             "--property=NTP"],
            capture_output=True, text=True, timeout=2, check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return {"synced": False, "error": f"neither chronyc nor timedatectl available: {exc}"}
    if out.returncode != 0:
        return {"synced": False, "error": out.stderr.strip() or "timedatectl failed"}

    fields = dict(line.split("=", 1) for line in out.stdout.strip().splitlines() if "=" in line)
    ntp_enabled = fields.get("NTP", "").lower() == "yes"
    ntp_synced = fields.get("NTPSynchronized", "").lower() == "yes"
    return {
        "synced": ntp_enabled and ntp_synced,
        "drift_seconds": None,  # timedatectl doesn't expose offset cheaply
        "leap_status": "Normal" if ntp_synced else "Not synchronised",
        "reference_id": "systemd-timesyncd" if ntp_enabled else "none",
        "source": "timedatectl",
    }


def recommended_totp_window() -> int:
    """Return the TOTP `valid_window` to use given current NTP health.

    synced  → 1 (±30s)
    degraded → 3 (±90s) — accept drift up to 90s
    unknown → 2 (±60s) — middle ground
    """
    h = probe()
    if h.get("synced"):
        return 1
    if "error" in h:
        return 2
    return 3
