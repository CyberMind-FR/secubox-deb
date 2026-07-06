# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: ToolBoX Sentinel link
CyberMind — https://cybermind.fr

Fail-safe bridge from the ToolBoX portal to the sbx-sentinel daemon's
read-only localhost status HTTP, plus the compromise/evaluation summary.

Everything here is defensive and MUST NOT raise out to a caller: a dark or
wedged daemon degrades to empty results, never an exception. Detections
carry mac_hash only — no other PII passes through this module.
"""
from __future__ import annotations

import json
import logging
import os
import re
import urllib.request
from collections import Counter

log = logging.getLogger("secubox.toolbox.sentinel")

_TIMEOUT = 1.5  # seconds — a wedged daemon must not stall a portal request
_DEFAULT_ADDR = "127.0.0.1:8790"
_SENTINEL_ENV = "/etc/secubox/sentinel.env"

# Heuristic classes never escalate to "compromised" — they are behavioral
# guesses, not confirmed known-infrastructure hits. Keep in sync with the Go
# scorer's heuristicClasses (currently zero-click).
_HEURISTIC_CLASSES = {"zero_click"}
_HIGH_CONFIDENCE = 85  # mirrors Go HighConfidenceThreshold


def _safe_int(value, default: int = 0) -> int:
    """Coerce daemon/caller-supplied values to int, never raising."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def daemon_base() -> str | None:
    """Resolve the daemon status-HTTP base URL, or None if unconfigured.

    Order: SENTINEL_HTTP_ADDR from the process env, then from
    /etc/secubox/sentinel.env, then the 127.0.0.1:8790 default. An explicitly
    empty value (the dark default) yields None so callers show 'inactive'.
    """
    addr = os.environ.get("SENTINEL_HTTP_ADDR")
    if addr is None:
        addr = _read_env_addr()
    if addr is None:
        addr = _DEFAULT_ADDR
    addr = addr.strip()
    if not addr:
        return None
    if not addr.startswith("http"):
        addr = "http://" + addr
    return addr.rstrip("/")


def _read_env_addr() -> str | None:
    """Best-effort read of SENTINEL_HTTP_ADDR from sentinel.env; None on any issue."""
    try:
        with open(_SENTINEL_ENV, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line.startswith("SENTINEL_HTTP_ADDR="):
                    return line.split("=", 1)[1].strip().strip('"')
    except Exception:
        pass
    return None


def _get_json(path: str):
    """GET base+path and parse JSON. Returns None on ANY failure (never raises)."""
    base = daemon_base()
    if not base:
        return None
    try:
        req = urllib.request.Request(base + path, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as exc:  # connection refused, timeout, bad JSON, HTTP error
        log.debug("sentinel fetch %s failed: %s", path, exc)
        return None


def fetch_stats() -> dict:
    data = _get_json("/stats")
    return data if isinstance(data, dict) else {}


def fetch_verdicts(limit: int = 50) -> list[dict]:
    limit = max(1, min(_safe_int(limit, 50), 500))
    data = _get_json(f"/verdicts?limit={limit}")
    return [d for d in data if isinstance(d, dict)] if isinstance(data, list) else []


def fetch_detections(mac_hash: str, limit: int = 50) -> list[dict]:
    if not mac_hash or not re.fullmatch(r"[0-9a-fA-F]{1,64}", mac_hash):
        return []
    limit = max(1, min(_safe_int(limit, 50), 500))
    data = _get_json(f"/verdicts?mac={mac_hash}&limit={limit}")
    return [d for d in data if isinstance(d, dict)] if isinstance(data, list) else []


def disposition(action: str) -> str:
    """Honest disposition label — an observed/async detection is not a block."""
    return "Bloquée" if action == "block" else "Détectée — observée"


def _is_confirmed_compromise(d: dict) -> bool:
    cls = str(d.get("class", ""))
    if cls in _HEURISTIC_CLASSES:
        return False
    return (
        d.get("action") == "block"
        and _safe_int(d.get("confidence", 0)) >= _HIGH_CONFIDENCE
    )


def assess(detections: list[dict]) -> dict:
    """Compromise/evaluation summary over one device's (or the fleet's) detections.

    tier: clean (none) · suspicious (report-only/heuristic) · compromised
    (a high-confidence, non-heuristic, block-action detection).
    """
    dets = [d for d in (detections or []) if isinstance(d, dict)]
    if not dets:
        return {"tier": "clean", "worst_severity": 0, "worst_confidence": 0,
                "count": 0, "dominant_class": "", "strongest": None}
    strongest = max(dets, key=lambda d: (_safe_int(d.get("severity", 0)),
                                          _safe_int(d.get("confidence", 0))))
    tier = "compromised" if any(_is_confirmed_compromise(d) for d in dets) else "suspicious"
    classes = Counter(str(d.get("class", "")) for d in dets if d.get("class"))
    dominant = classes.most_common(1)[0][0] if classes else ""
    return {
        "tier": tier,
        "worst_severity": max(_safe_int(d.get("severity", 0)) for d in dets),
        "worst_confidence": max(_safe_int(d.get("confidence", 0)) for d in dets),
        "count": len(dets),
        "dominant_class": dominant,
        "strongest": strongest,
    }
