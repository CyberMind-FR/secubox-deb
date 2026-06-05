# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

"""Beaconing pattern detection.

A C2 beacon is characterized by REGULAR periodic communications to the same
host with low jitter. Even on encrypted traffic, the CADENCE betrays it.

Phase 2a heuristic :
- For each (mac_hash, host), compute median interval + stdev between consecutive
  DPI events.
- Beacon score if : median_interval in [5s, 300s] AND coefficient_of_variation < 0.20
  (jitter < 20% of median).
- Real apps (Skype keepalive, MQTT, Apple push) often beacon too but at longer
  intervals (5+ minutes) or with bursty patterns — those score lower.

Phase 3 will add ML clustering.
"""
from __future__ import annotations

import json
import logging
import sqlite3
import statistics
import time
from collections import defaultdict
from pathlib import Path

log = logging.getLogger("secubox.toolbox.beaconing")

DB = Path("/var/lib/secubox/toolbox/toolbox.db")


def _load_events(mac_hash: str, lookback_seconds: int = 1800) -> dict[str, list[int]]:
    """Return {host: [ts1, ts2, ...sorted]} from DPI events for mac_hash."""
    if not mac_hash:
        return {}
    out: dict[str, list[int]] = defaultdict(list)
    try:
        since = int(time.time()) - lookback_seconds
        with sqlite3.connect(DB, timeout=2) as c:
            rows = c.execute(
                "SELECT ts, payload FROM events WHERE mac_hash=? AND source='dpi' AND ts > ? "
                "ORDER BY ts ASC",
                (mac_hash, since),
            ).fetchall()
        for ts, payload_json in rows:
            try:
                p = json.loads(payload_json)
            except Exception:
                continue
            host = p.get("host")
            if host:
                out[host].append(int(ts))
    except Exception as e:
        log.debug("beaconing load failed: %s", e)
    return out


def _analyze_series(timestamps: list[int]) -> dict:
    """Compute median interval + coefficient of variation."""
    if len(timestamps) < 4:
        return {"count": len(timestamps), "median": 0, "stdev": 0, "cv": 1.0}
    timestamps = sorted(timestamps)
    intervals = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]
    if not intervals:
        return {"count": len(timestamps), "median": 0, "stdev": 0, "cv": 1.0}
    med = statistics.median(intervals)
    sd = statistics.stdev(intervals) if len(intervals) > 1 else 0
    cv = (sd / med) if med > 0 else 1.0
    return {
        "count": len(timestamps),
        "median": int(med),
        "stdev": int(sd),
        "cv": round(cv, 3),
    }


def analyze_beaconing(mac_hash: str) -> list[dict]:
    """Returns suspect beacon candidates : list of {host, count, median_seconds, cv, score}.
    Sorted by score desc."""
    series = _load_events(mac_hash)
    out = []
    for host, ts_list in series.items():
        stats = _analyze_series(ts_list)
        count = stats["count"]
        median = stats["median"]
        cv = stats["cv"]
        if count < 4:
            continue  # not enough samples
        if median == 0:
            continue
        # Score : interval in [5, 300] + low CV → beacon-like
        score = 0
        indicators: list[str] = []
        if 5 <= median <= 300:
            if cv < 0.10:
                score = 50
                indicators.append(f"very_regular_cadence(cv={cv})")
            elif cv < 0.20:
                score = 35
                indicators.append(f"regular_cadence(cv={cv})")
            elif cv < 0.35:
                score = 20
                indicators.append(f"loosely_regular(cv={cv})")
        if score > 0:
            out.append({
                "host": host,
                "count": count,
                "median_seconds": median,
                "cv": cv,
                "score": score,
                "indicators": indicators,
            })
    return sorted(out, key=lambda x: -x["score"])
