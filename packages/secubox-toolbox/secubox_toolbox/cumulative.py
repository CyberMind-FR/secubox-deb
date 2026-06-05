# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

"""Phase 6.D (#496) — cumulative anonymous statistics across ALL sessions.

Aggregates from /var/lib/secubox/toolbox/toolbox.db :
  - total sessions seen (per day/week/all-time)
  - total events analyzed (DPI, cookies, JA4, SOC)
  - top apps detected (anonymized — never tied to a mac_hash)
  - top trackers seen
  - top countries contacted
  - risk score distribution
  - cabine uptime

Used by :
  - landing page kbin.gk2.secubox.in (public showcase)
  - dashboard /report/me/html (alongside personal stats)
  - admin /admin/clients/{mh}/report (per-client overlaid on cumulative)
"""
from __future__ import annotations

import json
import logging
import sqlite3
import time
from collections import Counter
from pathlib import Path

log = logging.getLogger("secubox.cumulative")

DB = Path("/var/lib/secubox/toolbox/toolbox.db")
CACHE_FILE = Path("/var/lib/secubox/toolbox/cumulative-cache.json")
CACHE_TTL_SECONDS = 60  # refresh every minute


def _now() -> int:
    return int(time.time())


def _safe_query(db, sql: str, params: tuple = ()) -> list:
    try:
        cur = db.execute(sql, params)
        return cur.fetchall()
    except Exception as e:
        log.debug("query failed: %s", e)
        return []


def compute() -> dict:
    """Recompute all cumulative stats from scratch — moderately expensive,
    cache externally with CACHE_TTL_SECONDS."""
    if not DB.exists():
        return _empty_stats()
    out = _empty_stats()
    try:
        with sqlite3.connect(DB, timeout=2) as c:
            c.row_factory = sqlite3.Row

            # Session counts
            now = _now()
            d24h = now - 86400
            d7d = now - 86400 * 7
            d30d = now - 86400 * 30

            out["sessions"]["last_24h"] = (_safe_query(c,
                "SELECT COUNT(DISTINCT mac_hash) FROM clients WHERE last_seen > ?",
                (d24h,)) or [(0,)])[0][0]
            out["sessions"]["last_7d"] = (_safe_query(c,
                "SELECT COUNT(DISTINCT mac_hash) FROM clients WHERE last_seen > ?",
                (d7d,)) or [(0,)])[0][0]
            out["sessions"]["last_30d"] = (_safe_query(c,
                "SELECT COUNT(DISTINCT mac_hash) FROM clients WHERE last_seen > ?",
                (d30d,)) or [(0,)])[0][0]
            out["sessions"]["all_time"] = (_safe_query(c,
                "SELECT COUNT(DISTINCT mac_hash) FROM clients") or [(0,)])[0][0]

            # Event counts by source (last 7 days for relevance)
            for row in _safe_query(c,
                "SELECT source, COUNT(*) as n FROM events WHERE ts > ? GROUP BY source",
                (d7d,)):
                out["events"][row["source"]] = row["n"]
            out["events"]["total_7d"] = sum(out["events"].values())

            # Top hosts (anonymized — just hostnames, no mac_hash)
            host_counter = Counter()
            for row in _safe_query(c,
                "SELECT payload FROM events WHERE source='dpi' AND ts > ? LIMIT 5000",
                (d7d,)):
                try:
                    p = json.loads(row["payload"])
                    h = p.get("host") or p.get("sni")
                    if h:
                        host_counter[h] += 1
                except Exception:
                    pass
            out["top_hosts_7d"] = [
                {"host": h, "count": n}
                for h, n in host_counter.most_common(15)
            ]

            # Risk score distribution (last 7d)
            score_buckets = {"low": 0, "medium": 0, "high": 0}
            for row in _safe_query(c,
                "SELECT score FROM clients WHERE last_seen > ?",
                (d7d,)):
                s = row["score"]
                if s < 30:
                    score_buckets["low"] += 1
                elif s < 70:
                    score_buckets["medium"] += 1
                else:
                    score_buckets["high"] += 1
            out["risk_distribution_7d"] = score_buckets

            # Level distribution
            level_buckets = {"r0": 0, "r1": 0, "r2": 0, "r3": 0}
            for row in _safe_query(c,
                "SELECT level, COUNT(*) as n FROM clients WHERE last_seen > ? GROUP BY level",
                (d7d,)):
                lvl = row["level"] or "r1"
                if lvl in level_buckets:
                    level_buckets[lvl] += row["n"]
            out["level_distribution_7d"] = level_buckets

    except Exception as e:
        log.warning("cumulative compute failed: %s", e)

    out["computed_at"] = _now()
    return out


def _empty_stats() -> dict:
    return {
        "sessions": {"last_24h": 0, "last_7d": 0, "last_30d": 0, "all_time": 0},
        "events": {},
        "top_hosts_7d": [],
        "risk_distribution_7d": {"low": 0, "medium": 0, "high": 0},
        "level_distribution_7d": {"r0": 0, "r1": 0, "r2": 0, "r3": 0},
        "computed_at": _now(),
    }


def get_cached() -> dict:
    """Returns cached stats if fresh, else recompute + persist."""
    if CACHE_FILE.exists():
        try:
            data = json.loads(CACHE_FILE.read_text())
            if _now() - data.get("computed_at", 0) < CACHE_TTL_SECONDS:
                return data
        except Exception:
            pass
    data = compute()
    try:
        CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        CACHE_FILE.write_text(json.dumps(data))
    except Exception:
        pass
    return data
