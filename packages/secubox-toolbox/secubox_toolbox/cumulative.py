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

# Live analysis-module event stores (post-#662 Phase-7 cutover). The legacy
# toolbox.db `events` table froze at the cutover; the live counts + hosts now
# live in each analysis module, exposed over its own unix socket.
#   GET /mitm-events/stats?since_seconds=N -> {"kind":..,"count":n,...}
#   GET /mitm-events?limit=N               -> {"events":[{...payload...}],"count":n}
_MITM_MODULES = [
    ("dpi", "/run/secubox/dpi.sock"),
    ("cookies", "/run/secubox/cookies.sock"),
    ("ja4", "/run/secubox/threat-analyst.sock"),
]
# dpi socket is the one carrying host/sni payloads for top-hosts aggregation.
_DPI_SOCK = "/run/secubox/dpi.sock"


def _now() -> int:
    return int(time.time())


def _uds_get_json(sock_path: str, path: str, timeout: int = 2) -> dict | None:
    """GET a JSON document over a unix socket. Returns the parsed dict, or
    None on any error (never raises). Mirrors api._pull_mitm_module_events's
    UDSConnection pattern."""
    import socket as _sock
    import http.client as _hc

    try:
        class UDSConnection(_hc.HTTPConnection):
            def connect(self):
                self.sock = _sock.socket(_sock.AF_UNIX, _sock.SOCK_STREAM)
                self.sock.settimeout(self.timeout)
                self.sock.connect(sock_path)

        conn = UDSConnection("localhost", timeout=timeout)
        try:
            conn.request("GET", path)
            resp = conn.getresponse()
            if resp.status != 200:
                return None
            raw = resp.read().decode("utf-8", errors="ignore")[:1000000]
            return json.loads(raw)
        finally:
            conn.close()
    except Exception as e:
        log.debug("uds get %s%s failed: %s", sock_path, path, e)
        return None


def _live_event_counts(window_seconds: int) -> dict | None:
    """Query each analysis module's GET /mitm-events/stats for its event count
    in the window. Returns {"dpi":n,"cookies":n,"ja4":n} (missing/error module
    omitted). Returns None only if EVERY module call failed (caller falls back
    to the legacy toolbox.db query)."""
    counts: dict[str, int] = {}
    any_ok = False
    for kind, sock_path in _MITM_MODULES:
        data = _uds_get_json(
            sock_path, f"/mitm-events/stats?since_seconds={int(window_seconds)}"
        )
        if data is None:
            continue
        any_ok = True
        # Prefer the module's self-reported kind; fall back to our tag.
        k = data.get("kind") or kind
        try:
            counts[k] = int(data.get("count", 0))
        except (TypeError, ValueError):
            counts[k] = 0
    return counts if any_ok else None


def _live_top_hosts(limit: int = 5000, top: int = 25) -> list | None:
    """Aggregate top hosts from the dpi module's recent events. Returns a list
    of {"host":..,"count":..} (same shape as the legacy top_hosts_7d), or None
    if the dpi module call failed."""
    data = _uds_get_json(_DPI_SOCK, f"/mitm-events?limit={int(limit)}")
    if data is None:
        return None
    host_counter: Counter = Counter()
    for ev in data.get("events", []) or []:
        try:
            p = ev.get("payload") or {}
            h = p.get("host") or p.get("sni")
            if h:
                host_counter[h] += 1
        except Exception:
            pass
    return [{"host": h, "count": n} for h, n in host_counter.most_common(top)]


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

            # Event counts by source (last 7 days for relevance).
            # Post-#662 Phase-7: the live counts live in the analysis modules'
            # own stores (queried over unix sockets). The legacy toolbox.db
            # `events` table froze at the cutover, so prefer the live path and
            # only fall back to the frozen table if EVERY module call fails.
            live_counts = _live_event_counts(86400 * 7)
            if live_counts is not None:
                out["events"].update(live_counts)
            else:
                for row in _safe_query(c,
                    "SELECT source, COUNT(*) as n FROM events WHERE ts > ? GROUP BY source",
                    (d7d,)):
                    out["events"][row["source"]] = row["n"]
            out["events"]["total_7d"] = sum(
                v for v in out["events"].values() if isinstance(v, int)
            )

            # Top hosts (anonymized — just hostnames, no mac_hash).
            # Live path: aggregate the dpi module's recent events; fall back to
            # the frozen toolbox.db `events` table only if the dpi call fails.
            live_hosts = _live_top_hosts()
            if live_hosts is not None:
                out["top_hosts_7d"] = live_hosts
            else:
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

            # Risk score / level distributions read the `clients` table (not
            # the frozen `events` table), so they stay on toolbox.db for now.
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
            level_buckets = {"r0": 0, "r1": 0, "r2": 0, "r3": 0, "r4": 0}
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
        "level_distribution_7d": {"r0": 0, "r1": 0, "r2": 0, "r3": 0, "r4": 0},
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
