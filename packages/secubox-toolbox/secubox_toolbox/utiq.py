# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

"""
SecuBox-Deb :: ToolBoX Utiq event store

Phase 8 (#500) — store every Utiq-tracker flow seen by the mitm-wg
addon so the operator can audit silence-but-track activity in the
admin UI.

Schema kept intentionally minimal :
  - client_ip is the WG peer IP (10.99.1.x).  Already a pseudo-
    identifier (anonymous), no need to hash again here.
  - publisher is derived from the host (the part BEFORE `.utiq.com`
    for CNAME wrappers, or `consenthub` / `utiq` for direct calls).
  - action ∈ {log, block, mask, pseudo}.
  - level mirrors the defense level in effect at the time.
  - detected_mtid is reserved for Phase 2 (when we parse the response
    body to extract the mtid mitm-wg would have revealed to the
    publisher).
"""
from __future__ import annotations

import logging
import sqlite3
import time
from pathlib import Path
from typing import Dict, List, Optional

log = logging.getLogger("secubox.toolbox.utiq.store")

DB_PATH = Path("/var/lib/secubox/toolbox/toolbox.db")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS utiq_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              INTEGER NOT NULL,
    client_ip       TEXT,
    publisher       TEXT,
    host            TEXT NOT NULL,
    path            TEXT,
    action          TEXT NOT NULL,
    level           TEXT NOT NULL,
    detected_mtid   TEXT,
    injected_mtid   TEXT
);
CREATE INDEX IF NOT EXISTS idx_utiq_ts ON utiq_events(ts);
CREATE INDEX IF NOT EXISTS idx_utiq_client ON utiq_events(client_ip, ts);
CREATE INDEX IF NOT EXISTS idx_utiq_publisher ON utiq_events(publisher, ts);
"""


def _conn() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(str(DB_PATH), timeout=5.0, isolation_level=None)
    c.row_factory = sqlite3.Row
    c.executescript(_SCHEMA)
    return c


def _publisher_from_host(host: str) -> str:
    """Derive a publisher tag from the host.

    `consenthub.utiq.com`         → 'consenthub'
    `lemonde.utiq.com`            → 'lemonde'
    `utiq.com` (rare direct)      → 'utiq'
    `cdn.example.com` (path-only) → 'example.com'  (fallback)
    """
    h = (host or "").lower()
    if h.endswith(".utiq.com"):
        return h[: -len(".utiq.com")].rsplit(".", 1)[-1] or "utiq"
    if h == "utiq.com":
        return "utiq"
    # path-only match (some sites serve utiqLoader.js from their own
    # 1st-party domain)
    parts = h.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return h or "unknown"


def record_event(
    *,
    client_ip: Optional[str],
    host: str,
    path: Optional[str],
    action: str,
    level: str,
    detected_mtid: Optional[str] = None,
    injected_mtid: Optional[str] = None,
) -> None:
    """Insert one event.  Best-effort — never raises into the addon."""
    try:
        with _conn() as c:
            c.execute(
                "INSERT INTO utiq_events(ts, client_ip, publisher, host, "
                "path, action, level, detected_mtid, injected_mtid) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    int(time.time()),
                    client_ip,
                    _publisher_from_host(host),
                    host,
                    path,
                    action,
                    level,
                    detected_mtid,
                    injected_mtid,
                ),
            )
    except Exception as e:
        log.warning("record_event failed: %s", e)


def recent(hours: int = 24, limit: int = 200) -> List[Dict]:
    """Return the last events within the window, newest first."""
    since = int(time.time()) - hours * 3600
    if hours < 1 or hours > 24 * 31:
        hours = 24
    if limit < 1 or limit > 5000:
        limit = 200
    with _conn() as c:
        cur = c.execute(
            "SELECT id, ts, client_ip, publisher, host, path, action, "
            "level, detected_mtid, injected_mtid "
            "FROM utiq_events WHERE ts >= ? ORDER BY ts DESC LIMIT ?",
            (since, limit),
        )
        return [dict(r) for r in cur.fetchall()]


def aggregates(hours: int = 24) -> Dict:
    """Counts by publisher + by client + by action for the dashboard."""
    since = int(time.time()) - hours * 3600
    out: Dict = {"window_hours": hours, "total": 0, "by_publisher": [],
                 "by_client": [], "by_action": []}
    with _conn() as c:
        out["total"] = c.execute(
            "SELECT COUNT(*) FROM utiq_events WHERE ts >= ?",
            (since,),
        ).fetchone()[0]
        out["by_publisher"] = [
            dict(r) for r in c.execute(
                "SELECT publisher, COUNT(*) AS n FROM utiq_events "
                "WHERE ts >= ? GROUP BY publisher "
                "ORDER BY n DESC LIMIT 25",
                (since,),
            ).fetchall()
        ]
        out["by_client"] = [
            dict(r) for r in c.execute(
                "SELECT client_ip, COUNT(*) AS n FROM utiq_events "
                "WHERE ts >= ? AND client_ip IS NOT NULL "
                "GROUP BY client_ip ORDER BY n DESC LIMIT 25",
                (since,),
            ).fetchall()
        ]
        out["by_action"] = [
            dict(r) for r in c.execute(
                "SELECT action, COUNT(*) AS n FROM utiq_events "
                "WHERE ts >= ? GROUP BY action ORDER BY n DESC",
                (since,),
            ).fetchall()
        ]
    return out


def client_recent_count(client_ip: str, hours: int = 1) -> int:
    """Used by inject_banner to decide whether to surface the Utiq tile.

    Cheap query — used per-request on banner-eligible flows.
    """
    if not client_ip:
        return 0
    since = int(time.time()) - hours * 3600
    try:
        with _conn() as c:
            return c.execute(
                "SELECT COUNT(*) FROM utiq_events "
                "WHERE client_ip = ? AND ts >= ?",
                (client_ip, since),
            ).fetchone()[0]
    except Exception:
        return 0
