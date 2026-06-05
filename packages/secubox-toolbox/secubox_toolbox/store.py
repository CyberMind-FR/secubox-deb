# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

"""SQLite store : consents, clients, events, reports. Purge auto par TTL."""
from __future__ import annotations

import json
import logging
import sqlite3
import time
from pathlib import Path

log = logging.getLogger("secubox.toolbox")
DB_PATH = Path("/var/lib/secubox/toolbox/toolbox.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS consents (
    mac_hash TEXT PRIMARY KEY,
    ts INTEGER NOT NULL,
    ttl_seconds INTEGER NOT NULL,
    ip TEXT,
    user_agent TEXT
);
CREATE TABLE IF NOT EXISTS clients (
    mac_hash TEXT PRIMARY KEY,
    ip TEXT,
    state TEXT NOT NULL DEFAULT 'validated',
    score INTEGER NOT NULL DEFAULT 0,
    level TEXT NOT NULL DEFAULT 'r1',
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mac_hash TEXT NOT NULL,
    ts INTEGER NOT NULL,
    source TEXT NOT NULL,
    payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_mac_ts ON events(mac_hash, ts);
CREATE TABLE IF NOT EXISTS reports (
    token TEXT PRIMARY KEY,
    mac_hash TEXT NOT NULL,
    ts INTEGER NOT NULL,
    pdf_path TEXT,
    expires_at INTEGER NOT NULL
);
"""


def _conn() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(DB_PATH, timeout=5)
    c.row_factory = sqlite3.Row
    c.executescript(SCHEMA)
    return c


def record_consent(mac_hash: str, ip: str, ua: str | None, ttl_seconds: int) -> None:
    with _conn() as c:
        c.execute(
            "INSERT OR REPLACE INTO consents(mac_hash, ts, ttl_seconds, ip, user_agent) "
            "VALUES (?, ?, ?, ?, ?)",
            (mac_hash, int(time.time()), ttl_seconds, ip, ua),
        )


def upsert_client(mac_hash: str, ip: str, level: str = "r1") -> None:
    """Phase 3 (#492) : level = 'r0' | 'r1' | 'r2' opt-in tier."""
    now = int(time.time())
    with _conn() as c:
        # Idempotent add of level column (for upgrades from pre-#492 DB)
        try:
            c.execute("ALTER TABLE clients ADD COLUMN level TEXT NOT NULL DEFAULT 'r1'")
        except sqlite3.OperationalError:
            pass  # column already exists
        c.execute(
            "INSERT INTO clients(mac_hash, ip, level, first_seen, last_seen) "
            "VALUES (?,?,?,?,?) "
            "ON CONFLICT(mac_hash) DO UPDATE SET ip=excluded.ip, "
            "level=excluded.level, last_seen=excluded.last_seen",
            (mac_hash, ip, level, now, now),
        )


def get_client_level(mac_hash: str) -> str:
    """Returns 'r0' | 'r1' | 'r2'. Default 'r1' if not found."""
    try:
        with _conn() as c:
            row = c.execute(
                "SELECT level FROM clients WHERE mac_hash=?", (mac_hash,)
            ).fetchone()
            if row:
                return row["level"] or "r1"
    except Exception:
        pass
    return "r1"


def add_event(mac_hash: str, source: str, payload: dict) -> None:
    with _conn() as c:
        c.execute(
            "INSERT INTO events(mac_hash, ts, source, payload) VALUES (?,?,?,?)",
            (mac_hash, int(time.time()), source, json.dumps(payload)),
        )


def list_clients() -> list[dict]:
    with _conn() as c:
        rows = c.execute(
            "SELECT mac_hash, ip, state, score, first_seen, last_seen FROM clients "
            "ORDER BY last_seen DESC LIMIT 200"
        ).fetchall()
    return [dict(r) for r in rows]


def purge_expired() -> int:
    """Returns count of rows purged."""
    now = int(time.time())
    n = 0
    with _conn() as c:
        n += c.execute(
            "DELETE FROM consents WHERE ts + ttl_seconds < ?", (now,)
        ).rowcount
        n += c.execute(
            "DELETE FROM reports WHERE expires_at < ?", (now,)
        ).rowcount
        # Events older than 24h
        n += c.execute(
            "DELETE FROM events WHERE ts < ?", (now - 86400,)
        ).rowcount
    if n:
        log.info("purge_expired: %d rows", n)
    return n
