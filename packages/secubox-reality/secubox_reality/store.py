# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: Reality — ROOT stage: persistent state (SQLite WAL)
CyberMind — https://cybermind.fr

Every query in this module is parameterized (``?`` placeholders) — no string
interpolation of caller-supplied values is ever used to build SQL.
"""
from __future__ import annotations

import json
import os
import sqlite3
import time
from contextlib import contextmanager
from typing import Any, Dict, Iterator, List, Optional

DEFAULT_DB_PATH = "/var/lib/secubox/reality/reality.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS servers (
    id           TEXT PRIMARY KEY,
    remark       TEXT NOT NULL,
    private_key  TEXT NOT NULL,
    public_key   TEXT NOT NULL,
    uuid         TEXT NOT NULL,
    dest         TEXT NOT NULL,
    sni          TEXT NOT NULL,
    listen_port  INTEGER NOT NULL,
    dest_port    INTEGER NOT NULL,
    flow         TEXT NOT NULL DEFAULT 'xtls-rprx-vision',
    short_ids    TEXT NOT NULL DEFAULT '[]',
    status       TEXT NOT NULL DEFAULT 'new',
    created_at   REAL NOT NULL,
    updated_at   REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS clients (
    id           TEXT PRIMARY KEY,
    server_id    TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    uuid         TEXT NOT NULL,
    email        TEXT NOT NULL,
    short_id     TEXT NOT NULL,
    flow         TEXT NOT NULL DEFAULT 'xtls-rprx-vision',
    created_at   REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_clients_server ON clients(server_id);

CREATE TABLE IF NOT EXISTS stats_samples (
    sample_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id    TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    ts           REAL NOT NULL,
    uplink       INTEGER NOT NULL DEFAULT 0,
    downlink     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_stats_server_ts ON stats_samples(server_id, ts);
"""


def init_db(path: str = DEFAULT_DB_PATH) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with _connect(path) as conn:
        conn.executescript(_SCHEMA)
        conn.commit()


@contextmanager
def _connect(path: str = DEFAULT_DB_PATH) -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(path, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA foreign_keys=ON")
        yield conn
    finally:
        conn.close()


def _row_to_server(row: sqlite3.Row) -> Dict[str, Any]:
    d = dict(row)
    d["short_ids"] = json.loads(d.get("short_ids") or "[]")
    return d


# --- servers -----------------------------------------------------------


def create_server(server: Dict[str, Any], path: str = DEFAULT_DB_PATH) -> Dict[str, Any]:
    now = time.time()
    with _connect(path) as conn:
        conn.execute(
            """
            INSERT INTO servers
                (id, remark, private_key, public_key, uuid, dest, sni,
                 listen_port, dest_port, flow, short_ids, status, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                server["id"],
                server["remark"],
                server["private_key"],
                server["public_key"],
                server["uuid"],
                server["dest"],
                server["sni"],
                server["listen_port"],
                server["dest_port"],
                server.get("flow", "xtls-rprx-vision"),
                json.dumps(server.get("short_ids", [])),
                server.get("status", "new"),
                now,
                now,
            ),
        )
        conn.commit()
    return get_server(server["id"], path=path)  # type: ignore[return-value]


def get_server(server_id: str, path: str = DEFAULT_DB_PATH) -> Optional[Dict[str, Any]]:
    with _connect(path) as conn:
        row = conn.execute("SELECT * FROM servers WHERE id = ?", (server_id,)).fetchone()
        return _row_to_server(row) if row else None


def list_servers(path: str = DEFAULT_DB_PATH) -> List[Dict[str, Any]]:
    with _connect(path) as conn:
        rows = conn.execute("SELECT * FROM servers ORDER BY created_at DESC").fetchall()
        return [_row_to_server(r) for r in rows]


def update_server_status(server_id: str, status: str, path: str = DEFAULT_DB_PATH) -> None:
    with _connect(path) as conn:
        conn.execute(
            "UPDATE servers SET status = ?, updated_at = ? WHERE id = ?",
            (status, time.time(), server_id),
        )
        conn.commit()


def delete_server(server_id: str, path: str = DEFAULT_DB_PATH) -> None:
    with _connect(path) as conn:
        conn.execute("DELETE FROM servers WHERE id = ?", (server_id,))
        conn.commit()


# --- clients -------------------------------------------------------------


def create_client(client: Dict[str, Any], path: str = DEFAULT_DB_PATH) -> Dict[str, Any]:
    now = time.time()
    with _connect(path) as conn:
        conn.execute(
            """
            INSERT INTO clients (id, server_id, uuid, email, short_id, flow, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                client["id"],
                client["server_id"],
                client["uuid"],
                client["email"],
                client["short_id"],
                client.get("flow", "xtls-rprx-vision"),
                now,
            ),
        )
        conn.commit()
    return get_client(client["id"], path=path)  # type: ignore[return-value]


def get_client(client_id: str, path: str = DEFAULT_DB_PATH) -> Optional[Dict[str, Any]]:
    with _connect(path) as conn:
        row = conn.execute("SELECT * FROM clients WHERE id = ?", (client_id,)).fetchone()
        return dict(row) if row else None


def list_clients(server_id: Optional[str] = None, path: str = DEFAULT_DB_PATH) -> List[Dict[str, Any]]:
    with _connect(path) as conn:
        if server_id:
            rows = conn.execute(
                "SELECT * FROM clients WHERE server_id = ? ORDER BY created_at DESC", (server_id,)
            ).fetchall()
        else:
            rows = conn.execute("SELECT * FROM clients ORDER BY created_at DESC").fetchall()
        return [dict(r) for r in rows]


def delete_client(client_id: str, path: str = DEFAULT_DB_PATH) -> None:
    with _connect(path) as conn:
        conn.execute("DELETE FROM clients WHERE id = ?", (client_id,))
        conn.commit()


# --- stats samples ---------------------------------------------------------


def insert_stats_sample(server_id: str, uplink: int, downlink: int, path: str = DEFAULT_DB_PATH) -> None:
    with _connect(path) as conn:
        conn.execute(
            "INSERT INTO stats_samples (server_id, ts, uplink, downlink) VALUES (?, ?, ?, ?)",
            (server_id, time.time(), uplink, downlink),
        )
        conn.commit()


def get_stats_window(server_id: str, since_ts: float, path: str = DEFAULT_DB_PATH) -> List[Dict[str, Any]]:
    with _connect(path) as conn:
        rows = conn.execute(
            "SELECT ts, uplink, downlink FROM stats_samples "
            "WHERE server_id = ? AND ts >= ? ORDER BY ts ASC",
            (server_id, since_ts),
        ).fetchall()
        return [dict(r) for r in rows]


def prune_stats_older_than(cutoff_ts: float, path: str = DEFAULT_DB_PATH) -> int:
    """Housekeeping: drop samples older than ``cutoff_ts``. Returns row count deleted."""
    with _connect(path) as conn:
        cur = conn.execute("DELETE FROM stats_samples WHERE ts < ?", (cutoff_ts,))
        conn.commit()
        return cur.rowcount
