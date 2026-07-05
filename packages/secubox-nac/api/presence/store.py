# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-nac — cross-plane presence store (Project B, #820, Task 1).

`PresenceStore` mirrors `api.store.DeviceStore` byte-for-byte in spirit: a
single shared SQLite connection (WAL, `check_same_thread=False`) guarded by
a `threading.Lock` around every SQL method, dict rows, `CREATE TABLE IF NOT
EXISTS`, and a best-value `INSERT ... ON CONFLICT(id) DO UPDATE` upsert for
the `presences` table (a new table living alongside A's `devices` table in
the SAME `devices.db`). Enrichment columns (geo_cc/geo_asn/geo_org/
device_mac/client_type/...) are merged with `COALESCE(excluded, stored)` so
a later sighting with missing fields never wipes previously learned data;
`first_seen` is set-once (existing value always wins); `last_seen` is
always overwritten; `hits` increments on every upsert (starts at 1 on
insert, `+1` on conflict).

Pure stdlib (`sqlite3`, `threading`, `time`) — no FastAPI, no secubox_core
import. Import of this module MUST have no side effects: no directory
creation, no DB connection opened at import time. `PresenceStore(db_path)`
is the only thing that touches disk.
"""
from __future__ import annotations

import sqlite3
import threading
import time

# Enrichment columns: a later upsert with a NULL/missing value must never
# wipe a previously stored non-null value here (mirrors DeviceStore's
# `_BEST_VALUE_COLUMNS`).
_BEST_VALUE_COLUMNS = (
    "plane",
    "identity",
    "device_mac",
    "geo_cc",
    "geo_asn",
    "geo_org",
    "provenance",
    "client_type",
    "tier",
    "extra",
)

_ALWAYS_SET_COLUMNS = ("last_seen",)

# `first_seen` is set-once: the FIRST value ever recorded wins (mirrors
# DeviceStore's `_FIRST_SEEN_COLUMN`).
_FIRST_SEEN_COLUMN = "first_seen"

_ALL_UPSERT_COLUMNS = _BEST_VALUE_COLUMNS + _ALWAYS_SET_COLUMNS + (_FIRST_SEEN_COLUMN,)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS presences(
  id TEXT PRIMARY KEY,
  plane TEXT,
  identity TEXT,
  device_mac TEXT,
  geo_cc TEXT, geo_asn TEXT, geo_org TEXT,
  provenance TEXT,
  client_type TEXT,
  first_seen INTEGER, last_seen INTEGER, hits INTEGER DEFAULT 0,
  tier TEXT DEFAULT 'info',
  extra TEXT
);
CREATE INDEX IF NOT EXISTS idx_pres_plane ON presences(plane);
CREATE INDEX IF NOT EXISTS idx_pres_last ON presences(last_seen);
CREATE TABLE IF NOT EXISTS presence_alerts(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER, plane TEXT, tier TEXT, detail TEXT
);
"""


def pid(plane: str, identity: str) -> str:
    """Build the canonical `presences.id` for a `(plane, identity)` pair."""
    return f"{plane}:{identity}"


class PresenceStore:
    """Cross-plane presence inventory backed by SQLite (WAL mode).

    Opens the SAME `devices.db` file as A's `DeviceStore` — the `presences`
    and `presence_alerts` tables live alongside `devices` in one file, each
    store owning its own connection/lock (mirrors how `DeviceStore` itself
    is instantiated: one connection per store object, `check_same_thread`
    disabled so both the collector's executor thread and threadpooled
    FastAPI handlers can share it safely under the lock).
    """

    def __init__(self, db_path: str):
        self.db_path = db_path
        # Serializes every SQL method so no two threads touch the shared
        # connection at once (mirrors DeviceStore's `_lock`).
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    @staticmethod
    def _row_to_dict(row: sqlite3.Row | None) -> dict | None:
        if row is None:
            return None
        return dict(row)

    def upsert(self, pres: dict) -> None:
        """Insert or best-value-merge a presence dict keyed by `id`.

        Enrichment columns (`_BEST_VALUE_COLUMNS`) use
        `COALESCE(excluded, stored)` so a later sighting with missing
        fields never wipes previously learned data. `last_seen` is always
        overwritten with the incoming value (falling back to the stored
        one via COALESCE if somehow absent). `first_seen` is set-once: the
        existing stored value always wins over the incoming one. `hits`
        is not read from the incoming dict at all — it starts at 1 on
        insert and increments by 1 on every subsequent upsert.

        The INSERT column list is built from the keys ACTUALLY present in
        the incoming dict (plus `id`/`hits`), never the full column set —
        binding an explicit NULL for an absent column would defeat the SQL
        DEFAULT (e.g. `tier` landing as NULL instead of DEFAULT 'info').
        """
        pres_id = pres.get("id")
        if not pres_id:
            raise ValueError("upsert requires an 'id' key")

        present = [c for c in _ALL_UPSERT_COLUMNS if c in pres]

        cols = ["id"] + present + ["hits"]
        values = [pres_id] + [pres.get(c) for c in present] + [1]
        placeholders = ", ".join("?" for _ in cols)
        col_list = ", ".join(cols)

        set_clauses = []
        for c in present:
            if c == _FIRST_SEEN_COLUMN:
                # set-once: the existing stored value always wins.
                set_clauses.append(f"{c} = COALESCE(presences.{c}, excluded.{c})")
            else:
                # best-value / always-set: a later non-null value wins,
                # but a NULL never wipes a previously stored non-null value.
                set_clauses.append(f"{c} = COALESCE(excluded.{c}, presences.{c})")
        set_clauses.append("hits = presences.hits + 1")

        conflict_sql = f"ON CONFLICT(id) DO UPDATE SET {', '.join(set_clauses)}"

        sql = (
            f"INSERT INTO presences ({col_list}) VALUES ({placeholders}) "
            f"{conflict_sql}"
        )
        with self._lock:
            self._conn.execute(sql, values)
            self._conn.commit()

    def get(self, id: str) -> dict | None:  # noqa: A002 - matches spec's `get(id)`
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM presences WHERE id = ?", (id,)
            ).fetchone()
        return self._row_to_dict(row)

    def list(self, *, plane: str | None = None, tier: str | None = None, limit: int = 1000) -> list:
        clauses = []
        params: list = []
        if plane is not None:
            clauses.append("plane = ?")
            params.append(plane)
        if tier is not None:
            clauses.append("tier = ?")
            params.append(tier)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)
        sql = (
            f"SELECT * FROM presences {where} "
            f"ORDER BY last_seen DESC LIMIT ?"
        )
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    def count(self, plane: str | None = None) -> int:
        with self._lock:
            if plane is not None:
                row = self._conn.execute(
                    "SELECT COUNT(*) AS n FROM presences WHERE plane = ?", (plane,)
                ).fetchone()
            else:
                row = self._conn.execute("SELECT COUNT(*) AS n FROM presences").fetchone()
        return int(row["n"])

    def record_alert(self, plane: str, tier: str, detail: str = "") -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO presence_alerts (ts, plane, tier, detail) VALUES (?, ?, ?, ?)",
                (int(time.time()), plane, tier, detail),
            )
            self._conn.commit()

    def alerts(self, limit: int = 200) -> list:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM presence_alerts ORDER BY ts DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    def prune_wan(self, *, max_age_days: int = 7, min_hits: int = 5) -> int:
        """Age out stale, low-value WAN presences (Project B, #820 whole-
        branch fix I1, spec §9).

        `collect_wan` upserts one row per distinct `client_ip` EVER seen,
        so the `presences` table grows unbounded for the `wan` plane in
        particular (a one-off scanner/bot IP is never seen again but its
        row lives forever). This deletes only rows where
        `plane = 'wan' AND last_seen < (now - max_age_days*86400) AND
        hits < min_hits` — a stale row that was ALSO seen repeatedly
        (`hits >= min_hits`) is kept, on the theory that a recurring
        visitor is worth keeping counts for even once quiet. Only the
        `wan` plane is ever touched here: `lan`/`wg` (mirrors of Project
        A's own bounded `devices` table) and `kbin` (bounded by the
        toolbox's own persona set) are never pruned by this method.

        Returns the number of rows deleted. Uses the same lock + a single
        parameterized `DELETE` as every other method here.
        """
        cutoff = int(time.time()) - max_age_days * 86400
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM presences WHERE plane = 'wan' AND last_seen < ? AND hits < ?",
                (cutoff, min_hits),
            )
            self._conn.commit()
        return cur.rowcount
