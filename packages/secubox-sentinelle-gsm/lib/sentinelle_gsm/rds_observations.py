# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gerald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
RDS station registry. Shares the same SQLite file as the GSM
observation pipeline (observations.db) so an operator can inspect
both surfaces with one DB query.

The PI code is the natural key: a 4-hex value (0x0000-0xFFFF) that
uniquely identifies a station within its country. We UPSERT on every
frame, bump `count`, and refresh `last_seen`. The `ps` (Program
Service, 8 chars) updates on every set — radios often display the
LATEST one. `rt` (RadioText) is kept too because it carries the live
song title / news ticker.

Schema is idempotent: the constructor creates the table if missing.
"""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path
from typing import Iterable, Optional


# Columns are denormalised on purpose — the cardinality is tiny
# (~100 stations max in any one geographic area) and a single-table
# UPSERT keeps the API endpoint logic trivial.
_DDL = """
CREATE TABLE IF NOT EXISTS rds_stations (
    pi          TEXT    PRIMARY KEY,    -- 4-hex Program Identification
    ps          TEXT,                   -- 8-char Program Service name
    rt          TEXT,                   -- last RadioText (up to 64 chars)
    pty         INTEGER,                -- Program Type 0-31
    tp          INTEGER,                -- Traffic Program flag (0/1)
    ta          INTEGER,                -- Traffic Announcement flag (0/1)
    freq        TEXT,                   -- frequency we saw this PI on
    first_seen  REAL    NOT NULL,
    last_seen   REAL    NOT NULL,
    count       INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS rds_stations_last_seen_idx
    ON rds_stations (last_seen DESC);
"""


class RdsStationRegistry:
    """Tiny wrapper around the rds_stations table. Constructor accepts
    either a pre-opened sqlite3.Connection (so we share the same file
    + transaction context as the GSM observations DB) OR a Path."""

    def __init__(self, conn_or_path):
        if isinstance(conn_or_path, (str, Path)):
            self.conn = sqlite3.connect(str(conn_or_path), check_same_thread=False)
            self._owns = True
        else:
            self.conn = conn_or_path
            self._owns = False
        # idempotent schema bootstrap
        self.conn.executescript(_DDL)
        self.conn.commit()

    def record(
        self,
        *,
        pi: str,
        ps: Optional[str] = None,
        rt: Optional[str] = None,
        pty: Optional[int] = None,
        tp: Optional[bool] = None,
        ta: Optional[bool] = None,
        freq: Optional[str] = None,
    ) -> None:
        """Upsert one RDS frame. The PI is the only required field —
        early frames often have just PI; PS/RT trickle in over a few
        seconds."""
        now = time.time()
        # COALESCE keeps the previous value when the incoming frame
        # didn't include that field. Without this, an early bare-PI
        # frame would overwrite a good PS with NULL.
        self.conn.execute(
            """
            INSERT INTO rds_stations
                (pi, ps, rt, pty, tp, ta, freq, first_seen, last_seen, count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
            ON CONFLICT(pi) DO UPDATE SET
                ps        = COALESCE(excluded.ps, ps),
                rt        = COALESCE(excluded.rt, rt),
                pty       = COALESCE(excluded.pty, pty),
                tp        = COALESCE(excluded.tp, tp),
                ta        = COALESCE(excluded.ta, ta),
                freq      = COALESCE(excluded.freq, freq),
                last_seen = excluded.last_seen,
                count     = count + 1
            """,
            (
                pi,
                ps,
                rt,
                pty,
                1 if tp else (0 if tp is False else None),
                1 if ta else (0 if ta is False else None),
                freq,
                now,
                now,
            ),
        )
        self.conn.commit()

    def list_stations(self, limit: int = 200) -> list[dict]:
        """Newest-first list of all observed stations."""
        cur = self.conn.execute(
            """
            SELECT pi, ps, rt, pty, tp, ta, freq,
                   first_seen, last_seen, count
              FROM rds_stations
             ORDER BY last_seen DESC
             LIMIT ?
            """,
            (limit,),
        )
        cols = [c[0] for c in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]

    def count(self) -> int:
        cur = self.conn.execute("SELECT count(*) FROM rds_stations")
        return cur.fetchone()[0]

    def close(self) -> None:
        if self._owns:
            self.conn.close()
