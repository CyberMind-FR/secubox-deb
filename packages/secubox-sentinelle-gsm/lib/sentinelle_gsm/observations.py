# packages/secubox-sentinelle-gsm/lib/sentinelle_gsm/observations.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gerald Kerma <devel@cybermind.fr>

"""
SQLite-backed cell sightings + paging events store.

Privacy invariant: paging_events stores ONLY subscriber_hash (HMAC),
never plaintext IMSI/TMSI/IMEI. Enforced by a WRITE-time shape check
identical to the one in alert_sink.
"""

from __future__ import annotations

import re
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


_PLAINTEXT_IMSI_RE = re.compile(r"\b\d{15}\b")


@dataclass
class Sighting:
    cell_id: str
    mcc: Optional[int] = None
    mnc: Optional[int] = None
    lac: Optional[int] = None
    ci: Optional[int] = None
    arfcn: Optional[int] = None
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    sighting_count: int = 1


@dataclass
class PagingEvent:
    ts: float
    cell_id: str
    subscriber_hash: str        # HMAC-trunc, NEVER plaintext
    request_type: str           # "paging-tmsi" | "paging-imsi" | "identity-request" | ...


class ObservationsDB:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(str(self.path), check_same_thread=False)
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS sightings (
                cell_id TEXT PRIMARY KEY,
                mcc INTEGER, mnc INTEGER, lac INTEGER, ci INTEGER,
                arfcn INTEGER,
                first_seen REAL NOT NULL,
                last_seen  REAL NOT NULL,
                sighting_count INTEGER NOT NULL DEFAULT 1
            )
        """)
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS paging_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL NOT NULL,
                cell_id TEXT NOT NULL,
                subscriber_hash TEXT NOT NULL,
                request_type TEXT NOT NULL
            )
        """)
        self._db.execute("CREATE INDEX IF NOT EXISTS pe_ts_idx ON paging_events(ts)")
        self._db.execute("CREATE INDEX IF NOT EXISTS pe_cell_idx ON paging_events(cell_id)")
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS cell_baseline (
                cell_id TEXT PRIMARY KEY,
                mcc INTEGER, mnc INTEGER, lac INTEGER, arfcn INTEGER,
                learn_count INTEGER NOT NULL DEFAULT 1,
                first_learned REAL NOT NULL,
                last_learned  REAL NOT NULL,
                cipher_a5     INTEGER
            )
        """)
        self._db.commit()

    def upsert_sighting(self, s: Sighting) -> None:
        self._guard_plaintext(s.cell_id)
        now = time.time()
        cur = self._db.execute(
            "SELECT first_seen, sighting_count FROM sightings WHERE cell_id = ?",
            (s.cell_id,),
        ).fetchone()
        if cur is None:
            self._db.execute(
                "INSERT INTO sightings(cell_id,mcc,mnc,lac,ci,arfcn,first_seen,last_seen,sighting_count) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (s.cell_id, s.mcc, s.mnc, s.lac, s.ci, s.arfcn,
                 now, now, 1),
            )
        else:
            self._db.execute(
                "UPDATE sightings SET last_seen=?, sighting_count=sighting_count+1, "
                "arfcn=COALESCE(?, arfcn), mcc=COALESCE(?, mcc), mnc=COALESCE(?, mnc), "
                "lac=COALESCE(?, lac), ci=COALESCE(?, ci) WHERE cell_id=?",
                (now, s.arfcn, s.mcc, s.mnc, s.lac, s.ci, s.cell_id),
            )
        self._db.commit()

    def record_paging(self, e: PagingEvent) -> None:
        self._guard_plaintext(e.cell_id)
        self._guard_plaintext(e.subscriber_hash)
        self._db.execute(
            "INSERT INTO paging_events(ts,cell_id,subscriber_hash,request_type) VALUES (?,?,?,?)",
            (e.ts, e.cell_id, e.subscriber_hash, e.request_type),
        )
        self._db.commit()

    def sightings(self, limit: int = 200) -> list[Sighting]:
        rows = self._db.execute(
            "SELECT cell_id,mcc,mnc,lac,ci,arfcn,first_seen,last_seen,sighting_count "
            "FROM sightings ORDER BY last_seen DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [Sighting(*r) for r in rows]

    def paging_for_cell(self, cell_id: str, limit: int = 100) -> list[PagingEvent]:
        rows = self._db.execute(
            "SELECT ts, cell_id, subscriber_hash, request_type FROM paging_events "
            "WHERE cell_id = ? ORDER BY ts DESC LIMIT ?",
            (cell_id, limit),
        ).fetchall()
        return [PagingEvent(*r) for r in rows]

    def _guard_plaintext(self, value: str) -> None:
        if _PLAINTEXT_IMSI_RE.search(value or ""):
            raise ValueError("observations: plaintext-IMSI shape detected — refusing write")
