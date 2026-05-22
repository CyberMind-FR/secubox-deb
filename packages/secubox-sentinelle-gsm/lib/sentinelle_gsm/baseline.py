# packages/secubox-sentinelle-gsm/lib/sentinelle_gsm/baseline.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gerald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
Operator baseline — list of cells the operator's carrier(s) legitimately
operate in this RF environment. Cells are graduated to baseline after
being observed N>=3 times; or in 'learn mode' every cell observed within
a sweep window is marked baseline regardless of count.

Used by the scoring engine for ghost_bts + identity_mismatch +
cipher_downgrade heuristics.

Privacy invariant: BaselineCell has NO subscriber-id field. The
cell_baseline table colocated in observations.db likewise has no
paged-identity column. Enforced by tests/test_privacy_invariant.py.
"""

from __future__ import annotations

import dataclasses
import sqlite3
import time
from typing import Optional


@dataclasses.dataclass
class BaselineCell:
    cell_id: str
    mcc: Optional[int] = None
    mnc: Optional[int] = None
    lac: Optional[int] = None
    arfcn: Optional[int] = None
    learn_count: int = 1
    first_learned: float = 0.0
    last_learned: float = 0.0
    cipher_a5: Optional[int] = None


class CellBaseline:
    """Thin wrapper over the cell_baseline table colocated in observations.db.

    Takes a raw sqlite3.Connection (NOT an ObservationsDB) so it can share
    the same db file without coupling to observations.py's public interface.
    """

    LEARN_THRESHOLD = 3      # default — cells need >=3 sightings to graduate

    def __init__(self, db: sqlite3.Connection):
        self._db = db
        self._learn_mode_until: float = 0.0   # epoch; learn_mode while now() < this

    def set_learn_mode(self, seconds: float) -> None:
        """Enable explicit-learn-mode for the next `seconds` seconds.
        Every cell observed in that window graduates to baseline on first
        sighting (initial learn_count = LEARN_THRESHOLD)."""
        self._learn_mode_until = time.time() + seconds

    def in_learn_mode(self) -> bool:
        return time.time() < self._learn_mode_until

    def consider(self, cell_id: str, mcc=None, mnc=None, lac=None,
                 arfcn=None, cipher_a5=None) -> None:
        """Called by the consume loop on every cell sighting. In learn
        mode, immediately graduate; otherwise increment learn_count and
        graduate when it crosses LEARN_THRESHOLD."""
        now = time.time()
        row = self._db.execute(
            "SELECT learn_count FROM cell_baseline WHERE cell_id = ?",
            (cell_id,),
        ).fetchone()
        if row is None:
            initial = self.LEARN_THRESHOLD if self.in_learn_mode() else 1
            self._db.execute(
                "INSERT INTO cell_baseline(cell_id,mcc,mnc,lac,arfcn,learn_count,"
                "first_learned,last_learned,cipher_a5) VALUES (?,?,?,?,?,?,?,?,?)",
                (cell_id, mcc, mnc, lac, arfcn, initial, now, now, cipher_a5),
            )
        else:
            new_count = row[0] + 1
            self._db.execute(
                "UPDATE cell_baseline SET learn_count = ?, last_learned = ?, "
                "mcc = COALESCE(?, mcc), mnc = COALESCE(?, mnc), "
                "lac = COALESCE(?, lac), arfcn = COALESCE(?, arfcn), "
                "cipher_a5 = COALESCE(?, cipher_a5) WHERE cell_id = ?",
                (new_count, now, mcc, mnc, lac, arfcn, cipher_a5, cell_id),
            )
        self._db.commit()

    def is_baseline(self, cell_id: str) -> bool:
        row = self._db.execute(
            "SELECT learn_count FROM cell_baseline WHERE cell_id = ?",
            (cell_id,),
        ).fetchone()
        return row is not None and row[0] >= self.LEARN_THRESHOLD

    def get(self, cell_id: str) -> Optional[BaselineCell]:
        row = self._db.execute(
            "SELECT cell_id,mcc,mnc,lac,arfcn,learn_count,first_learned,last_learned,cipher_a5 "
            "FROM cell_baseline WHERE cell_id = ?",
            (cell_id,),
        ).fetchone()
        return BaselineCell(*row) if row else None

    def list(self, limit: int = 200) -> list[BaselineCell]:
        rows = self._db.execute(
            "SELECT cell_id,mcc,mnc,lac,arfcn,learn_count,first_learned,last_learned,cipher_a5 "
            "FROM cell_baseline ORDER BY last_learned DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [BaselineCell(*r) for r in rows]
