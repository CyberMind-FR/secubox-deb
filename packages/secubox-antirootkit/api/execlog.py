# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: antirootkit execlog — append-only forensic archive

Records every exec event (pid, uid, exe, argv, verdict, dpkg backing) as an
immutable append-only SQLite log. No UPDATE/DELETE API — append-only by design.
"""

import sqlite3
import json
import time


DDL = "CREATE TABLE IF NOT EXISTS execlog (ts REAL, pid INT, ppid INT, uid INT, exe TEXT, argv TEXT, success INT, verdict TEXT, pkg TEXT)"


class ExecLog:
    """Append-only SQLite forensic log for execve events."""

    def __init__(self, db_path: str, check_same_thread: bool = True):
        """Open/create SQLite db in WAL mode, initialize execlog table.

        Args:
            db_path: filesystem path to the SQLite database
            check_same_thread: sqlite3's default (True) forbids using the
                connection from a thread other than the one that created it.
                FastAPI's sync `def` routes run in a threadpool worker thread,
                so the API module must construct its ExecLog singleton with
                check_same_thread=False (single-writer append-only log; the
                sqlite3 module serializes access internally). Default True
                preserves prior callers/tests unchanged.
        """
        self.db = sqlite3.connect(db_path, check_same_thread=check_same_thread)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute(DDL)
        self.db.commit()

    def record(self, ev, verdict: str, pkg=None, now=time.time):
        """INSERT-only: append an exec event to the log.

        Args:
            ev: ExecEvent with pid, ppid, uid, exe, argv, success
            verdict: "allow" or "jail"
            pkg: str|None, dpkg package backing exe (if known)
            now: callable returning float timestamp (default time.time)
        """
        self.db.execute(
            "INSERT INTO execlog VALUES (?,?,?,?,?,?,?,?,?)",
            (
                now(),
                ev.pid,
                ev.ppid,
                ev.uid,
                ev.exe,
                json.dumps(ev.argv),
                int(ev.success),
                verdict,
                pkg,
            ),
        )
        self.db.commit()

    def recent(self, limit: int = 100) -> list:
        """Return most recent execlog rows (most recent first).

        Args:
            limit: max number of rows to return

        Returns:
            list[dict] of rows in DESC timestamp order
        """
        cur = self.db.execute(
            "SELECT * FROM execlog ORDER BY ts DESC LIMIT ?", (limit,)
        )
        return [dict(r) for r in cur.fetchall()]

    def count(self) -> int:
        """Return the true total number of execlog rows (unbounded by any
        `limit`, unlike `recent()`) — used for the /status monitoring badge
        so it doesn't freeze at 100 once the log grows past that size."""
        cur = self.db.execute("SELECT COUNT(*) c FROM execlog")
        return cur.fetchone()["c"]

    def failed_exec_count(self, exe: str, window_s: int, now=time.time) -> int:
        """Count failed exec attempts for exe within time window.

        Used to detect crash-loops (e.g. repeating failed exec of unknown binary).

        Args:
            exe: executable path
            window_s: time window in seconds
            now: callable returning float timestamp (default time.time)

        Returns:
            count of rows where success=0 and exe matches within window
        """
        cur = self.db.execute(
            "SELECT COUNT(*) c FROM execlog WHERE exe=? AND success=0 AND ts>=?",
            (exe, now() - window_s),
        )
        return cur.fetchone()["c"]
