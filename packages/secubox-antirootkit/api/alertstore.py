# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: antirootkit alert store (v1)

A small, capped SQLite-backed alert queue shared between the exec-watch
daemon (api/daemon.py — appends an alert whenever it jails an unknown
process) and the FastAPI GET /alerts endpoint (api/main.py — reads it).

Cross-process by construction (ref #915 re-review): sbx-antirootkitd.service
(the daemon, `python3 -m api.daemon`) and secubox-antirootkit.service (the
API, `uvicorn api.main:app`) are TWO SEPARATE systemd units/processes. A
plain module-level Python list would be a no-op across that boundary — each
process gets its own copy, so the daemon's append() would never be visible
to the API's GET /alerts. This mirrors api.execlog.ExecLog exactly (which
already correctly shares /var/lib/secubox/antirootkit/execlog.db between
both processes): both sides open the SAME sqlite file at
/var/lib/secubox/antirootkit/alerts.db.

This is intentionally NOT the durable forensic record — that's still
ExecLog, append-only. This store only backs the live /alerts view and is
capped (oldest rows dropped first).
"""

from __future__ import annotations

import json
import sqlite3
import time

DEFAULT_DB_PATH = "/var/lib/secubox/antirootkit/alerts.db"
MAX_ALERTS = 500

DDL = (
    "CREATE TABLE IF NOT EXISTS alerts ("
    "ts REAL, exe TEXT, pid INT, score INT, reasons TEXT, dest TEXT, "
    "ioc INT, data TEXT)"
)


class AlertStore:
    """SQLite-backed alert queue, opened at the same db_path by both the
    daemon (writer) and the API (reader) processes."""

    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        # check_same_thread=False: FastAPI's sync `def` routes run in a
        # threadpool worker thread (see api/execlog.py for the identical
        # rationale); sqlite3 serializes access to a connection internally,
        # so this is safe for our single-writer-per-process usage.
        self.db = sqlite3.connect(db_path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute(DDL)
        self.db.commit()

    def append(self, alert: dict, now=time.time) -> None:
        """INSERT an alert dict (as produced by api.alerts.build_alert) and
        trim the table back down to MAX_ALERTS rows (oldest dropped first)."""
        self.db.execute(
            "INSERT INTO alerts VALUES (?,?,?,?,?,?,?,?)",
            (
                now(),
                alert.get("exe"),
                alert.get("pid"),
                alert.get("score"),
                json.dumps(alert.get("reasons") or []),
                alert.get("dest"),
                int(bool(alert.get("ioc"))),
                json.dumps(alert),
            ),
        )
        self.db.commit()
        self._trim()

    def _trim(self) -> None:
        self.db.execute(
            "DELETE FROM alerts WHERE rowid NOT IN "
            "(SELECT rowid FROM alerts ORDER BY ts DESC, rowid DESC LIMIT ?)",
            (MAX_ALERTS,),
        )
        self.db.commit()

    def recent(self, limit: int = 500) -> list[dict]:
        """Return up to `limit` alerts, most-recent-first. Returns the
        original alert dict (the `data` column) so callers see exactly what
        api.alerts.build_alert() produced, not a lossy column projection."""
        if limit <= 0:
            return []
        cur = self.db.execute(
            "SELECT data FROM alerts ORDER BY ts DESC, rowid DESC LIMIT ?",
            (limit,),
        )
        return [json.loads(r["data"]) for r in cur.fetchall()]

    def clear(self) -> None:
        """Test-only: empty the table."""
        self.db.execute("DELETE FROM alerts")
        self.db.commit()
