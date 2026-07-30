# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-ytsas :: library.py
CyberMind — https://cybermind.fr

SQLite-backed yt-dlp media library — the "sas" (staging area). A downloaded
video is CONSERVED BY DEFAULT (nothing auto-disappears); purge is opt-in: set
`ephemeral_until` and only then does the sweep delete it, at that time. A video
can also be conserved permanently in PeerTube (peertube_* columns).

Semantics mirror the torrent SAS (packages/secubox-torrent/lxc/app/library.js)
exactly: kept-by-default, opt-in ephemeral TTL, disk-floor safety valve that
touches ONLY ephemerals, and a host-mediated conserve → PeerTube pipeline.
"""

import sqlite3
import threading
import time


def _now() -> int:
    return int(time.time())


class Library:
    """Thread-safe (single lock, check_same_thread=False) SQLite library.

    The API layer calls these from FastAPI's threadpool (`def` handlers) and
    from the async purge loop, so every access is serialised through _lock.
    """

    def __init__(self, db_path: str):
        self.db = sqlite3.connect(db_path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        # kept defaults to 1: conserve by default. `ephemeral_until` (unix ts,
        # nullable) is the opt-in purge marker — NULL means "never purge".
        # `complete`=1 once the yt-dlp download finished (path then points at the
        # produced file). id = the yt-dlp video id, or a sha1(url) fallback.
        with self._lock:
            self.db.execute(
                """CREATE TABLE IF NOT EXISTS items (
                    id TEXT PRIMARY KEY,
                    url TEXT,
                    title TEXT,
                    path TEXT,
                    added_at INTEGER,
                    kept INTEGER DEFAULT 1,
                    ephemeral_until INTEGER,
                    peertube_status TEXT,
                    peertube_url TEXT,
                    complete INTEGER DEFAULT 0)"""
            )
            self._migrate()
            self.db.commit()

    # Add columns that older DBs lack, and flip any legacy ephemeral-by-default
    # rows to conserved so an upgrade never silently purges existing content.
    def _migrate(self):
        cols = {r["name"] for r in self.db.execute("PRAGMA table_info(items)")}

        def add(name, decl):
            if name not in cols:
                self.db.execute(f"ALTER TABLE items ADD COLUMN {name} {decl}")

        add("ephemeral_until", "INTEGER")
        add("peertube_status", "TEXT")
        add("peertube_url", "TEXT")
        add("complete", "INTEGER DEFAULT 0")
        # Legacy rows stored kept=0 (ephemeral-by-default). Under the sas model
        # they become conserved: keep them, no ephemeral_until → never purged.
        self.db.execute(
            "UPDATE items SET kept=1 WHERE kept=0 AND ephemeral_until IS NULL"
        )

    # ------------------------------------------------------------------ writes
    def add(self, id: str, url: str, title: str, path: str):
        """Insert a freshly-queued item (complete=0, conserved by default).

        Re-adding a known id must NOT reset its purge marker, PeerTube status,
        or completion — only refresh the (possibly better) title/url. Mirrors
        the torrent library's ON CONFLICT touch-only behaviour.
        """
        now = _now()
        with self._lock:
            self.db.execute(
                """INSERT INTO items (id,url,title,path,added_at,kept,ephemeral_until,complete)
                   VALUES (?,?,?,?,?,1,NULL,0)
                   ON CONFLICT(id) DO UPDATE SET
                     url=excluded.url,
                     title=COALESCE(NULLIF(excluded.title,''), items.title)""",
                (id, url, title, path, now),
            )
            self.db.commit()

    def keep(self, id: str, new_path: str = None):
        """Conserve indefinitely: clear any purge marker (kept=1, ephemeral NULL)."""
        with self._lock:
            self.db.execute(
                "UPDATE items SET kept=1, ephemeral_until=NULL, path=COALESCE(?,path) WHERE id=?",
                (new_path, id),
            )
            self.db.commit()

    def set_ephemeral(self, id: str, until):
        """Opt-in purge: delete this item at `until` (unix ts). Falsy = cancel."""
        if not until:
            return self.keep(id)
        with self._lock:
            self.db.execute(
                "UPDATE items SET kept=0, ephemeral_until=? WHERE id=?",
                (int(until), id),
            )
            self.db.commit()

    def set_peertube(self, id: str, status: str, url: str = None):
        with self._lock:
            self.db.execute(
                "UPDATE items SET peertube_status=?, peertube_url=COALESCE(?,peertube_url) WHERE id=?",
                (status, url, id),
            )
            self.db.commit()

    def set_complete(self, id: str, v=1, path: str = None):
        with self._lock:
            self.db.execute(
                "UPDATE items SET complete=?, path=COALESCE(?,path) WHERE id=?",
                (1 if v else 0, path, id),
            )
            self.db.commit()

    def remove(self, id: str):
        with self._lock:
            self.db.execute("DELETE FROM items WHERE id=?", (id,))
            self.db.commit()

    # ------------------------------------------------------------------- reads
    def list(self):
        with self._lock:
            rows = self.db.execute(
                "SELECT * FROM items ORDER BY added_at DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    def get(self, id: str):
        with self._lock:
            r = self.db.execute("SELECT * FROM items WHERE id=?", (id,)).fetchone()
        return dict(r) if r else None

    # Rows still downloading — used to surface in-flight jobs after a restart.
    def incomplete(self):
        with self._lock:
            rows = self.db.execute(
                "SELECT * FROM items WHERE complete=0 OR complete IS NULL"
            ).fetchall()
        return [dict(r) for r in rows]

    # Items whose opt-in purge time has passed — the ONLY rows the sweep deletes.
    def expired_ephemeral(self, now: int = None):
        now = _now() if now is None else now
        with self._lock:
            rows = self.db.execute(
                "SELECT id FROM items WHERE ephemeral_until IS NOT NULL AND ephemeral_until < ?",
                (now,),
            ).fetchall()
        return [r["id"] for r in rows]

    # Every user-marked-ephemeral row (regardless of time) — used ONLY as the
    # disk-floor safety valve; conserved content is never returned here.
    def marked_ephemeral(self):
        with self._lock:
            rows = self.db.execute(
                "SELECT id FROM items WHERE ephemeral_until IS NOT NULL"
            ).fetchall()
        return [r["id"] for r in rows]

    # Headline counts for the dashboard cardlet. Single query, all real rows.
    def counts(self):
        with self._lock:
            r = self.db.execute(
                """SELECT
                     COUNT(*) AS total,
                     SUM(CASE WHEN kept=1 THEN 1 ELSE 0 END) AS conserved,
                     SUM(CASE WHEN complete=0 OR complete IS NULL THEN 1 ELSE 0 END) AS downloading,
                     SUM(CASE WHEN peertube_status IS NOT NULL AND peertube_status <> '' THEN 1 ELSE 0 END) AS to_peertube
                   FROM items"""
            ).fetchone()
        return {
            "total": r["total"] or 0,
            "conserved": r["conserved"] or 0,
            "downloading": r["downloading"] or 0,
            "to_peertube": r["to_peertube"] or 0,
        }
