# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: Podcaster store
CyberMind — https://cybermind.fr

SQLite persistence for feeds + episodes. Pure stdlib (sqlite3); no ORM.
"""
import sqlite3
import time
from pathlib import Path
from typing import Any, Optional

DB_PATH = Path("/var/lib/secubox/podcaster/podcaster.db")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS feeds (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    url         TEXT UNIQUE NOT NULL,
    title       TEXT,
    description TEXT,
    image       TEXT,
    site        TEXT,
    added_ts    INTEGER NOT NULL,
    last_fetch  INTEGER DEFAULT 0,
    auto_dl     INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS episodes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    feed_id     INTEGER NOT NULL REFERENCES feeds(id) ON DELETE CASCADE,
    guid        TEXT NOT NULL,
    title       TEXT,
    description TEXT,
    pubdate     INTEGER DEFAULT 0,
    enclosure   TEXT,
    mime        TEXT,
    bytes       INTEGER DEFAULT 0,
    duration    TEXT,
    local_path  TEXT,
    state       TEXT DEFAULT 'new',   -- new | queued | downloading | done | error
    progress    INTEGER DEFAULT 0,    -- 0..100
    error       TEXT,
    UNIQUE(feed_id, guid)
);
CREATE INDEX IF NOT EXISTS idx_ep_feed ON episodes(feed_id);
CREATE INDEX IF NOT EXISTS idx_ep_state ON episodes(state);
CREATE INDEX IF NOT EXISTS idx_ep_pub ON episodes(pubdate DESC);
"""


def _conn() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(DB_PATH, timeout=10)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    c.execute("PRAGMA journal_mode=WAL")
    return c


def init() -> None:
    with _conn() as c:
        c.executescript(_SCHEMA)


# ── feeds ──────────────────────────────────────────────────────────
def add_feed(url: str, meta: dict, auto_dl: int = 0) -> int:
    with _conn() as c:
        cur = c.execute(
            "INSERT OR IGNORE INTO feeds(url,title,description,image,site,added_ts,auto_dl) "
            "VALUES(?,?,?,?,?,?,?)",
            (url, meta.get("title"), meta.get("description"),
             meta.get("image"), meta.get("site"), int(time.time()), int(auto_dl)),
        )
        if cur.lastrowid:
            return cur.lastrowid
        row = c.execute("SELECT id FROM feeds WHERE url=?", (url,)).fetchone()
        return row["id"] if row else 0


def set_feed_autodl(feed_id: int, on: int) -> None:
    with _conn() as c:
        c.execute("UPDATE feeds SET auto_dl=? WHERE id=?", (int(on), feed_id))


def feed_autodl(feed_id: int) -> int:
    with _conn() as c:
        r = c.execute("SELECT auto_dl FROM feeds WHERE id=?", (feed_id,)).fetchone()
        return int(r["auto_dl"]) if r else 0


def pending_episode_ids(feed_id: int, limit: int = 0) -> list[int]:
    """Episode ids in state 'new' for a feed (newest first); for auto-download."""
    q = "SELECT id FROM episodes WHERE feed_id=? AND state='new' ORDER BY pubdate DESC"
    if limit and limit > 0:
        q += f" LIMIT {int(limit)}"
    with _conn() as c:
        return [r["id"] for r in c.execute(q, (feed_id,)).fetchall()]


def update_feed_meta(feed_id: int, meta: dict) -> None:
    with _conn() as c:
        c.execute(
            "UPDATE feeds SET title=COALESCE(?,title), description=COALESCE(?,description), "
            "image=COALESCE(?,image), site=COALESCE(?,site), last_fetch=? WHERE id=?",
            (meta.get("title"), meta.get("description"), meta.get("image"),
             meta.get("site"), int(time.time()), feed_id),
        )


def list_feeds() -> list[dict]:
    with _conn() as c:
        rows = c.execute(
            "SELECT f.*, "
            "(SELECT COUNT(*) FROM episodes e WHERE e.feed_id=f.id) AS episodes, "
            "(SELECT COUNT(*) FROM episodes e WHERE e.feed_id=f.id AND e.state='done') AS downloaded "
            "FROM feeds f ORDER BY f.title COLLATE NOCASE"
        ).fetchall()
        return [dict(r) for r in rows]


def delete_feed(feed_id: int) -> None:
    with _conn() as c:
        c.execute("DELETE FROM feeds WHERE id=?", (feed_id,))


def all_feed_urls() -> list[tuple[int, str]]:
    with _conn() as c:
        return [(r["id"], r["url"]) for r in c.execute("SELECT id,url FROM feeds")]


# ── episodes ───────────────────────────────────────────────────────
def upsert_episode(feed_id: int, ep: dict) -> None:
    with _conn() as c:
        c.execute(
            "INSERT OR IGNORE INTO episodes"
            "(feed_id,guid,title,description,pubdate,enclosure,mime,bytes,duration) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            (feed_id, ep["guid"], ep.get("title"), ep.get("description"),
             ep.get("pubdate", 0), ep.get("enclosure"), ep.get("mime"),
             ep.get("bytes", 0), ep.get("duration")),
        )


def list_episodes(feed_id: Optional[int] = None, state: Optional[str] = None,
                  limit: int = 200) -> list[dict]:
    q = ("SELECT e.*, f.title AS feed_title, f.image AS feed_image "
         "FROM episodes e JOIN feeds f ON f.id=e.feed_id")
    where, args = [], []
    if feed_id is not None:
        where.append("e.feed_id=?"); args.append(feed_id)
    if state:
        where.append("e.state=?"); args.append(state)
    if where:
        q += " WHERE " + " AND ".join(where)
    # Order by container type: an audiobook plays first chapter → last (pubdate
    # ASC, since the upload stamps chapter i with base+i); a podcast shows the
    # latest first (pubdate DESC). One CASE handles both, even in a mixed list.
    q += (" ORDER BY CASE WHEN f.url LIKE 'audiobook:%' "
          "THEN e.pubdate ELSE -e.pubdate END ASC LIMIT ?")
    args.append(limit)
    with _conn() as c:
        return [dict(r) for r in c.execute(q, args).fetchall()]


def get_episode(ep_id: int) -> Optional[dict]:
    with _conn() as c:
        r = c.execute("SELECT * FROM episodes WHERE id=?", (ep_id,)).fetchone()
        return dict(r) if r else None


def set_episode(ep_id: int, **fields: Any) -> None:
    if not fields:
        return
    cols = ", ".join(f"{k}=?" for k in fields)
    with _conn() as c:
        c.execute(f"UPDATE episodes SET {cols} WHERE id=?", (*fields.values(), ep_id))


def downloaded_episodes(limit: int = 500) -> list[dict]:
    """Episodes with a local file — the shareable library."""
    with _conn() as c:
        rows = c.execute(
            "SELECT e.*, f.title AS feed_title FROM episodes e JOIN feeds f ON f.id=e.feed_id "
            "WHERE e.state='done' AND e.local_path IS NOT NULL "
            "ORDER BY CASE WHEN f.url LIKE 'audiobook:%' "
            "THEN e.pubdate ELSE -e.pubdate END ASC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]


def counts() -> dict:
    with _conn() as c:
        return {
            "feeds": c.execute("SELECT COUNT(*) FROM feeds").fetchone()[0],
            "episodes": c.execute("SELECT COUNT(*) FROM episodes").fetchone()[0],
            "downloaded": c.execute(
                "SELECT COUNT(*) FROM episodes WHERE state='done'").fetchone()[0],
            "queued": c.execute(
                "SELECT COUNT(*) FROM episodes WHERE state IN('queued','downloading')"
            ).fetchone()[0],
        }
