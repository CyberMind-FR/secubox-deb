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
CREATE TABLE IF NOT EXISTS splice_host_obs (
    host       TEXT PRIMARY KEY,
    hits       INTEGER NOT NULL DEFAULT 0,
    html_hits  INTEGER NOT NULL DEFAULT 0,
    last_seen  REAL
);
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
CREATE TABLE IF NOT EXISTS ad_block_stats (
    ad_host TEXT, site TEXT, action TEXT,
    hits INTEGER NOT NULL DEFAULT 0, bytes INTEGER NOT NULL DEFAULT 0,
    last_seen REAL, PRIMARY KEY (ad_host, site, action));
CREATE TABLE IF NOT EXISTS ad_candidates (
    host TEXT, site TEXT, hits INTEGER NOT NULL DEFAULT 0, last_seen REAL,
    PRIMARY KEY (host, site));
CREATE TABLE IF NOT EXISTS ad_block_client_host (
    mac_hash TEXT, ad_host TEXT, hits INTEGER NOT NULL DEFAULT 0,
    bytes INTEGER NOT NULL DEFAULT 0, last_seen REAL,
    PRIMARY KEY (mac_hash, ad_host));
"""


def _conn() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(DB_PATH, timeout=5)
    c.row_factory = sqlite3.Row
    c.executescript(SCHEMA)
    return c


def record_ad_blocks(rows) -> None:
    """rows: iterable of (ad_host, site, action, hits, bytes). Batch upsert."""
    rows = [r for r in rows if r and r[0]]
    if not rows:
        return
    now = time.time()
    try:
        with _conn() as c:
            c.executemany(
                "INSERT INTO ad_block_stats(ad_host,site,action,hits,bytes,last_seen) "
                "VALUES(?,?,?,?,?,?) ON CONFLICT(ad_host,site,action) DO UPDATE SET "
                "hits=hits+excluded.hits, bytes=bytes+excluded.bytes, last_seen=excluded.last_seen",
                [(h, s or "", a, int(n), int(b), now) for (h, s, a, n, b) in rows])
    except Exception as e:
        log.debug("record_ad_blocks failed: %s", e)


def record_ad_client_blocks(rows) -> None:
    """rows: iterable of (mac_hash, ad_host, hits, bytes). Per-visitor ad-block
    breakdown (#659). Batch upsert. Skips rows with empty mac_hash."""
    rows = [r for r in rows if r and r[0]]
    if not rows:
        return
    now = time.time()
    try:
        with _conn() as c:
            c.executemany(
                "INSERT INTO ad_block_client_host(mac_hash,ad_host,hits,bytes,last_seen) "
                "VALUES(?,?,?,?,?) ON CONFLICT(mac_hash,ad_host) DO UPDATE SET "
                "hits=hits+excluded.hits, bytes=bytes+excluded.bytes, last_seen=excluded.last_seen",
                [(mh, h or "", int(n), int(b), now) for (mh, h, n, b) in rows])
    except Exception as e:
        log.debug("record_ad_client_blocks failed: %s", e)


def ad_client_stats(mac_hash: str, hours: int = 24, top: int = 25) -> dict:
    """One visitor's top ad hosts blocked, within the time window (#659)."""
    cutoff = time.time() - hours * 3600
    out = {"mac_hash": mac_hash, "total": 0, "top_hosts": []}
    try:
        with _conn() as c:
            r = c.execute(
                "SELECT SUM(hits) FROM ad_block_client_host WHERE mac_hash=? AND last_seen>=?",
                (mac_hash, cutoff)).fetchone()
            out["total"] = int((r and r[0]) or 0)
            out["top_hosts"] = [{"host": h, "hits": int(n), "bytes": int(b or 0)} for h, n, b in c.execute(
                "SELECT ad_host, SUM(hits), SUM(bytes) FROM ad_block_client_host "
                "WHERE mac_hash=? AND last_seen>=? GROUP BY ad_host ORDER BY SUM(hits) DESC LIMIT ?",
                (mac_hash, cutoff, top))]
    except Exception as e:
        log.debug("ad_client_stats failed: %s", e)
    return out


def record_cosmetic_pages(pages: int) -> None:
    """#755 — append one cosmetic-hide tally (pages cleaned since the last flush).
    ad_stats sums these over the window. Best-effort; never raises."""
    try:
        n = int(pages)
        if n <= 0:
            return
        with _conn() as c:
            c.execute("CREATE TABLE IF NOT EXISTS cosmetic_events(ts REAL, pages INTEGER)")
            c.execute("INSERT INTO cosmetic_events(ts, pages) VALUES(?, ?)", (time.time(), n))
    except Exception as e:
        log.debug("record_cosmetic_pages failed: %s", e)


def record_ad_candidates(rows) -> None:
    """rows: iterable of (host, site, hits)."""
    rows = [r for r in rows if r and r[0]]
    if not rows:
        return
    now = time.time()
    try:
        with _conn() as c:
            c.executemany(
                "INSERT INTO ad_candidates(host,site,hits,last_seen) VALUES(?,?,?,?) "
                "ON CONFLICT(host,site) DO UPDATE SET hits=hits+excluded.hits, last_seen=excluded.last_seen",
                [(h, s or "", int(n), now) for (h, s, n) in rows])
    except Exception as e:
        log.debug("record_ad_candidates failed: %s", e)


def ad_candidate_sites(min_sites: int = 1, max_hosts: int = 5000) -> list:
    """Hosts seen as ad-candidates on >= min_sites DISTINCT sites."""
    try:
        with _conn() as c:
            return [r[0] for r in c.execute(
                "SELECT host FROM ad_candidates GROUP BY host "
                "HAVING COUNT(DISTINCT site) >= ? ORDER BY SUM(hits) DESC LIMIT ?",
                (min_sites, max_hosts))]
    except Exception:
        return []


def ad_stats(hours: int = 24, top: int = 25) -> dict:
    cutoff = time.time() - hours * 3600
    out = {"window_hours": hours, "total_blocked": 0, "total_bytes": 0,
           "by_action": {"block": 0, "silent": 0}, "top_hosts": [], "top_sites": [],
           "top_visitors": []}
    try:
        with _conn() as c:
            for action, hits in c.execute(
                "SELECT action, SUM(hits) FROM ad_block_stats WHERE last_seen>=? GROUP BY action",
                (cutoff,)):
                out["by_action"][action] = int(hits or 0)
            out["total_blocked"] = out["by_action"].get("block", 0)
            r = c.execute("SELECT SUM(bytes) FROM ad_block_stats WHERE action='block' AND last_seen>=?",
                          (cutoff,)).fetchone()
            out["total_bytes"] = int((r and r[0]) or 0)
            out["top_hosts"] = [{"host": h, "hits": int(n), "bytes": int(b or 0)} for h, n, b in c.execute(
                "SELECT ad_host, SUM(hits), SUM(bytes) FROM ad_block_stats WHERE action='block' AND last_seen>=? "
                "GROUP BY ad_host ORDER BY SUM(hits) DESC LIMIT ?", (cutoff, top))]
            out["top_sites"] = [{"site": s, "hits": int(n)} for s, n in c.execute(
                "SELECT site, SUM(hits) FROM ad_block_stats WHERE action='block' AND last_seen>=? AND site<>'' "
                "GROUP BY site ORDER BY SUM(hits) DESC LIMIT ?", (cutoff, top))]
            out["top_visitors"] = [{"mac_hash": mh, "hits": int(n)} for mh, n in c.execute(
                "SELECT mac_hash, SUM(hits) FROM ad_block_client_host "
                "WHERE last_seen>=? AND mac_hash<>'' GROUP BY mac_hash "
                "ORDER BY SUM(hits) DESC LIMIT ?", (cutoff, top))]
            # #755 — trackers detected/poisoned by the MITM in the window: distinct
            # cross-site cookie-identifier hashes seen on social_edges. This is the
            # "Trackers" half of the card (the 204 ad-block is the "pubs" half).
            out["trackers_seen"] = 0
            try:
                out["trackers_seen"] = int(c.execute(
                    "SELECT COUNT(DISTINCT cookie_id_hash) FROM social_edges "
                    "WHERE ts >= ? AND cookie_id_hash IS NOT NULL AND cookie_id_hash <> ''",
                    (int(cutoff),),
                ).fetchone()[0] or 0)
            except sqlite3.Error:
                out["trackers_seen"] = 0
            # #755 — pages where the cosmetic ad-hide style was injected (Task 2 writes
            # cosmetic_events; absent table → 0).
            out["pages_cleaned"] = 0
            try:
                out["pages_cleaned"] = int(c.execute(
                    "SELECT COALESCE(SUM(pages),0) FROM cosmetic_events WHERE ts >= ?",
                    (cutoff,),
                ).fetchone()[0] or 0)
            except sqlite3.Error:
                out["pages_cleaned"] = 0
    except Exception as e:
        log.debug("ad_stats failed: %s", e)
    return out


_SPLICE_OBS_CAP = 50   # stop counting once we have enough signal per host


def record_splice_obs(host: str, is_html: bool) -> None:
    """Observe a MITM'd flow's host + whether it served text/html. Sampling-capped
    so writes stay bounded. Best-effort (never raises into the proxy path)."""
    h = (host or "").lower().strip(".")
    if not h:
        return
    try:
        with _conn() as c:
            c.execute(
                "INSERT INTO splice_host_obs(host, hits, html_hits, last_seen) "
                "VALUES(?, 1, ?, ?) "
                "ON CONFLICT(host) DO UPDATE SET "
                "  hits = MIN(hits + 1, ?), "
                "  html_hits = html_hits + ?, "
                "  last_seen = ? "
                "WHERE splice_host_obs.hits < ?",
                (h, 1 if is_html else 0, time.time(),
                 _SPLICE_OBS_CAP, 1 if is_html else 0, time.time(), _SPLICE_OBS_CAP),
            )
    except Exception as e:
        log.debug("splice obs failed: %s", e)


def never_html_hosts(min_hits: int = 20) -> list[str]:
    """Hosts observed >= min_hits times that NEVER served text/html."""
    try:
        with _conn() as c:
            rows = c.execute(
                "SELECT host FROM splice_host_obs WHERE hits >= ? AND html_hits = 0",
                (min_hits,),
            ).fetchall()
        return [r[0] for r in rows]
    except Exception:
        return []


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


def set_client_level(mac_hash: str, level: str) -> None:
    """#724 — set a client's level by hash only (no ip needed), for the banner
    self-service switch on R3 wg peers (which have no captive MAC/ip). Updates the
    existing row; inserts a minimal row if the client is unknown."""
    now = int(time.time())
    with _conn() as c:
        try:
            c.execute("ALTER TABLE clients ADD COLUMN level TEXT NOT NULL DEFAULT 'r1'")
        except sqlite3.OperationalError:
            pass
        cur = c.execute("UPDATE clients SET level=?, last_seen=? WHERE mac_hash=?",
                        (level, now, mac_hash))
        if cur.rowcount == 0:
            c.execute(
                "INSERT INTO clients(mac_hash, ip, level, first_seen, last_seen) "
                "VALUES (?,?,?,?,?) ON CONFLICT(mac_hash) DO UPDATE SET "
                "level=excluded.level, last_seen=excluded.last_seen",
                (mac_hash, "?", level, now, now),
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
            "SELECT mac_hash, ip, state, score, level, first_seen, last_seen FROM clients "
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


def latest_user_agent(mac_hash: str) -> str | None:
    """Most recent recorded User-Agent for a client (from consents), or None."""
    try:
        with _conn() as c:
            row = c.execute(
                "SELECT user_agent FROM consents "
                "WHERE mac_hash=? AND user_agent IS NOT NULL AND user_agent<>'' "
                "ORDER BY ts DESC LIMIT 1",
                (mac_hash,),
            ).fetchone()
        return row["user_agent"] if row else None
    except sqlite3.Error:
        return None


def reset_client(mac_hash: str) -> int:
    """Phase 12.B (#516) — RAZ a specific client's accumulated toolbox
    state : events + consents + reports.  Returns rows deleted.  The
    `clients` row itself is kept (it re-populates from live activity)
    but its score is zeroed.  Social-mapping rows are wiped separately
    via secubox_toolbox.social.wipe_mac().
    """
    if not mac_hash:
        return 0
    n = 0
    try:
        with _conn() as c:
            for table in ("events", "consents", "reports"):
                n += c.execute(
                    f"DELETE FROM {table} WHERE mac_hash = ?", (mac_hash,)
                ).rowcount or 0
            c.execute(
                "UPDATE clients SET score = 0, state = 'validated' "
                "WHERE mac_hash = ?", (mac_hash,)
            )
    except Exception as e:
        log.warning("reset_client failed: %s", e)
    if n:
        log.info("reset_client %s: %d rows", mac_hash[:8], n)
    return n
