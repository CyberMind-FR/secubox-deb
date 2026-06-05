# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

"""Threat intel feeds : pull + cache local + IP/SNI lookup.

Sources (CC0/public domain) :
- abuse.ch ThreatFox       : malware C2 IoCs (IPs + domains + URLs)
- abuse.ch Feodo Tracker   : botnet C2 (Emotet, Dridex, TrickBot, Heodo)
- abuse.ch SSLBL           : TLS certificate blacklist (cert fingerprints)

Refresh toutes les heures (asyncio task). Cache local SQLite, table dédiée.
Pas de re-download massif si la dernière fetch < 1h.
"""
from __future__ import annotations

import asyncio
import logging
import sqlite3
import time
from pathlib import Path

log = logging.getLogger("secubox.toolbox.threat_intel")

DB = Path("/var/lib/secubox/toolbox/toolbox.db")
SCHEMA = """
CREATE TABLE IF NOT EXISTS threat_intel (
    ioc TEXT NOT NULL,
    ioc_type TEXT NOT NULL,  -- 'ip', 'domain', 'sha256', 'sni'
    source TEXT NOT NULL,    -- 'threatfox', 'feodo', 'sslbl'
    weight INTEGER NOT NULL DEFAULT 50,
    label TEXT,              -- malware family / threat name
    first_seen INTEGER,
    last_seen INTEGER,
    PRIMARY KEY (ioc, ioc_type, source)
);
CREATE INDEX IF NOT EXISTS idx_ti_ioc ON threat_intel(ioc);
CREATE TABLE IF NOT EXISTS threat_intel_fetch (
    source TEXT PRIMARY KEY,
    last_fetch INTEGER NOT NULL,
    rows INTEGER NOT NULL DEFAULT 0,
    error TEXT
);
"""

# Feed sources — small representative subsets to limit bandwidth/storage on
# embedded boards. ThreatFox export-json-recent is ~6 MB compressed,
# Feodo blocklist is ~10 KB.
FEED_FEODO = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json"
FEED_THREATFOX = "https://threatfox.abuse.ch/export/json/recent/"
FEED_SSLBL = "https://sslbl.abuse.ch/blacklist/sslblacklist.csv"

REFRESH_INTERVAL = 3600  # 1h


def _conn() -> sqlite3.Connection:
    c = sqlite3.connect(DB, timeout=5)
    c.row_factory = sqlite3.Row
    c.executescript(SCHEMA)
    return c


def _was_fetched_recently(source: str) -> bool:
    try:
        with _conn() as c:
            row = c.execute(
                "SELECT last_fetch FROM threat_intel_fetch WHERE source=?",
                (source,),
            ).fetchone()
        if not row:
            return False
        return int(time.time()) - row["last_fetch"] < REFRESH_INTERVAL
    except Exception:
        return False


def _record_fetch(source: str, rows: int, error: str | None = None) -> None:
    with _conn() as c:
        c.execute(
            "INSERT OR REPLACE INTO threat_intel_fetch(source, last_fetch, rows, error) "
            "VALUES (?, ?, ?, ?)",
            (source, int(time.time()), rows, error),
        )


async def _http_get_json(url: str) -> dict | list | None:
    try:
        import httpx
    except ImportError:
        log.warning("httpx not available — threat_intel disabled")
        return None
    try:
        async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
            r = await client.get(url, headers={"User-Agent": "secubox-toolbox/2.0"})
            r.raise_for_status()
            return r.json()
    except Exception as e:
        log.warning("fetch %s failed: %s", url, e)
        return None


async def _http_get_text(url: str) -> str | None:
    try:
        import httpx
    except ImportError:
        return None
    try:
        async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
            r = await client.get(url, headers={"User-Agent": "secubox-toolbox/2.0"})
            r.raise_for_status()
            return r.text
    except Exception as e:
        log.warning("fetch %s failed: %s", url, e)
        return None


# ──────────── Feed ingest ────────────

async def ingest_feodo() -> int:
    if _was_fetched_recently("feodo"):
        return 0
    data = await _http_get_json(FEED_FEODO)
    if data is None or not isinstance(data, list):
        _record_fetch("feodo", 0, "fetch failed")
        return 0
    now = int(time.time())
    rows = []
    for entry in data:
        ip = entry.get("ip_address")
        if not ip:
            continue
        rows.append((ip, "ip", "feodo", 55, entry.get("malware") or "C2", now, now))
    if rows:
        with _conn() as c:
            c.executemany(
                "INSERT OR REPLACE INTO threat_intel"
                "(ioc, ioc_type, source, weight, label, first_seen, last_seen)"
                " VALUES (?,?,?,?,?,?,?)",
                rows,
            )
    _record_fetch("feodo", len(rows))
    log.info("feodo: %d IPs ingested", len(rows))
    return len(rows)


async def ingest_threatfox(limit: int = 5000) -> int:
    """Limit to N most recent IoCs to control storage."""
    if _was_fetched_recently("threatfox"):
        return 0
    data = await _http_get_json(FEED_THREATFOX)
    if data is None or not isinstance(data, dict):
        _record_fetch("threatfox", 0, "fetch failed")
        return 0
    now = int(time.time())
    rows = []
    # ThreatFox returns { "<id>": [ {ioc, ioc_type, malware, ...}, ... ], ... }
    for entries in data.values():
        if not isinstance(entries, list):
            continue
        for e in entries:
            ioc = e.get("ioc", "")
            ioc_type = e.get("ioc_type", "")
            malware = e.get("malware_printable") or e.get("malware") or "?"
            if not ioc:
                continue
            # Normalize types
            if ioc_type == "ip:port":
                ip = ioc.split(":", 1)[0]
                rows.append((ip, "ip", "threatfox", 50, malware, now, now))
            elif ioc_type == "domain":
                rows.append((ioc, "domain", "threatfox", 45, malware, now, now))
            elif ioc_type == "url":
                # Skip URLs (too volatile)
                continue
            elif ioc_type == "sha256_hash":
                rows.append((ioc, "sha256", "threatfox", 40, malware, now, now))
            if len(rows) >= limit:
                break
        if len(rows) >= limit:
            break
    if rows:
        with _conn() as c:
            c.executemany(
                "INSERT OR REPLACE INTO threat_intel"
                "(ioc, ioc_type, source, weight, label, first_seen, last_seen)"
                " VALUES (?,?,?,?,?,?,?)",
                rows,
            )
    _record_fetch("threatfox", len(rows))
    log.info("threatfox: %d IoCs ingested (capped at %d)", len(rows), limit)
    return len(rows)


async def ingest_sslbl() -> int:
    if _was_fetched_recently("sslbl"):
        return 0
    text = await _http_get_text(FEED_SSLBL)
    if not text:
        _record_fetch("sslbl", 0, "fetch failed")
        return 0
    now = int(time.time())
    rows = []
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split(",")
        if len(parts) < 3:
            continue
        # Format: "Listingdate,SHA1,Listingreason"
        sha1 = parts[1].strip().lower()
        reason = parts[2].strip()
        if len(sha1) == 40:
            rows.append((sha1, "sha1_cert", "sslbl", 50, reason, now, now))
    if rows:
        with _conn() as c:
            c.executemany(
                "INSERT OR REPLACE INTO threat_intel"
                "(ioc, ioc_type, source, weight, label, first_seen, last_seen)"
                " VALUES (?,?,?,?,?,?,?)",
                rows,
            )
    _record_fetch("sslbl", len(rows))
    log.info("sslbl: %d cert fingerprints ingested", len(rows))
    return len(rows)


async def refresh_all() -> dict[str, int]:
    """Refresh all feeds. Returns counts per source."""
    res: dict[str, int] = {}
    for fn, name in [(ingest_feodo, "feodo"),
                     (ingest_threatfox, "threatfox"),
                     (ingest_sslbl, "sslbl")]:
        try:
            res[name] = await fn()
        except Exception as e:
            log.error("refresh %s failed: %s", name, e)
            res[name] = 0
    return res


async def refresh_loop() -> None:
    """Run forever, refreshing every REFRESH_INTERVAL seconds."""
    while True:
        try:
            counts = await refresh_all()
            log.info("threat_intel refresh: %s", counts)
        except Exception as e:
            log.error("threat_intel refresh_loop error: %s", e)
        await asyncio.sleep(REFRESH_INTERVAL)


# ──────────── Lookups ────────────

def is_malicious_ip(ip: str) -> list[dict]:
    """Returns list of matches : [{source, weight, label}, ...]"""
    try:
        with _conn() as c:
            rows = c.execute(
                "SELECT source, weight, label FROM threat_intel "
                "WHERE ioc=? AND ioc_type='ip'",
                (ip,),
            ).fetchall()
    except Exception:
        return []
    return [dict(r) for r in rows]


def is_malicious_domain(domain: str) -> list[dict]:
    """Match exact domain or parent domain (eg. evil.example.com matches example.com)."""
    parts = domain.lower().split(".")
    candidates = [".".join(parts[i:]) for i in range(len(parts) - 1)]
    if not candidates:
        return []
    try:
        with _conn() as c:
            placeholders = ",".join("?" * len(candidates))
            rows = c.execute(
                f"SELECT ioc, source, weight, label FROM threat_intel "
                f"WHERE ioc_type='domain' AND ioc IN ({placeholders})",
                candidates,
            ).fetchall()
    except Exception:
        return []
    return [dict(r) for r in rows]


def feed_stats() -> dict:
    """Return last-fetch + row-count per source for /admin/metrics."""
    try:
        with _conn() as c:
            rows = c.execute(
                "SELECT source, last_fetch, rows, error FROM threat_intel_fetch"
            ).fetchall()
            total = c.execute(
                "SELECT COUNT(*) FROM threat_intel"
            ).fetchone()[0]
        return {
            "total_iocs": total,
            "sources": {r["source"]: {
                "last_fetch": r["last_fetch"],
                "rows": r["rows"],
                "error": r["error"],
                "age_seconds": int(time.time()) - r["last_fetch"],
            } for r in rows},
        }
    except Exception as e:
        return {"error": str(e)}
