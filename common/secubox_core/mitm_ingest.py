# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

"""Shared mitm-ingest helper for SecuBox modules receiving events from
secubox-toolbox mitmproxy addons (cookies/dpi/avatar/soc/threat-analyst).

Each module mounts its ingest route once at app startup :

    from secubox_core.mitm_ingest import mount_ingest_routes
    mount_ingest_routes(
        app,
        endpoint_path="/classify",          # what the mitm addon POSTs to
        db_path="/var/lib/secubox-dpi/mitm-ingest.db",
        kind="dpi",
    )

This registers:
  - POST {endpoint_path}    : ingest a single mitm event (validates + stores)
  - GET  /mitm-events       : returns recent events for secubox-toolbox aggregator
  - GET  /mitm-events/stats : aggregate counters per mac_hash (last 24h)

Events are stored in an isolated SQLite db so the module's main schema is
untouched. The toolbox aggregator queries GET /mitm-events?mac_hash=... to
enrich its session report with cross-module classification.
"""
from __future__ import annotations

import json
import logging
import sqlite3
import time
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, Query
from pydantic import BaseModel, Field

log = logging.getLogger("secubox.mitm_ingest")


class MitmEvent(BaseModel):
    """Flexible payload : accepts any mitm addon shape.

    All addon payloads (dpi/cookies/avatar/soc/ja4) carry these common
    fields. Module-specific extra fields are passed through verbatim and
    persisted as JSON.
    """
    ts_ms: int = Field(..., description="mitm event timestamp ms epoch")
    client_ip: Optional[str] = None
    client_mac: Optional[str] = None      # raw MAC (legacy / backward-compat)
    client_mac_hash: Optional[str] = None  # 16-char HMAC-SHA256 (preferred)

    class Config:
        extra = "allow"  # accept any extra module-specific fields


def _init_db(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path, timeout=5) as c:
        c.execute("""
            CREATE TABLE IF NOT EXISTS mitm_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts_ms INTEGER NOT NULL,
                kind TEXT NOT NULL,
                client_mac_hash TEXT,
                client_ip TEXT,
                payload TEXT NOT NULL
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS ix_mitm_events_mac ON mitm_events(client_mac_hash, ts_ms DESC)")
        c.execute("CREATE INDEX IF NOT EXISTS ix_mitm_events_ts ON mitm_events(ts_ms)")


def _purge_old(db_path: Path, retention_seconds: int = 86400 * 2) -> None:
    """Drop events older than retention window (default 48h)."""
    cutoff = int(time.time() * 1000) - retention_seconds * 1000
    try:
        with sqlite3.connect(db_path, timeout=2) as c:
            c.execute("DELETE FROM mitm_events WHERE ts_ms < ?", (cutoff,))
    except Exception as e:
        log.debug("mitm_ingest purge failed: %s", e)


def mount_ingest_routes(
    app: FastAPI,
    *,
    endpoint_path: str,
    db_path: str | Path,
    kind: str,
    retention_hours: int = 48,
    enrich_hook: "callable | None" = None,
) -> None:
    """Mount /POST {endpoint_path} and GET /mitm-events on the given FastAPI app.

    enrich_hook : optional callable(event_dict) -> enriched_event_dict.
    Called BEFORE persistence. Module-specific enrichment (e.g. nDPI lookup
    for secubox-dpi, JA4 hash calc for secubox-threat-analyst) can be added
    via this hook. Must be quick (synchronous, < 50ms) — anything slower
    must go through a background task. Errors are logged but never block
    ingestion (raw event is still persisted).
    """
    db_path = Path(db_path)
    _init_db(db_path)

    @app.post(endpoint_path)
    async def ingest(event: MitmEvent) -> dict:
        ev_dict = (event.model_dump() if hasattr(event, "model_dump") else event.dict())
        if enrich_hook is not None:
            try:
                enriched = enrich_hook(ev_dict)
                if isinstance(enriched, dict):
                    ev_dict = enriched
            except Exception as e:
                log.warning("mitm enrich_hook failed (%s): %s", kind, e)
        try:
            with sqlite3.connect(db_path, timeout=2) as c:
                c.execute(
                    "INSERT INTO mitm_events(ts_ms, kind, client_mac_hash, client_ip, payload) "
                    "VALUES (?,?,?,?,?)",
                    (
                        event.ts_ms,
                        kind,
                        event.client_mac_hash,
                        event.client_ip,
                        json.dumps(ev_dict)[:16000],
                    ),
                )
        except Exception as e:
            log.warning("mitm ingest insert failed (%s): %s", kind, e)
            return {"ok": False, "error": "store_failed"}
        # Lightweight opportunistic purge (1% of inserts)
        if event.ts_ms % 100 == 0:
            _purge_old(db_path, retention_hours * 3600)
        return {"ok": True, "kind": kind}

    @app.get("/mitm-events")
    async def list_events(
        mac_hash: Optional[str] = Query(None, description="filter by client mac hash"),
        limit: int = Query(200, ge=1, le=2000),
        since_ms: Optional[int] = Query(None, description="only events newer than this ts_ms"),
    ) -> dict:
        try:
            with sqlite3.connect(db_path, timeout=2) as c:
                where = []
                args: list[Any] = []
                if mac_hash:
                    where.append("client_mac_hash = ?")
                    args.append(mac_hash)
                if since_ms:
                    where.append("ts_ms > ?")
                    args.append(since_ms)
                clause = " WHERE " + " AND ".join(where) if where else ""
                cur = c.execute(
                    f"SELECT ts_ms, client_mac_hash, client_ip, payload FROM mitm_events"
                    f"{clause} ORDER BY ts_ms DESC LIMIT ?",
                    args + [limit],
                )
                events = []
                for ts_ms, mh, ip, payload in cur.fetchall():
                    try:
                        p = json.loads(payload)
                    except Exception:
                        p = {}
                    events.append({"ts_ms": ts_ms, "mac_hash": mh, "ip": ip, "payload": p})
                return {"kind": kind, "count": len(events), "events": events}
        except Exception as e:
            log.warning("mitm list_events failed (%s): %s", kind, e)
            return {"kind": kind, "count": 0, "events": [], "error": str(e)[:80]}

    @app.get("/mitm-events/stats")
    async def stats(
        mac_hash: Optional[str] = Query(None),
        last_seconds: int = Query(86400, ge=60, le=604800),
    ) -> dict:
        cutoff = int(time.time() * 1000) - last_seconds * 1000
        try:
            with sqlite3.connect(db_path, timeout=2) as c:
                if mac_hash:
                    cur = c.execute(
                        "SELECT COUNT(*) FROM mitm_events WHERE ts_ms > ? AND client_mac_hash = ?",
                        (cutoff, mac_hash),
                    )
                else:
                    cur = c.execute("SELECT COUNT(*) FROM mitm_events WHERE ts_ms > ?", (cutoff,))
                count = cur.fetchone()[0]
                return {"kind": kind, "count": count, "since_seconds": last_seconds}
        except Exception as e:
            return {"kind": kind, "count": 0, "error": str(e)[:80]}

    log.info("mitm-ingest mounted : POST %s + GET /mitm-events (kind=%s, db=%s)",
             endpoint_path, kind, db_path)
