# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: secubox-threatmesh (#728)
CyberMind — https://cybermind.fr

Sovereign threat-intel control plane (self-sourced, no third-party central API):

  Phase 1  free public feeds (secubox-threatfeed timer) -> threat_intel
  Phase 2  MESH distribution of LOCAL decisions over the SecuBox P2P mesh
           (gossip to peers from secubox-p2p; ingest peer decisions) -> threat_intel
  Phase 3  status / aggregate / bouncer-compatible decisions API + UI

All IOCs land in the shared `threat_intel` table (toolbox.db); secubox-blacklist-sync
drains it to the nft blacklist. No central account, no CAPI, no paywall.
"""
import json
import re
import sqlite3
import subprocess
import time
from pathlib import Path

from fastapi import FastAPI, APIRouter, Depends
from fastapi.responses import JSONResponse

from secubox_core.auth import require_jwt
from secubox_core.logger import get_logger
from secubox_core.auth import require_lecture

log = get_logger("threatmesh")

TI_DB = Path("/var/lib/secubox/toolbox/toolbox.db")
P2P_PEERS = Path("/var/lib/secubox/p2p/peers.json")
P2P_NODE = Path("/var/lib/secubox/p2p/node_id")
LOCAL_ORIGINS = {"manual", "secubox-waf", "secubox"}
IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$")

app = FastAPI(title="secubox-threatmesh", version="1.0.0", root_path="/api/v1/threatmesh")
router = APIRouter()
_node_id = None


# ── store ───────────────────────────────────────────────────────────
def _conn():
    c = sqlite3.connect(TI_DB, timeout=20)
    c.row_factory = sqlite3.Row
    return c


def _ensure(c):
    c.execute("""CREATE TABLE IF NOT EXISTS threat_intel (
        ioc TEXT NOT NULL, ioc_type TEXT NOT NULL, source TEXT NOT NULL,
        weight INTEGER NOT NULL DEFAULT 50, label TEXT,
        first_seen INTEGER, last_seen INTEGER,
        PRIMARY KEY (ioc, ioc_type, source))""")


def node_id() -> str:
    global _node_id
    if _node_id:
        return _node_id
    try:
        _node_id = P2P_NODE.read_text().strip()
    except Exception:
        try:
            _node_id = json.loads(P2P_PEERS.read_text())["peers"][0]["id"]
        except Exception:
            _node_id = "sb-local"
    return _node_id


def upsert_iocs(rows, source, weight=60, label=None):
    """rows: iterable of (ioc, ioc_type). Returns count."""
    now = int(time.time())
    n = 0
    with _conn() as c:
        _ensure(c)
        for ioc, t in rows:
            c.execute(
                "INSERT INTO threat_intel(ioc,ioc_type,source,weight,label,first_seen,last_seen) "
                "VALUES(?,?,?,?,?,?,?) ON CONFLICT(ioc,ioc_type,source) DO UPDATE SET last_seen=excluded.last_seen",
                (ioc, t, source, weight, label, now, now))
            n += 1
        c.commit()
    return n


def counts_by_source():
    with _conn() as c:
        _ensure(c)
        return {r["source"]: r["n"] for r in c.execute(
            "SELECT source, COUNT(*) n FROM threat_intel GROUP BY source ORDER BY n DESC")}


def aggregate_ips(limit=50000):
    """Distinct bad IPs across ALL sources, with a consensus count."""
    with _conn() as c:
        _ensure(c)
        return [dict(r) for r in c.execute(
            "SELECT ioc, COUNT(DISTINCT source) consensus, MAX(weight) weight, "
            "GROUP_CONCAT(DISTINCT source) sources FROM threat_intel "
            "WHERE ioc_type='ip' GROUP BY ioc ORDER BY consensus DESC LIMIT ?", (limit,))]


# ── mesh (Phase 2) ──────────────────────────────────────────────────
def mesh_peers():
    """Other SecuBox nodes from secubox-p2p (skip self)."""
    me = node_id()
    out = []
    try:
        d = json.loads(P2P_PEERS.read_text())
        for p in d.get("peers", []):
            if p.get("id") == me:
                continue
            addr = None
            for a in p.get("addresses", []):
                if a.get("type") in ("wg", "wireguard", "mesh"):
                    addr = a.get("address"); break
            addr = addr or (p.get("wg_addresses") or [None])[0] or p.get("address")
            if addr:
                out.append({"id": p.get("id"), "name": p.get("name"), "address": addr})
    except Exception as e:
        log.debug(f"peers read: {e}")
    return out


# ── endpoints ───────────────────────────────────────────────────────
@app.get("/health")
async def health():
    return {"status": "ok", "module": "deb"}


@router.get("/status", dependencies=[Depends(require_lecture)])
async def status():
    src = counts_by_source()
    feeds = {k: v for k, v in src.items() if k.startswith("feed:")}
    mesh = {k: v for k, v in src.items() if k.startswith("mesh:")}
    return {
        "mode": "sovereign",  # CAPI dropped (#728)
        "node": node_id(),
        "capi": False,
        "feeds": feeds, "feed_total": sum(feeds.values()),
        "mesh": mesh, "mesh_total": sum(mesh.values()),
        "peers": len(mesh_peers()),
        "sources": src,
    }


@router.get("/peers", dependencies=[Depends(require_lecture)])
async def peers():
    return {"node": node_id(), "peers": mesh_peers()}


@router.get("/decisions", dependencies=[Depends(require_lecture)])
async def decisions(min_consensus: int = 1, limit: int = 50000):
    """Aggregated sovereign blocklist (feeds + mesh + local). Bouncer-friendly
    shape so external consumers can poll OUR server, not a third-party service."""
    rows = [r for r in aggregate_ips(limit) if r["consensus"] >= min_consensus]
    return [{
        "id": i, "origin": "secubox-threatmesh", "type": "ban", "scope": "Ip",
        "value": r["ioc"], "duration": "24h",
        "consensus": r["consensus"], "sources": r["sources"],
    } for i, r in enumerate(rows)]


@router.post("/feeds/refresh", dependencies=[Depends(require_jwt)])
def feeds_refresh():
    """Trigger the feed fetcher now (normally on a timer)."""
    try:
        subprocess.Popen(["/usr/sbin/secubox-threatfeed"])
        return {"ok": True, "started": True}
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


app.include_router(router)
