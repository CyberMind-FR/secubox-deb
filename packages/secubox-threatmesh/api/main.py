# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: secubox-threatmesh (#728)
CyberMind — https://cybermind.fr

Sovereign threat-intel control plane that replaces CrowdSec CAPI:

  Phase 1  free public feeds (secubox-threatfeed timer) -> threat_intel
  Phase 2  MESH distribution of LOCAL decisions over the SecuBox P2P mesh
           (gossip to peers from secubox-p2p; ingest peer decisions) -> threat_intel
  Phase 3  status / aggregate / CrowdSec-bouncer-compatible decisions API + UI

All IOCs land in the shared `threat_intel` table (toolbox.db); secubox-blacklist-sync
drains it to the nft blacklist. No central account, no CAPI, no paywall.
"""
import asyncio
import json
import re
import sqlite3
import subprocess
import time
import urllib.request
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from secubox_core.auth import require_jwt
from secubox_core.logger import get_logger

log = get_logger("threatmesh")

TI_DB = Path("/var/lib/secubox/toolbox/toolbox.db")
P2P_PEERS = Path("/var/lib/secubox/p2p/peers.json")
P2P_NODE = Path("/var/lib/secubox/p2p/node_id")
MESH_INTERVAL = 600          # gossip every 10 min
LOCAL_ORIGINS = {"crowdsec", "cscli", "manual", "secubox-waf", "secubox"}
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


def local_decisions():
    """Our OWN locally-detected bad IPs (CrowdSec LAPI bans of local origin)."""
    try:
        out = subprocess.run(["cscli", "decisions", "list", "-o", "json", "-a"],
                             capture_output=True, text=True, timeout=20)
        data = json.loads(out.stdout or "[]") or []
    except Exception as e:
        log.debug(f"cscli decisions: {e}")
        return []
    ips = []
    for alert in data:
        for dec in (alert.get("decisions") or []):
            if dec.get("type") == "ban" and dec.get("scope", "").lower() == "ip":
                origin = (dec.get("origin") or "").lower()
                val = dec.get("value", "")
                if IPV4.match(val) and not origin.startswith(("feed:", "mesh:", "lists:")):
                    ips.append(val)
    return sorted(set(ips))


async def _post_json(url, payload, timeout=15):
    def _do():
        req = urllib.request.Request(
            url, data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json", "User-Agent": "SecuBox-ThreatMesh/1.0"},
            method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status
    return await asyncio.to_thread(_do)


async def mesh_gossip_once():
    peers = mesh_peers()
    decisions = local_decisions()
    if not peers or not decisions:
        return {"peers": len(peers), "shared": len(decisions), "pushed": 0}
    payload = {"node": node_id(), "ts": int(time.time()), "ips": decisions}
    pushed = 0
    for p in peers:
        url = f"http://{p['address']}:8780/api/v1/threatmesh/mesh/ingest"
        try:
            await _post_json(url, payload)
            pushed += 1
        except Exception as e:
            log.debug(f"gossip to {p['id']} failed: {e}")
    return {"peers": len(peers), "shared": len(decisions), "pushed": pushed}


async def _mesh_loop():
    while True:
        try:
            r = await mesh_gossip_once()
            log.info(f"mesh gossip: {r}")
        except Exception as e:
            log.error(f"mesh loop: {e}")
        await asyncio.sleep(MESH_INTERVAL)


@app.on_event("startup")
async def _startup():
    asyncio.create_task(_mesh_loop())


# ── endpoints ───────────────────────────────────────────────────────
@app.get("/health")
async def health():
    return {"status": "ok", "module": "deb"}


@router.get("/status")
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


@router.get("/peers")
async def peers():
    return {"node": node_id(), "peers": mesh_peers()}


@router.get("/decisions")
async def decisions(min_consensus: int = 1, limit: int = 50000):
    """Aggregated sovereign blocklist (feeds + mesh + local). CrowdSec-bouncer
    friendly shape so external consumers can poll OUR server, not crowdsec.net."""
    rows = [r for r in aggregate_ips(limit) if r["consensus"] >= min_consensus]
    return [{
        "id": i, "origin": "secubox-threatmesh", "type": "ban", "scope": "Ip",
        "value": r["ioc"], "duration": "24h",
        "consensus": r["consensus"], "sources": r["sources"],
    } for i, r in enumerate(rows)]


@router.post("/mesh/ingest")
async def mesh_ingest(request: Request):
    """Receive a peer's locally-detected decisions over the mesh -> threat_intel
    tagged mesh:<node>. Trust boundary = the WireGuard mesh transport."""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"ok": False, "error": "bad json"}, status_code=400)
    node = str(body.get("node", "")).strip()[:64] or "unknown"
    if not re.match(r"^[A-Za-z0-9._:-]+$", node):
        return JSONResponse({"ok": False, "error": "bad node"}, status_code=400)
    ips = [ip for ip in (body.get("ips") or []) if isinstance(ip, str) and IPV4.match(ip)]
    n = upsert_iocs(((ip, "ip") for ip in ips[:20000]), f"mesh:{node}", weight=70, label="mesh")
    log.info(f"mesh ingest from {node}: {n} ips")
    return {"ok": True, "ingested": n}


@router.post("/feeds/refresh", dependencies=[Depends(require_jwt)])
def feeds_refresh():
    """Trigger the feed fetcher now (normally on a timer)."""
    try:
        subprocess.Popen(["/usr/sbin/secubox-threatfeed"])
        return {"ok": True, "started": True}
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


@router.post("/mesh/gossip", dependencies=[Depends(require_jwt)])
async def mesh_gossip_now():
    return await mesh_gossip_once()


app.include_router(router)
