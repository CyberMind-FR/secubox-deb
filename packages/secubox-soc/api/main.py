"""SecuBox SOC API - Security Operations Center"""
import asyncio
import subprocess
import json
import os
import hashlib
import time
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, List
from fastapi import FastAPI, Depends, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel
from secubox_core.auth import require_jwt
from secubox_core.config import get_config

app = FastAPI(title="SecuBox SOC")
config = get_config("soc")

# Data directories
DATA_DIR = Path("/var/lib/secubox/soc")
TICKETS_FILE = DATA_DIR / "tickets.json"
INTEL_FILE = DATA_DIR / "intel.json"
PEERS_FILE = DATA_DIR / "peers.json"
ALERTS_FILE = DATA_DIR / "alerts.json"

# Ensure directories exist
try:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
except PermissionError:
    pass

# WebSocket connections for real-time updates
active_connections: List[WebSocket] = []


class Ticket(BaseModel):
    title: str
    description: str
    severity: str = "medium"
    assignee: Optional[str] = None
    status: str = "open"


class ThreatIntel(BaseModel):
    indicator: str
    type: str
    threat_type: str
    source: str
    confidence: int = 50


class Peer(BaseModel):
    name: str
    endpoint: str
    public_key: Optional[str] = None


class Alert(BaseModel):
    source: str
    message: str
    severity: str = "info"
    data: Optional[dict] = None


def _load_json(path: Path) -> list:
    if path.exists():
        try:
            with open(path, 'r') as f:
                return json.load(f)
        except:
            pass
    return []


def _save_json(path: Path, data):
    try:
        with open(path, 'w') as f:
            json.dump(data, f, indent=2, default=str)
    except:
        pass


def _generate_id() -> str:
    return hashlib.sha256(f"{time.time()}".encode()).hexdigest()[:12]


@app.get("/status")
async def status():
    tickets = _load_json(TICKETS_FILE)
    alerts = _load_json(ALERTS_FILE)
    peers = _load_json(PEERS_FILE)
    open_tickets = sum(1 for t in tickets if t.get('status') in ['open', 'investigating'])
    critical_alerts = sum(1 for a in alerts if a.get('severity') == 'critical')
    return {
        "module": "soc",
        "status": "ok",
        "version": "1.0.0",
        "open_tickets": open_tickets,
        "critical_alerts": critical_alerts,
        "connected_peers": len(peers)
    }


@app.get("/health")
async def health():
    return {"status": "ok", "module": "soc"}


# ══════════════════════════════════════════════════════════════
# WORLD CLOCK
# ══════════════════════════════════════════════════════════════

TIMEZONES = [
    {"id": "UTC", "name": "UTC", "offset": 0, "city": "UTC"},
    {"id": "America/New_York", "name": "EST", "offset": -5, "city": "New York"},
    {"id": "America/Los_Angeles", "name": "PST", "offset": -8, "city": "Los Angeles"},
    {"id": "Europe/London", "name": "GMT", "offset": 0, "city": "London"},
    {"id": "Europe/Paris", "name": "CET", "offset": 1, "city": "Paris"},
    {"id": "Europe/Moscow", "name": "MSK", "offset": 3, "city": "Moscow"},
    {"id": "Asia/Dubai", "name": "GST", "offset": 4, "city": "Dubai"},
    {"id": "Asia/Singapore", "name": "SGT", "offset": 8, "city": "Singapore"},
    {"id": "Asia/Tokyo", "name": "JST", "offset": 9, "city": "Tokyo"},
    {"id": "Australia/Sydney", "name": "AEST", "offset": 10, "city": "Sydney"},
]


@app.get("/clock", dependencies=[Depends(require_jwt)])
async def get_clock():
    now = datetime.now(timezone.utc)
    clocks = []
    for tz in TIMEZONES:
        offset_hours = tz["offset"]
        local_time = now.timestamp() + (offset_hours * 3600)
        local_dt = datetime.fromtimestamp(local_time, tz=timezone.utc)
        clocks.append({
            "id": tz["id"],
            "name": tz["name"],
            "city": tz["city"],
            "time": local_dt.strftime("%H:%M:%S"),
            "date": local_dt.strftime("%Y-%m-%d"),
            "day": local_dt.strftime("%a"),
            "offset": f"UTC{'+' if offset_hours >= 0 else ''}{offset_hours}"
        })
    return {"utc": now.isoformat(), "timestamp": int(now.timestamp()), "clocks": clocks}


# ══════════════════════════════════════════════════════════════
# THREAT MAP
# ══════════════════════════════════════════════════════════════

@app.get("/map/threats", dependencies=[Depends(require_jwt)])
async def get_map_threats():
    intel = _load_json(INTEL_FILE)
    threat_regions = {}
    regions = ["US", "CA", "MX", "BR", "AR", "CO", "GB", "FR", "DE", "NL", "ES", "IT", "PL", "UA", "RU", "CN", "JP", "KR", "IN", "PK", "IR", "SA", "AU", "NZ", "ID", "SG", "ZA", "NG", "EG", "KE"]
    for item in intel[-100:]:
        region = regions[hash(item.get('indicator', '')) % len(regions)]
        if region not in threat_regions:
            threat_regions[region] = {"count": 0, "types": {}}
        threat_regions[region]["count"] += 1
        threat_type = item.get('threat_type', 'unknown')
        threat_regions[region]["types"][threat_type] = threat_regions[region]["types"].get(threat_type, 0) + 1
    return {"regions": threat_regions, "total_threats": len(intel), "last_updated": datetime.now(timezone.utc).isoformat()}


@app.get("/map/attacks", dependencies=[Depends(require_jwt)])
async def get_live_attacks():
    attacks = []
    try:
        result = subprocess.run(["cscli", "decisions", "list", "-o", "json"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0 and result.stdout:
            decisions = json.loads(result.stdout)
            for d in decisions[:20]:
                attacks.append({
                    "source_ip": d.get("value", ""),
                    "type": d.get("scenario", "unknown"),
                    "timestamp": d.get("created_at", "")
                })
    except:
        pass
    return {"attacks": attacks, "timestamp": datetime.now(timezone.utc).isoformat()}


# ══════════════════════════════════════════════════════════════
# TICKETS
# ══════════════════════════════════════════════════════════════

@app.get("/tickets", dependencies=[Depends(require_jwt)])
async def list_tickets(status: Optional[str] = None):
    tickets = _load_json(TICKETS_FILE)
    if status:
        tickets = [t for t in tickets if t.get('status') == status]
    tickets.sort(key=lambda x: x.get('created_at', ''), reverse=True)
    return {"tickets": tickets, "total": len(tickets)}


@app.post("/tickets", dependencies=[Depends(require_jwt)])
async def create_ticket(ticket: Ticket):
    tickets = _load_json(TICKETS_FILE)
    new_ticket = {
        "id": _generate_id(),
        "title": ticket.title,
        "description": ticket.description,
        "severity": ticket.severity,
        "assignee": ticket.assignee,
        "status": ticket.status,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat()
    }
    tickets.append(new_ticket)
    _save_json(TICKETS_FILE, tickets)
    await broadcast_update("ticket_created", new_ticket)
    return {"success": True, "ticket": new_ticket}


@app.put("/tickets/{ticket_id}", dependencies=[Depends(require_jwt)])
async def update_ticket(ticket_id: str, ticket: Ticket):
    tickets = _load_json(TICKETS_FILE)
    for i, t in enumerate(tickets):
        if t.get('id') == ticket_id:
            tickets[i].update({
                "title": ticket.title,
                "description": ticket.description,
                "severity": ticket.severity,
                "assignee": ticket.assignee,
                "status": ticket.status,
                "updated_at": datetime.now(timezone.utc).isoformat()
            })
            _save_json(TICKETS_FILE, tickets)
            return {"success": True, "ticket": tickets[i]}
    raise HTTPException(status_code=404, detail="Ticket not found")


@app.delete("/tickets/{ticket_id}", dependencies=[Depends(require_jwt)])
async def delete_ticket(ticket_id: str):
    tickets = _load_json(TICKETS_FILE)
    tickets = [t for t in tickets if t.get('id') != ticket_id]
    _save_json(TICKETS_FILE, tickets)
    return {"success": True}


# ══════════════════════════════════════════════════════════════
# THREAT INTEL
# ══════════════════════════════════════════════════════════════

@app.get("/intel", dependencies=[Depends(require_jwt)])
async def list_intel(type: Optional[str] = None, limit: int = 100):
    intel = _load_json(INTEL_FILE)
    if type:
        intel = [i for i in intel if i.get('type') == type]
    intel.sort(key=lambda x: x.get('added_at', ''), reverse=True)
    return {"intel": intel[:limit], "total": len(intel)}


@app.post("/intel", dependencies=[Depends(require_jwt)])
async def add_intel(item: ThreatIntel):
    intel = _load_json(INTEL_FILE)
    existing = [i for i in intel if i.get('indicator') == item.indicator]
    if existing:
        raise HTTPException(status_code=409, detail="Indicator already exists")
    new_intel = {
        "id": _generate_id(),
        "indicator": item.indicator,
        "type": item.type,
        "threat_type": item.threat_type,
        "source": item.source,
        "confidence": item.confidence,
        "added_at": datetime.now(timezone.utc).isoformat()
    }
    intel.append(new_intel)
    _save_json(INTEL_FILE, intel)
    await broadcast_update("intel_added", new_intel)
    return {"success": True, "intel": new_intel}


@app.delete("/intel/{intel_id}", dependencies=[Depends(require_jwt)])
async def delete_intel(intel_id: str):
    intel = _load_json(INTEL_FILE)
    intel = [i for i in intel if i.get('id') != intel_id]
    _save_json(INTEL_FILE, intel)
    return {"success": True}


# ══════════════════════════════════════════════════════════════
# P2P PEERS
# ══════════════════════════════════════════════════════════════

@app.get("/peers", dependencies=[Depends(require_jwt)])
async def list_peers():
    peers = _load_json(PEERS_FILE)
    return {"peers": peers, "total": len(peers)}


@app.post("/peers", dependencies=[Depends(require_jwt)])
async def add_peer(peer: Peer):
    peers = _load_json(PEERS_FILE)
    existing = [p for p in peers if p.get('endpoint') == peer.endpoint]
    if existing:
        raise HTTPException(status_code=409, detail="Peer already exists")
    new_peer = {
        "id": _generate_id(),
        "name": peer.name,
        "endpoint": peer.endpoint,
        "public_key": peer.public_key,
        "status": "pending",
        "added_at": datetime.now(timezone.utc).isoformat(),
        "last_seen": None
    }
    peers.append(new_peer)
    _save_json(PEERS_FILE, peers)
    return {"success": True, "peer": new_peer}


@app.delete("/peers/{peer_id}", dependencies=[Depends(require_jwt)])
async def delete_peer(peer_id: str):
    peers = _load_json(PEERS_FILE)
    peers = [p for p in peers if p.get('id') != peer_id]
    _save_json(PEERS_FILE, peers)
    return {"success": True}


@app.post("/peers/{peer_id}/sync", dependencies=[Depends(require_jwt)])
async def sync_peer(peer_id: str):
    peers = _load_json(PEERS_FILE)
    for i, p in enumerate(peers):
        if p.get('id') == peer_id:
            peers[i]["last_seen"] = datetime.now(timezone.utc).isoformat()
            peers[i]["status"] = "connected"
            _save_json(PEERS_FILE, peers)
            return {"success": True, "peer": peers[i]}
    raise HTTPException(status_code=404, detail="Peer not found")


# ══════════════════════════════════════════════════════════════
# ALERTS
# ══════════════════════════════════════════════════════════════

@app.get("/alerts", dependencies=[Depends(require_jwt)])
async def list_alerts(severity: Optional[str] = None, limit: int = 50):
    alerts = _load_json(ALERTS_FILE)
    if severity:
        alerts = [a for a in alerts if a.get('severity') == severity]
    alerts.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    return {"alerts": alerts[:limit], "total": len(alerts)}


@app.post("/alerts", dependencies=[Depends(require_jwt)])
async def create_alert(alert: Alert):
    alerts = _load_json(ALERTS_FILE)
    new_alert = {
        "id": _generate_id(),
        "source": alert.source,
        "message": alert.message,
        "severity": alert.severity,
        "data": alert.data,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "acknowledged": False
    }
    alerts.append(new_alert)
    if len(alerts) > 1000:
        alerts = alerts[-1000:]
    _save_json(ALERTS_FILE, alerts)
    await broadcast_update("alert", new_alert)
    return {"success": True, "alert": new_alert}


@app.post("/alerts/{alert_id}/ack", dependencies=[Depends(require_jwt)])
async def acknowledge_alert(alert_id: str):
    alerts = _load_json(ALERTS_FILE)
    for i, a in enumerate(alerts):
        if a.get('id') == alert_id:
            alerts[i]["acknowledged"] = True
            alerts[i]["ack_at"] = datetime.now(timezone.utc).isoformat()
            _save_json(ALERTS_FILE, alerts)
            return {"success": True}
    raise HTTPException(status_code=404, detail="Alert not found")


# ══════════════════════════════════════════════════════════════
# STATS
# ══════════════════════════════════════════════════════════════

@app.get("/stats", dependencies=[Depends(require_jwt)])
async def get_stats():
    tickets = _load_json(TICKETS_FILE)
    intel = _load_json(INTEL_FILE)
    alerts = _load_json(ALERTS_FILE)
    peers = _load_json(PEERS_FILE)

    open_tickets = sum(1 for t in tickets if t.get('status') == 'open')
    investigating = sum(1 for t in tickets if t.get('status') == 'investigating')
    critical_tickets = sum(1 for t in tickets if t.get('severity') == 'critical' and t.get('status') in ['open', 'investigating'])
    unacked_alerts = sum(1 for a in alerts if not a.get('acknowledged'))
    critical_alerts = sum(1 for a in alerts if a.get('severity') == 'critical' and not a.get('acknowledged'))

    intel_by_type = {}
    for i in intel:
        t = i.get('type', 'unknown')
        intel_by_type[t] = intel_by_type.get(t, 0) + 1

    return {
        "tickets": {"total": len(tickets), "open": open_tickets, "investigating": investigating, "critical": critical_tickets},
        "alerts": {"total": len(alerts), "unacknowledged": unacked_alerts, "critical": critical_alerts},
        "intel": {"total": len(intel), "by_type": intel_by_type},
        "peers": {"total": len(peers), "connected": sum(1 for p in peers if p.get('status') == 'connected')}
    }


# ══════════════════════════════════════════════════════════════
# WEBSOCKET
# ══════════════════════════════════════════════════════════════

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_connections.append(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        active_connections.remove(websocket)


async def broadcast_update(event_type: str, data: dict):
    message = json.dumps({"type": event_type, "data": data, "timestamp": datetime.now(timezone.utc).isoformat()})
    for connection in active_connections:
        try:
            await connection.send_text(message)
        except:
            pass
