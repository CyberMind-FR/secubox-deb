#!/usr/bin/env python3
"""
SecuBox P2P API — Peer-to-Peer Network Hub
Manages peers, services, profiles, mesh network, and threat intelligence
"""
from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import subprocess
import json
import os
from pathlib import Path
from datetime import datetime

import sys
sys.path.insert(0, '/usr/lib/python3/dist-packages')
try:
    from secubox_core.auth import require_jwt
except ImportError:
    async def require_jwt():
        return {"sub": "admin"}

app = FastAPI(
    title="SecuBox P2P API",
    description="P2P network hub management",
    version="1.0.0",
    docs_url="/docs",
    redoc_url=None
)

P2P_DIR = Path("/var/lib/secubox-p2p")
PEERS_FILE = P2P_DIR / "peers.json"
SERVICES_FILE = P2P_DIR / "services.json"
PROFILES_FILE = P2P_DIR / "profiles.json"
THREATS_FILE = P2P_DIR / "threats.json"
CONFIG_FILE = Path("/etc/secubox/p2p.toml")

def init_dirs():
    P2P_DIR.mkdir(parents=True, exist_ok=True)

def load_json(path: Path) -> Any:
    if path.exists():
        try:
            with open(path) as f:
                return json.load(f)
        except:
            pass
    return [] if 'peers' in str(path) or 'services' in str(path) else {}

def save_json(path: Path, data: Any):
    init_dirs()
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)

class PeerRequest(BaseModel):
    peer_id: str
    name: Optional[str] = None
    address: Optional[str] = None

class ServiceRequest(BaseModel):
    name: str
    port: int
    protocol: str = "tcp"
    description: Optional[str] = None

class ProfileRequest(BaseModel):
    name: str
    settings: Dict[str, Any] = {}

class ThreatRequest(BaseModel):
    ip: str
    reason: str
    severity: str = "medium"

# ============== Overview ==============

@app.get("/status")
async def get_status():
    """Get P2P network status."""
    init_dirs()
    peers = load_json(PEERS_FILE)
    services = load_json(SERVICES_FILE)
    threats = load_json(THREATS_FILE)

    return {
        "online": True,
        "peer_count": len(peers) if isinstance(peers, list) else 0,
        "service_count": len(services) if isinstance(services, list) else 0,
        "threat_count": len(threats) if isinstance(threats, dict) else 0,
        "uptime": "unknown",
        "version": "1.0.0"
    }

# ============== Peers ==============

@app.get("/peers")
async def list_peers():
    """List all known peers."""
    init_dirs()
    peers = load_json(PEERS_FILE)
    return {"peers": peers if isinstance(peers, list) else []}

@app.post("/peers")
async def add_peer(req: PeerRequest, user: dict = Depends(require_jwt)):
    """Add a new peer."""
    init_dirs()
    peers = load_json(PEERS_FILE)
    if not isinstance(peers, list):
        peers = []

    peer = {
        "id": req.peer_id,
        "name": req.name or req.peer_id[:8],
        "address": req.address,
        "added": datetime.utcnow().isoformat(),
        "status": "pending"
    }
    peers.append(peer)
    save_json(PEERS_FILE, peers)
    return {"status": "ok", "peer": peer}

@app.delete("/peers/{peer_id}")
async def remove_peer(peer_id: str, user: dict = Depends(require_jwt)):
    """Remove a peer."""
    init_dirs()
    peers = load_json(PEERS_FILE)
    if isinstance(peers, list):
        peers = [p for p in peers if p.get('id') != peer_id]
        save_json(PEERS_FILE, peers)
    return {"status": "ok"}

# ============== Services ==============

@app.get("/services")
async def list_services():
    """List all P2P services."""
    init_dirs()
    services = load_json(SERVICES_FILE)
    return {"services": services if isinstance(services, list) else []}

@app.post("/services")
async def register_service(req: ServiceRequest, user: dict = Depends(require_jwt)):
    """Register a P2P service."""
    init_dirs()
    services = load_json(SERVICES_FILE)
    if not isinstance(services, list):
        services = []

    service = {
        "name": req.name,
        "port": req.port,
        "protocol": req.protocol,
        "description": req.description,
        "registered": datetime.utcnow().isoformat(),
        "active": True
    }
    services.append(service)
    save_json(SERVICES_FILE, services)
    return {"status": "ok", "service": service}

@app.delete("/services/{name}")
async def unregister_service(name: str, user: dict = Depends(require_jwt)):
    """Unregister a service."""
    init_dirs()
    services = load_json(SERVICES_FILE)
    if isinstance(services, list):
        services = [s for s in services if s.get('name') != name]
        save_json(SERVICES_FILE, services)
    return {"status": "ok"}

# ============== Profiles ==============

@app.get("/profiles")
async def list_profiles():
    """List P2P profiles."""
    init_dirs()
    profiles = load_json(PROFILES_FILE)
    return {"profiles": profiles if isinstance(profiles, dict) else {}}

@app.post("/profiles")
async def create_profile(req: ProfileRequest, user: dict = Depends(require_jwt)):
    """Create a P2P profile."""
    init_dirs()
    profiles = load_json(PROFILES_FILE)
    if not isinstance(profiles, dict):
        profiles = {}

    profiles[req.name] = {
        "name": req.name,
        "settings": req.settings,
        "created": datetime.utcnow().isoformat()
    }
    save_json(PROFILES_FILE, profiles)
    return {"status": "ok", "profile": profiles[req.name]}

@app.delete("/profiles/{name}")
async def delete_profile(name: str, user: dict = Depends(require_jwt)):
    """Delete a profile."""
    init_dirs()
    profiles = load_json(PROFILES_FILE)
    if isinstance(profiles, dict) and name in profiles:
        del profiles[name]
        save_json(PROFILES_FILE, profiles)
    return {"status": "ok"}

# ============== Mesh Network ==============

@app.get("/mesh")
async def get_mesh_status():
    """Get mesh network topology."""
    init_dirs()
    peers = load_json(PEERS_FILE)

    # Build simple mesh topology
    nodes = []
    links = []

    for i, peer in enumerate(peers if isinstance(peers, list) else []):
        nodes.append({
            "id": peer.get('id', str(i)),
            "name": peer.get('name', f'peer-{i}'),
            "status": peer.get('status', 'unknown')
        })

    return {
        "nodes": nodes,
        "links": links,
        "total_nodes": len(nodes)
    }

# ============== Threat Intelligence ==============

@app.get("/threats")
async def list_threats():
    """List threat intelligence entries."""
    init_dirs()
    threats = load_json(THREATS_FILE)
    return {"threats": threats if isinstance(threats, dict) else {}}

@app.post("/threats")
async def report_threat(req: ThreatRequest, user: dict = Depends(require_jwt)):
    """Report a threat."""
    init_dirs()
    threats = load_json(THREATS_FILE)
    if not isinstance(threats, dict):
        threats = {}

    threats[req.ip] = {
        "ip": req.ip,
        "reason": req.reason,
        "severity": req.severity,
        "reported": datetime.utcnow().isoformat(),
        "reporter": user.get('sub', 'anonymous')
    }
    save_json(THREATS_FILE, threats)
    return {"status": "ok", "threat": threats[req.ip]}

@app.delete("/threats/{ip}")
async def remove_threat(ip: str, user: dict = Depends(require_jwt)):
    """Remove a threat entry."""
    init_dirs()
    threats = load_json(THREATS_FILE)
    if isinstance(threats, dict) and ip in threats:
        del threats[ip]
        save_json(THREATS_FILE, threats)
    return {"status": "ok"}

# ============== Factory / Dev ==============

@app.get("/factory/status")
async def factory_status():
    """Get factory/development status."""
    return {
        "mode": "production",
        "debug": False,
        "build": "1.0.0"
    }

@app.post("/factory/reset")
async def factory_reset(user: dict = Depends(require_jwt)):
    """Reset to factory defaults."""
    init_dirs()
    # Clear all data files
    for f in [PEERS_FILE, SERVICES_FILE, PROFILES_FILE, THREATS_FILE]:
        if f.exists():
            f.unlink()
    return {"status": "ok", "message": "Factory reset complete"}

@app.get("/health")
async def health():
    return {"status": "ok", "service": "secubox-p2p"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
