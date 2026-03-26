"""
SecuBox Mesh API - Yggdrasil Mesh Network with SecuBox Peer Discovery

FastAPI backend for mesh networking with:
- Yggdrasil mesh network management
- SecuBox peer discovery and registration
- Service announcement and resolution
- Mesh DNS integration
"""

import json
import subprocess
import time
import asyncio
import socket
from pathlib import Path
from typing import Optional, List
from datetime import datetime

from fastapi import FastAPI, HTTPException, Query, Depends, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

try:
    from secubox_core.auth import require_jwt
except ImportError:
    async def require_jwt():
        return {"user": "dev"}

app = FastAPI(
    title="SecuBox Mesh API",
    description="Yggdrasil mesh network with SecuBox peer discovery",
    version="1.1.0"
)

# Configuration paths
CONFIG_PATH = Path("/etc/secubox/mesh.toml")
DATA_PATH = Path("/var/lib/secubox/mesh")
SERVICES_FILE = DATA_PATH / "services.json"
DOMAINS_FILE = DATA_PATH / "domains.json"
PEERS_FILE = DATA_PATH / "peers.json"

# SecuBox service announcement port
SECUBOX_ANNOUNCE_PORT = 9444
SECUBOX_SERVICE_TYPE = "_secubox._tcp"

# Ensure data directory exists
DATA_PATH.mkdir(parents=True, exist_ok=True)


class ServiceAnnounce(BaseModel):
    name: str
    type: str
    port: int


class ServiceRevoke(BaseModel):
    name: str


class PeerInfo(BaseModel):
    ipv6: str
    hostname: Optional[str] = None
    version: Optional[str] = None
    modules: Optional[List[str]] = None


class PeerRegister(BaseModel):
    ipv6: str
    hostname: str
    version: str
    platform: str  # "openwrt" or "debian"
    modules: List[str]


def load_json(path: Path, default=None):
    """Load JSON from file with default fallback."""
    if default is None:
        default = {}
    try:
        if path.exists():
            return json.loads(path.read_text())
    except (json.JSONDecodeError, IOError):
        pass
    return default


def save_json(path: Path, data):
    """Save JSON to file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2))


def get_yggdrasil_info():
    """Get Yggdrasil node information."""
    info = {
        "running": False,
        "ipv6": None,
        "subnet": None,
        "public_key": None,
        "coords": None
    }

    try:
        result = subprocess.run(
            ["systemctl", "is-active", "yggdrasil"],
            capture_output=True,
            text=True
        )
        info["running"] = result.returncode == 0

        if info["running"]:
            result = subprocess.run(
                ["yggdrasilctl", "-json", "getSelf"],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                data = json.loads(result.stdout)
                info["ipv6"] = data.get("address") or data.get("Address")
                info["subnet"] = data.get("subnet") or data.get("Subnet")
                info["public_key"] = data.get("key") or data.get("PublicKey")
                info["coords"] = data.get("coords") or data.get("Coords")
    except (subprocess.SubprocessError, json.JSONDecodeError, FileNotFoundError):
        pass

    return info


def get_yggdrasil_peers():
    """Get Yggdrasil connected peers."""
    peers = []

    try:
        result = subprocess.run(
            ["yggdrasilctl", "-json", "getPeers"],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            data = json.loads(result.stdout)
            # Handle different response formats
            peer_list = data.get("peers") or data.get("Peers") or data
            if isinstance(peer_list, dict):
                for key, peer in peer_list.items():
                    peers.append({
                        "key": peer.get("key") or peer.get("PublicKey") or key,
                        "address": peer.get("address") or peer.get("Address"),
                        "port": peer.get("port") or peer.get("Port"),
                        "uptime": peer.get("uptime") or peer.get("Uptime"),
                        "rx_bytes": peer.get("bytes_recvd") or peer.get("RXBytes") or 0,
                        "tx_bytes": peer.get("bytes_sent") or peer.get("TXBytes") or 0,
                    })
            elif isinstance(peer_list, list):
                for peer in peer_list:
                    peers.append({
                        "key": peer.get("key") or peer.get("PublicKey"),
                        "address": peer.get("address") or peer.get("Address"),
                        "port": peer.get("port") or peer.get("Port"),
                        "uptime": peer.get("uptime") or peer.get("Uptime"),
                        "rx_bytes": peer.get("bytes_recvd") or peer.get("RXBytes") or 0,
                        "tx_bytes": peer.get("bytes_sent") or peer.get("TXBytes") or 0,
                    })
    except (subprocess.SubprocessError, json.JSONDecodeError, FileNotFoundError):
        pass

    return peers


def get_yggdrasil_sessions():
    """Get Yggdrasil active sessions (remote nodes we're communicating with)."""
    sessions = []

    try:
        result = subprocess.run(
            ["yggdrasilctl", "-json", "getSessions"],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            data = json.loads(result.stdout)
            session_list = data.get("sessions") or data.get("Sessions") or data
            if isinstance(session_list, dict):
                for key, session in session_list.items():
                    sessions.append({
                        "address": session.get("address") or session.get("Address") or key,
                        "key": session.get("key") or session.get("PublicKey"),
                        "rx_bytes": session.get("bytes_recvd") or session.get("RXBytes") or 0,
                        "tx_bytes": session.get("bytes_sent") or session.get("TXBytes") or 0,
                        "uptime": session.get("uptime") or session.get("Uptime"),
                    })
    except (subprocess.SubprocessError, json.JSONDecodeError, FileNotFoundError):
        pass

    return sessions


def ipv6_to_meshname(ipv6: str) -> str:
    """Convert Yggdrasil IPv6 to meshname domain."""
    if not ipv6:
        return ""
    clean = ipv6.replace(":", "").lower()
    short = clean[:16]
    return f"{short}.meshname"


async def probe_secubox_peer(ipv6: str, timeout: float = 3.0) -> dict:
    """Probe a mesh peer to check if it's running SecuBox."""
    result = {
        "is_secubox": False,
        "platform": None,
        "version": None,
        "hostname": None,
        "modules": []
    }

    try:
        # Try to reach the SecuBox API on the mesh peer
        proc = await asyncio.create_subprocess_exec(
            "curl", "-s", "--connect-timeout", str(timeout),
            "-k", f"https://[{ipv6}]:9443/api/v1/hub/status",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout + 1)

        if stdout:
            try:
                data = json.loads(stdout.decode())
                if data.get("status") == "ok" or "secubox" in str(data).lower():
                    result["is_secubox"] = True
                    result["hostname"] = data.get("hostname")
                    result["version"] = data.get("version")
                    result["platform"] = "debian"
            except json.JSONDecodeError:
                pass

        # Try OpenWRT LuCI endpoint if not detected
        if not result["is_secubox"]:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                "--connect-timeout", str(timeout),
                "-k", f"https://[{ipv6}]/cgi-bin/luci",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout + 1)
            http_code = stdout.decode().strip()

            if http_code in ["200", "301", "302", "401", "403"]:
                result["is_secubox"] = True
                result["platform"] = "openwrt"

    except (asyncio.TimeoutError, Exception):
        pass

    return result


@app.get("/status")
async def get_status():
    """Get mesh network status (public)."""
    ygg_info = get_yggdrasil_info()
    peers = get_yggdrasil_peers()
    services = load_json(SERVICES_FILE, {"services": []})
    domains = load_json(DOMAINS_FILE, {"domains": [], "last_sync": None})
    secubox_peers = load_json(PEERS_FILE, {"peers": []})

    mesh_running = False
    try:
        result = subprocess.run(
            ["systemctl", "is-active", "secubox-mesh"],
            capture_output=True,
            text=True
        )
        mesh_running = result.returncode == 0
    except subprocess.SubprocessError:
        pass

    return {
        "yggdrasil": {
            "running": ygg_info["running"],
            "ipv6": ygg_info["ipv6"],
            "subnet": ygg_info["subnet"],
            "public_key": ygg_info["public_key"],
            "coords": ygg_info["coords"],
            "peers_count": len(peers),
        },
        "mesh_dns_running": mesh_running,
        "local_services_count": len(services.get("services", [])),
        "remote_domains_count": len(domains.get("domains", [])),
        "secubox_peers_count": len(secubox_peers.get("peers", [])),
        "last_sync": domains.get("last_sync")
    }


@app.get("/peers")
async def get_peers(user=Depends(require_jwt)):
    """Get Yggdrasil connected peers."""
    peers = get_yggdrasil_peers()
    return {"peers": peers, "count": len(peers)}


@app.get("/sessions")
async def get_sessions(user=Depends(require_jwt)):
    """Get Yggdrasil active sessions."""
    sessions = get_yggdrasil_sessions()
    return {"sessions": sessions, "count": len(sessions)}


@app.get("/services")
async def get_services():
    """Get local announced services (public read)."""
    data = load_json(SERVICES_FILE, {"services": []})
    ygg_info = get_yggdrasil_info()

    for service in data.get("services", []):
        if ygg_info["ipv6"]:
            service["meshname"] = f"{service['name']}.{ipv6_to_meshname(ygg_info['ipv6'])}"
        else:
            service["meshname"] = None

    return data


@app.post("/announce")
async def announce_service(service: ServiceAnnounce, user=Depends(require_jwt)):
    """Announce a service to the mesh network."""
    data = load_json(SERVICES_FILE, {"services": []})

    for existing in data["services"]:
        if existing["name"] == service.name:
            raise HTTPException(status_code=400, detail="Service already exists")

    new_service = {
        "name": service.name,
        "type": service.type,
        "port": service.port,
        "active": True,
        "announced_at": int(time.time())
    }
    data["services"].append(new_service)
    save_json(SERVICES_FILE, data)

    return {"status": "success", "service": new_service}


@app.post("/revoke")
async def revoke_service(service: ServiceRevoke, user=Depends(require_jwt)):
    """Revoke a service from the mesh network."""
    data = load_json(SERVICES_FILE, {"services": []})

    found = False
    data["services"] = [s for s in data["services"] if s["name"] != service.name or not (found := True)]

    if not found:
        raise HTTPException(status_code=404, detail="Service not found")

    save_json(SERVICES_FILE, data)
    return {"status": "success"}


@app.get("/domains")
async def get_domains():
    """Get discovered remote domains (public read)."""
    data = load_json(DOMAINS_FILE, {"domains": [], "last_sync": None})
    return data


@app.post("/sync")
async def sync_domains(user=Depends(require_jwt)):
    """Sync domains from the mesh network."""
    data = load_json(DOMAINS_FILE, {"domains": []})
    data["last_sync"] = int(time.time())
    save_json(DOMAINS_FILE, data)

    return {"status": "success", "domains_count": len(data.get("domains", []))}


@app.get("/resolve")
async def resolve_domain(domain: str = Query(..., description="Meshname domain to resolve"), user=Depends(require_jwt)):
    """Resolve a meshname domain to IPv6."""
    if not domain:
        raise HTTPException(status_code=400, detail="Domain is required")

    data = load_json(DOMAINS_FILE, {"domains": []})
    for d in data.get("domains", []):
        if d["name"] == domain:
            return {
                "domain": domain,
                "ipv6": d["ipv6"],
                "type": d.get("type", "unknown"),
                "source": "cache"
            }

    raise HTTPException(status_code=404, detail="Domain not found")


# ════════════════════════════════════════════════════════════════════════════
# SecuBox Peer Discovery
# ════════════════════════════════════════════════════════════════════════════

@app.get("/secubox/peers")
async def get_secubox_peers(user=Depends(require_jwt)):
    """Get discovered SecuBox peers on the mesh network."""
    data = load_json(PEERS_FILE, {"peers": []})
    return {
        "peers": data.get("peers", []),
        "count": len(data.get("peers", [])),
        "last_discovery": data.get("last_discovery")
    }


@app.post("/secubox/register")
async def register_secubox_peer(peer: PeerRegister, user=Depends(require_jwt)):
    """Register a SecuBox peer (called by remote peers)."""
    data = load_json(PEERS_FILE, {"peers": []})

    # Update or add peer
    existing = next((p for p in data["peers"] if p["ipv6"] == peer.ipv6), None)
    if existing:
        existing.update({
            "hostname": peer.hostname,
            "version": peer.version,
            "platform": peer.platform,
            "modules": peer.modules,
            "last_seen": datetime.now().isoformat(),
        })
    else:
        data["peers"].append({
            "ipv6": peer.ipv6,
            "hostname": peer.hostname,
            "version": peer.version,
            "platform": peer.platform,
            "modules": peer.modules,
            "first_seen": datetime.now().isoformat(),
            "last_seen": datetime.now().isoformat(),
            "online": True
        })

    save_json(PEERS_FILE, data)
    return {"status": "success", "peer": peer.ipv6}


@app.post("/secubox/discover")
async def discover_secubox_peers(user=Depends(require_jwt)):
    """Discover SecuBox peers on the mesh network."""
    sessions = get_yggdrasil_sessions()
    data = load_json(PEERS_FILE, {"peers": []})

    # Probe each session in parallel
    semaphore = asyncio.Semaphore(10)

    async def probe_with_semaphore(session):
        async with semaphore:
            ipv6 = session.get("address", "").split("/")[0]
            if not ipv6 or not ipv6.startswith("2"):
                return None

            result = await probe_secubox_peer(ipv6, timeout=5.0)
            if result["is_secubox"]:
                return {
                    "ipv6": ipv6,
                    "hostname": result["hostname"],
                    "version": result["version"],
                    "platform": result["platform"],
                    "modules": result["modules"],
                    "first_seen": datetime.now().isoformat(),
                    "last_seen": datetime.now().isoformat(),
                    "online": True
                }
            return None

    tasks = [probe_with_semaphore(s) for s in sessions]
    results = await asyncio.gather(*tasks)

    # Update peers list
    new_peers = [r for r in results if r]
    for new_peer in new_peers:
        existing = next((p for p in data["peers"] if p["ipv6"] == new_peer["ipv6"]), None)
        if existing:
            existing.update({
                "hostname": new_peer["hostname"] or existing.get("hostname"),
                "version": new_peer["version"] or existing.get("version"),
                "platform": new_peer["platform"] or existing.get("platform"),
                "modules": new_peer["modules"] or existing.get("modules", []),
                "last_seen": datetime.now().isoformat(),
                "online": True
            })
        else:
            data["peers"].append(new_peer)

    # Mark offline peers
    discovered_ips = {p["ipv6"] for p in new_peers}
    for peer in data["peers"]:
        if peer["ipv6"] not in discovered_ips:
            peer["online"] = False

    data["last_discovery"] = datetime.now().isoformat()
    save_json(PEERS_FILE, data)

    return {
        "status": "success",
        "sessions_probed": len(sessions),
        "secubox_found": len(new_peers),
        "total_peers": len(data["peers"]),
        "peers": new_peers
    }


@app.get("/secubox/peer/{ipv6:path}")
async def get_secubox_peer(ipv6: str, user=Depends(require_jwt)):
    """Get details of a specific SecuBox peer."""
    data = load_json(PEERS_FILE, {"peers": []})
    peer = next((p for p in data["peers"] if p["ipv6"] == ipv6), None)

    if not peer:
        raise HTTPException(status_code=404, detail="Peer not found")

    return peer


@app.delete("/secubox/peer/{ipv6:path}")
async def remove_secubox_peer(ipv6: str, user=Depends(require_jwt)):
    """Remove a SecuBox peer from the list."""
    data = load_json(PEERS_FILE, {"peers": []})

    original_len = len(data["peers"])
    data["peers"] = [p for p in data["peers"] if p["ipv6"] != ipv6]

    if len(data["peers"]) == original_len:
        raise HTTPException(status_code=404, detail="Peer not found")

    save_json(PEERS_FILE, data)
    return {"status": "success"}


@app.get("/secubox/self")
async def get_self_info(user=Depends(require_jwt)):
    """Get this node's SecuBox info for mesh announcement."""
    ygg_info = get_yggdrasil_info()

    # Get hostname
    hostname = "secubox"
    try:
        hostname = socket.gethostname()
    except Exception:
        pass

    # Get installed modules (check for running services)
    modules = []
    try:
        result = subprocess.run(
            ["systemctl", "list-units", "--type=service", "--state=running", "--no-legend"],
            capture_output=True, text=True
        )
        for line in result.stdout.split('\n'):
            if 'secubox-' in line:
                match = line.split()[0].replace('.service', '').replace('secubox-', '')
                if match:
                    modules.append(match)
    except Exception:
        pass

    return {
        "ipv6": ygg_info["ipv6"],
        "hostname": hostname,
        "version": "1.1.0",
        "platform": "debian",
        "modules": modules,
        "meshname": ipv6_to_meshname(ygg_info["ipv6"]) if ygg_info["ipv6"] else None
    }


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "secubox-mesh", "version": "1.1.0"}
