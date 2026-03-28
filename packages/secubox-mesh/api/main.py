"""
SecuBox Mesh API - Yggdrasil Mesh Network with SecuBox Peer Discovery

FastAPI backend for mesh networking with:
- Yggdrasil mesh network management
- SecuBox peer discovery and registration
- Service announcement and resolution
- Mesh DNS integration
- Peer health monitoring
- Traffic statistics
- Webhook notifications
"""

import json
import subprocess
import time
import asyncio
import socket
import threading
import hashlib
import hmac
import httpx
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from enum import Enum

from fastapi import FastAPI, HTTPException, Query, Depends, WebSocket, WebSocketDisconnect, BackgroundTasks
from pydantic import BaseModel, Field

try:
    from secubox_core.auth import require_jwt
except ImportError:
    async def require_jwt():
        return {"user": "dev"}

app = FastAPI(
    title="SecuBox Mesh API",
    description="Yggdrasil mesh network with SecuBox peer discovery",
    version="2.0.0"
)

# Configuration paths
CONFIG_PATH = Path("/etc/secubox/mesh.toml")
DATA_PATH = Path("/var/lib/secubox/mesh")
SERVICES_FILE = DATA_PATH / "services.json"
DOMAINS_FILE = DATA_PATH / "domains.json"
PEERS_FILE = DATA_PATH / "peers.json"
HEALTH_HISTORY_FILE = DATA_PATH / "health_history.json"
TRAFFIC_STATS_FILE = DATA_PATH / "traffic_stats.json"
WEBHOOKS_FILE = DATA_PATH / "webhooks.json"

# SecuBox service announcement port
SECUBOX_ANNOUNCE_PORT = 9444
SECUBOX_SERVICE_TYPE = "_secubox._tcp"

# Ensure data directory exists
DATA_PATH.mkdir(parents=True, exist_ok=True)


# ════════════════════════════════════════════════════════════════════════════
# Models
# ════════════════════════════════════════════════════════════════════════════

class HealthStatus(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


class PeerHealthRecord(BaseModel):
    ipv6: str
    status: HealthStatus
    timestamp: str
    response_time_ms: Optional[float] = None
    error: Optional[str] = None


class TrafficStats(BaseModel):
    timestamp: str
    total_rx_bytes: int = 0
    total_tx_bytes: int = 0
    peer_count: int = 0
    session_count: int = 0
    secubox_peers_online: int = 0


class WebhookConfig(BaseModel):
    id: str
    url: str
    events: List[str] = ["peer_online", "peer_offline", "discovery_complete"]
    secret: Optional[str] = None
    enabled: bool = True
    created_at: str
    last_triggered: Optional[str] = None
    failure_count: int = 0


class DiscoverySchedule(BaseModel):
    enabled: bool = False
    interval_minutes: int = Field(ge=1, le=1440, default=15)
    last_run: Optional[str] = None
    next_run: Optional[str] = None


# ════════════════════════════════════════════════════════════════════════════
# Stats Cache
# ════════════════════════════════════════════════════════════════════════════

class StatsCache:
    """Thread-safe stats cache with TTL."""
    def __init__(self, ttl_seconds: int = 30):
        self.ttl = ttl_seconds
        self._cache: Dict[str, Any] = {}
        self._timestamps: Dict[str, float] = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            if key in self._cache:
                if time.time() - self._timestamps[key] < self.ttl:
                    return self._cache[key]
                del self._cache[key]
                del self._timestamps[key]
        return None

    def set(self, key: str, value: Any):
        with self._lock:
            self._cache[key] = value
            self._timestamps[key] = time.time()

    def invalidate(self, key: str = None):
        with self._lock:
            if key:
                self._cache.pop(key, None)
                self._timestamps.pop(key, None)
            else:
                self._cache.clear()
                self._timestamps.clear()


stats_cache = StatsCache(ttl_seconds=30)


# ════════════════════════════════════════════════════════════════════════════
# Background Tasks
# ════════════════════════════════════════════════════════════════════════════

_discovery_task: Optional[asyncio.Task] = None
_health_check_task: Optional[asyncio.Task] = None


async def _periodic_discovery():
    """Background task for periodic peer discovery."""
    while True:
        try:
            schedule = load_json(DATA_PATH / "discovery_schedule.json", {
                "enabled": False, "interval_minutes": 15
            })

            if schedule.get("enabled", False):
                interval = schedule.get("interval_minutes", 15)
                await asyncio.sleep(interval * 60)

                # Run discovery
                sessions = get_yggdrasil_sessions()
                data = load_json(PEERS_FILE, {"peers": []})

                discovered = []
                for session in sessions:
                    ipv6 = session.get("address", "").split("/")[0]
                    if ipv6 and ipv6.startswith("2"):
                        result = await probe_secubox_peer(ipv6, timeout=5.0)
                        if result["is_secubox"]:
                            discovered.append({
                                "ipv6": ipv6,
                                "hostname": result["hostname"],
                                "version": result["version"],
                                "platform": result["platform"],
                                "online": True
                            })

                # Update schedule
                schedule["last_run"] = datetime.now().isoformat()
                schedule["next_run"] = (datetime.now() + timedelta(minutes=interval)).isoformat()
                save_json(DATA_PATH / "discovery_schedule.json", schedule)

                # Notify webhooks
                await trigger_webhooks("discovery_complete", {
                    "peers_found": len(discovered),
                    "timestamp": datetime.now().isoformat()
                })
            else:
                await asyncio.sleep(60)
        except asyncio.CancelledError:
            break
        except Exception:
            await asyncio.sleep(60)


async def _periodic_health_check():
    """Background task for peer health monitoring."""
    while True:
        try:
            await asyncio.sleep(60)  # Check every minute
            data = load_json(PEERS_FILE, {"peers": []})
            history = load_json(HEALTH_HISTORY_FILE, {"records": []})

            for peer in data.get("peers", []):
                ipv6 = peer.get("ipv6")
                if not ipv6:
                    continue

                # Quick health check
                start = time.time()
                try:
                    proc = await asyncio.create_subprocess_exec(
                        "ping", "-c", "1", "-W", "2", ipv6,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    await asyncio.wait_for(proc.communicate(), timeout=3.0)
                    response_time = (time.time() - start) * 1000

                    was_online = peer.get("online", False)
                    peer["online"] = proc.returncode == 0

                    record = {
                        "ipv6": ipv6,
                        "status": "healthy" if peer["online"] else "unhealthy",
                        "timestamp": datetime.now().isoformat(),
                        "response_time_ms": response_time if peer["online"] else None
                    }
                    history["records"].append(record)

                    # Trigger webhook on status change
                    if was_online and not peer["online"]:
                        await trigger_webhooks("peer_offline", {
                            "ipv6": ipv6,
                            "hostname": peer.get("hostname"),
                            "timestamp": datetime.now().isoformat()
                        })
                    elif not was_online and peer["online"]:
                        await trigger_webhooks("peer_online", {
                            "ipv6": ipv6,
                            "hostname": peer.get("hostname"),
                            "timestamp": datetime.now().isoformat()
                        })

                except (asyncio.TimeoutError, Exception):
                    peer["online"] = False

            # Keep last 1000 records
            history["records"] = history["records"][-1000:]
            save_json(HEALTH_HISTORY_FILE, history)
            save_json(PEERS_FILE, data)

        except asyncio.CancelledError:
            break
        except Exception:
            pass


@app.on_event("startup")
async def startup_event():
    """Start background tasks."""
    global _discovery_task, _health_check_task
    _discovery_task = asyncio.create_task(_periodic_discovery())
    _health_check_task = asyncio.create_task(_periodic_health_check())


@app.on_event("shutdown")
async def shutdown_event():
    """Stop background tasks."""
    global _discovery_task, _health_check_task
    if _discovery_task:
        _discovery_task.cancel()
    if _health_check_task:
        _health_check_task.cancel()


# ════════════════════════════════════════════════════════════════════════════
# Webhook Support
# ════════════════════════════════════════════════════════════════════════════

async def trigger_webhooks(event: str, payload: dict):
    """Trigger webhooks for an event."""
    webhooks = load_json(WEBHOOKS_FILE, {"webhooks": []})

    for hook in webhooks.get("webhooks", []):
        if not hook.get("enabled", True):
            continue
        if event not in hook.get("events", []):
            continue

        try:
            data = {
                "event": event,
                "timestamp": datetime.now().isoformat(),
                "payload": payload
            }

            headers = {"Content-Type": "application/json"}
            if hook.get("secret"):
                sig = hmac.new(
                    hook["secret"].encode(),
                    json.dumps(data).encode(),
                    hashlib.sha256
                ).hexdigest()
                headers["X-SecuBox-Signature"] = f"sha256={sig}"

            async with httpx.AsyncClient(timeout=10) as client:
                await client.post(hook["url"], json=data, headers=headers)

            hook["last_triggered"] = datetime.now().isoformat()
            hook["failure_count"] = 0
        except Exception:
            hook["failure_count"] = hook.get("failure_count", 0) + 1

    save_json(WEBHOOKS_FILE, webhooks)


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
    return {"status": "healthy", "service": "secubox-mesh", "version": "2.0.0"}


# ════════════════════════════════════════════════════════════════════════════
# Peer Health Monitoring
# ════════════════════════════════════════════════════════════════════════════

@app.get("/health/peers")
async def get_peer_health(user=Depends(require_jwt)):
    """Get health status of all SecuBox peers."""
    data = load_json(PEERS_FILE, {"peers": []})

    health_summary = {
        "total": len(data.get("peers", [])),
        "online": sum(1 for p in data.get("peers", []) if p.get("online", False)),
        "offline": sum(1 for p in data.get("peers", []) if not p.get("online", False)),
        "peers": []
    }

    for peer in data.get("peers", []):
        health_summary["peers"].append({
            "ipv6": peer.get("ipv6"),
            "hostname": peer.get("hostname"),
            "status": "healthy" if peer.get("online") else "unhealthy",
            "last_seen": peer.get("last_seen"),
            "platform": peer.get("platform")
        })

    return health_summary


@app.post("/health/check/{ipv6:path}")
async def check_peer_health(ipv6: str, user=Depends(require_jwt)):
    """Manually check health of a specific peer."""
    start = time.time()

    try:
        proc = await asyncio.create_subprocess_exec(
            "ping", "-c", "3", "-W", "2", ipv6,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10.0)
        response_time = (time.time() - start) * 1000

        # Parse ping output for packet loss
        output = stdout.decode()
        packet_loss = 100
        if "packet loss" in output.lower():
            import re
            match = re.search(r'(\d+)% packet loss', output)
            if match:
                packet_loss = int(match.group(1))

        status = "healthy" if proc.returncode == 0 and packet_loss < 50 else (
            "degraded" if packet_loss < 100 else "unhealthy"
        )

        # Record in history
        history = load_json(HEALTH_HISTORY_FILE, {"records": []})
        history["records"].append({
            "ipv6": ipv6,
            "status": status,
            "timestamp": datetime.now().isoformat(),
            "response_time_ms": response_time,
            "packet_loss": packet_loss
        })
        history["records"] = history["records"][-1000:]
        save_json(HEALTH_HISTORY_FILE, history)

        return {
            "ipv6": ipv6,
            "status": status,
            "response_time_ms": round(response_time, 2),
            "packet_loss": packet_loss,
            "checked_at": datetime.now().isoformat()
        }

    except asyncio.TimeoutError:
        return {
            "ipv6": ipv6,
            "status": "unhealthy",
            "error": "Timeout",
            "checked_at": datetime.now().isoformat()
        }
    except Exception as e:
        return {
            "ipv6": ipv6,
            "status": "unhealthy",
            "error": str(e),
            "checked_at": datetime.now().isoformat()
        }


@app.get("/health/history")
async def get_health_history(
    ipv6: Optional[str] = None,
    limit: int = Query(default=100, le=1000),
    user=Depends(require_jwt)
):
    """Get peer health history."""
    history = load_json(HEALTH_HISTORY_FILE, {"records": []})
    records = history.get("records", [])

    if ipv6:
        records = [r for r in records if r.get("ipv6") == ipv6]

    records = sorted(records, key=lambda x: x.get("timestamp", ""), reverse=True)

    return {
        "records": records[:limit],
        "total": len(records)
    }


# ════════════════════════════════════════════════════════════════════════════
# Traffic Statistics
# ════════════════════════════════════════════════════════════════════════════

@app.get("/stats/traffic")
async def get_traffic_stats(user=Depends(require_jwt)):
    """Get current traffic statistics."""
    cached = stats_cache.get("traffic_stats")
    if cached:
        return cached

    peers = get_yggdrasil_peers()
    sessions = get_yggdrasil_sessions()
    secubox_data = load_json(PEERS_FILE, {"peers": []})

    total_rx = sum(p.get("rx_bytes", 0) for p in peers)
    total_tx = sum(p.get("tx_bytes", 0) for p in peers)

    # Session traffic
    session_rx = sum(s.get("rx_bytes", 0) for s in sessions)
    session_tx = sum(s.get("tx_bytes", 0) for s in sessions)

    stats = {
        "timestamp": datetime.now().isoformat(),
        "peers": {
            "count": len(peers),
            "rx_bytes": total_rx,
            "tx_bytes": total_tx,
            "rx_human": _human_bytes(total_rx),
            "tx_human": _human_bytes(total_tx)
        },
        "sessions": {
            "count": len(sessions),
            "rx_bytes": session_rx,
            "tx_bytes": session_tx,
            "rx_human": _human_bytes(session_rx),
            "tx_human": _human_bytes(session_tx)
        },
        "secubox_peers": {
            "total": len(secubox_data.get("peers", [])),
            "online": sum(1 for p in secubox_data.get("peers", []) if p.get("online", False))
        }
    }

    stats_cache.set("traffic_stats", stats)
    return stats


def _human_bytes(b: int) -> str:
    """Convert bytes to human-readable format."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} PB"


@app.get("/stats/history")
async def get_traffic_history(
    hours: int = Query(default=24, le=168),
    user=Depends(require_jwt)
):
    """Get traffic statistics history."""
    history = load_json(TRAFFIC_STATS_FILE, {"records": []})
    records = history.get("records", [])

    # Filter by time
    cutoff = datetime.now() - timedelta(hours=hours)
    cutoff_str = cutoff.isoformat()
    records = [r for r in records if r.get("timestamp", "") >= cutoff_str]

    return {
        "records": records,
        "period_hours": hours
    }


@app.post("/stats/snapshot")
async def create_stats_snapshot(user=Depends(require_jwt)):
    """Create a traffic stats snapshot (useful for manual tracking)."""
    stats = await get_traffic_stats(user)

    history = load_json(TRAFFIC_STATS_FILE, {"records": []})
    history["records"].append({
        "timestamp": datetime.now().isoformat(),
        "total_rx_bytes": stats["peers"]["rx_bytes"] + stats["sessions"]["rx_bytes"],
        "total_tx_bytes": stats["peers"]["tx_bytes"] + stats["sessions"]["tx_bytes"],
        "peer_count": stats["peers"]["count"],
        "session_count": stats["sessions"]["count"],
        "secubox_peers_online": stats["secubox_peers"]["online"]
    })

    # Keep last 1000 records
    history["records"] = history["records"][-1000:]
    save_json(TRAFFIC_STATS_FILE, history)

    return {"status": "success", "snapshot": stats}


# ════════════════════════════════════════════════════════════════════════════
# Discovery Scheduling
# ════════════════════════════════════════════════════════════════════════════

@app.get("/discovery/schedule")
async def get_discovery_schedule(user=Depends(require_jwt)):
    """Get current discovery schedule."""
    schedule = load_json(DATA_PATH / "discovery_schedule.json", {
        "enabled": False,
        "interval_minutes": 15,
        "last_run": None,
        "next_run": None
    })
    return schedule


@app.post("/discovery/schedule")
async def set_discovery_schedule(config: DiscoverySchedule, user=Depends(require_jwt)):
    """Configure automatic peer discovery."""
    schedule = {
        "enabled": config.enabled,
        "interval_minutes": config.interval_minutes,
        "last_run": config.last_run,
        "next_run": (datetime.now() + timedelta(minutes=config.interval_minutes)).isoformat() if config.enabled else None
    }
    save_json(DATA_PATH / "discovery_schedule.json", schedule)

    return {"status": "success", "schedule": schedule}


# ════════════════════════════════════════════════════════════════════════════
# Webhooks
# ════════════════════════════════════════════════════════════════════════════

@app.get("/webhooks")
async def list_webhooks(user=Depends(require_jwt)):
    """List configured webhooks."""
    data = load_json(WEBHOOKS_FILE, {"webhooks": []})
    return {
        "webhooks": data.get("webhooks", []),
        "available_events": ["peer_online", "peer_offline", "discovery_complete", "service_announced", "service_revoked"]
    }


class WebhookCreate(BaseModel):
    url: str
    events: List[str] = ["peer_online", "peer_offline"]
    secret: Optional[str] = None
    enabled: bool = True


@app.post("/webhooks")
async def add_webhook(config: WebhookCreate, user=Depends(require_jwt)):
    """Add a webhook."""
    data = load_json(WEBHOOKS_FILE, {"webhooks": []})

    webhook_id = hashlib.sha256(f"{config.url}{time.time()}".encode()).hexdigest()[:12]

    webhook = {
        "id": webhook_id,
        "url": config.url,
        "events": config.events,
        "secret": config.secret,
        "enabled": config.enabled,
        "created_at": datetime.now().isoformat(),
        "last_triggered": None,
        "failure_count": 0
    }

    data["webhooks"].append(webhook)
    save_json(WEBHOOKS_FILE, data)

    return {"status": "success", "webhook": webhook}


@app.delete("/webhooks/{webhook_id}")
async def delete_webhook(webhook_id: str, user=Depends(require_jwt)):
    """Delete a webhook."""
    data = load_json(WEBHOOKS_FILE, {"webhooks": []})

    original_len = len(data["webhooks"])
    data["webhooks"] = [w for w in data["webhooks"] if w.get("id") != webhook_id]

    if len(data["webhooks"]) == original_len:
        raise HTTPException(status_code=404, detail="Webhook not found")

    save_json(WEBHOOKS_FILE, data)
    return {"status": "success"}


@app.post("/webhooks/{webhook_id}/test")
async def test_webhook(webhook_id: str, user=Depends(require_jwt)):
    """Test a webhook with a sample payload."""
    data = load_json(WEBHOOKS_FILE, {"webhooks": []})

    webhook = next((w for w in data["webhooks"] if w.get("id") == webhook_id), None)
    if not webhook:
        raise HTTPException(status_code=404, detail="Webhook not found")

    test_payload = {
        "event": "test",
        "timestamp": datetime.now().isoformat(),
        "payload": {"message": "This is a test webhook from SecuBox Mesh"}
    }

    try:
        headers = {"Content-Type": "application/json"}
        if webhook.get("secret"):
            sig = hmac.new(
                webhook["secret"].encode(),
                json.dumps(test_payload).encode(),
                hashlib.sha256
            ).hexdigest()
            headers["X-SecuBox-Signature"] = f"sha256={sig}"

        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(webhook["url"], json=test_payload, headers=headers)
            return {
                "status": "success",
                "response_code": resp.status_code,
                "response_body": resp.text[:500]
            }
    except Exception as e:
        return {
            "status": "error",
            "error": str(e)
        }


# ════════════════════════════════════════════════════════════════════════════
# Service Health Checks
# ════════════════════════════════════════════════════════════════════════════

@app.get("/services/health")
async def get_services_health(user=Depends(require_jwt)):
    """Check health of all announced services."""
    data = load_json(SERVICES_FILE, {"services": []})
    ygg_info = get_yggdrasil_info()

    results = []
    for service in data.get("services", []):
        port = service.get("port")

        # Check if port is listening locally
        listening = False
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex(("127.0.0.1", port))
            listening = result == 0
            sock.close()
        except Exception:
            pass

        results.append({
            "name": service.get("name"),
            "port": port,
            "type": service.get("type"),
            "status": "healthy" if listening else "unhealthy",
            "listening": listening,
            "meshname": f"{service['name']}.{ipv6_to_meshname(ygg_info['ipv6'])}" if ygg_info.get("ipv6") else None
        })

    return {
        "services": results,
        "healthy": sum(1 for s in results if s["status"] == "healthy"),
        "total": len(results)
    }


@app.post("/services/{name}/health")
async def check_service_health(name: str, user=Depends(require_jwt)):
    """Check health of a specific service."""
    data = load_json(SERVICES_FILE, {"services": []})

    service = next((s for s in data.get("services", []) if s.get("name") == name), None)
    if not service:
        raise HTTPException(status_code=404, detail="Service not found")

    port = service.get("port")
    start = time.time()

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex(("127.0.0.1", port))
        response_time = (time.time() - start) * 1000
        sock.close()

        return {
            "name": name,
            "port": port,
            "status": "healthy" if result == 0 else "unhealthy",
            "response_time_ms": round(response_time, 2),
            "checked_at": datetime.now().isoformat()
        }
    except Exception as e:
        return {
            "name": name,
            "port": port,
            "status": "unhealthy",
            "error": str(e),
            "checked_at": datetime.now().isoformat()
        }


# ════════════════════════════════════════════════════════════════════════════
# Export / Import
# ════════════════════════════════════════════════════════════════════════════

@app.get("/export/peers")
async def export_peers(format: str = Query(default="json", enum=["json", "csv"]), user=Depends(require_jwt)):
    """Export SecuBox peers."""
    data = load_json(PEERS_FILE, {"peers": []})
    peers = data.get("peers", [])

    if format == "csv":
        lines = ["ipv6,hostname,version,platform,online,first_seen,last_seen"]
        for p in peers:
            lines.append(",".join([
                p.get("ipv6", ""),
                p.get("hostname", ""),
                p.get("version", ""),
                p.get("platform", ""),
                str(p.get("online", False)),
                p.get("first_seen", ""),
                p.get("last_seen", "")
            ]))
        return {"format": "csv", "data": "\n".join(lines)}

    return {
        "format": "json",
        "exported_at": datetime.now().isoformat(),
        "peers": peers
    }


@app.get("/export/services")
async def export_services(user=Depends(require_jwt)):
    """Export announced services."""
    data = load_json(SERVICES_FILE, {"services": []})

    return {
        "exported_at": datetime.now().isoformat(),
        "services": data.get("services", [])
    }


class ImportPeers(BaseModel):
    peers: List[dict]
    merge: bool = True  # If true, merge with existing; if false, replace


@app.post("/import/peers")
async def import_peers(config: ImportPeers, user=Depends(require_jwt)):
    """Import SecuBox peers."""
    data = load_json(PEERS_FILE, {"peers": []})

    if config.merge:
        existing_ips = {p.get("ipv6") for p in data.get("peers", [])}
        for peer in config.peers:
            if peer.get("ipv6") not in existing_ips:
                data["peers"].append({
                    **peer,
                    "first_seen": peer.get("first_seen", datetime.now().isoformat()),
                    "last_seen": datetime.now().isoformat(),
                    "online": False
                })
    else:
        data["peers"] = [{
            **p,
            "first_seen": p.get("first_seen", datetime.now().isoformat()),
            "last_seen": datetime.now().isoformat(),
            "online": False
        } for p in config.peers]

    save_json(PEERS_FILE, data)

    return {
        "status": "success",
        "imported": len(config.peers),
        "total": len(data["peers"])
    }


# ════════════════════════════════════════════════════════════════════════════
# Mesh Network Summary
# ════════════════════════════════════════════════════════════════════════════

@app.get("/summary")
async def get_mesh_summary(user=Depends(require_jwt)):
    """Get comprehensive mesh network summary."""
    ygg_info = get_yggdrasil_info()
    peers = get_yggdrasil_peers()
    sessions = get_yggdrasil_sessions()
    services = load_json(SERVICES_FILE, {"services": []})
    domains = load_json(DOMAINS_FILE, {"domains": []})
    secubox_peers = load_json(PEERS_FILE, {"peers": []})
    schedule = load_json(DATA_PATH / "discovery_schedule.json", {"enabled": False})

    # Calculate totals
    total_rx = sum(p.get("rx_bytes", 0) for p in peers)
    total_tx = sum(p.get("tx_bytes", 0) for p in peers)

    return {
        "node": {
            "ipv6": ygg_info.get("ipv6"),
            "subnet": ygg_info.get("subnet"),
            "meshname": ipv6_to_meshname(ygg_info["ipv6"]) if ygg_info.get("ipv6") else None,
            "running": ygg_info.get("running", False)
        },
        "connectivity": {
            "peers": len(peers),
            "sessions": len(sessions),
            "total_rx": _human_bytes(total_rx),
            "total_tx": _human_bytes(total_tx)
        },
        "secubox": {
            "total_peers": len(secubox_peers.get("peers", [])),
            "online_peers": sum(1 for p in secubox_peers.get("peers", []) if p.get("online", False)),
            "last_discovery": secubox_peers.get("last_discovery")
        },
        "services": {
            "local": len(services.get("services", [])),
            "remote_domains": len(domains.get("domains", []))
        },
        "discovery": {
            "scheduled": schedule.get("enabled", False),
            "interval_minutes": schedule.get("interval_minutes", 15),
            "next_run": schedule.get("next_run")
        },
        "timestamp": datetime.now().isoformat()
    }
