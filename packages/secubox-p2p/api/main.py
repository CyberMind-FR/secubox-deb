#!/usr/bin/env python3
"""
SecuBox P2P API — Peer-to-Peer Network Hub
Manages peer discovery, mesh networking, service federation, and master-link enrollment
"""
from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import subprocess
import asyncio
import json
import os
import re
import socket
import hashlib
import secrets
from pathlib import Path
from datetime import datetime, timedelta

import sys
sys.path.insert(0, '/usr/lib/python3/dist-packages')
try:
    from secubox_core.auth import require_jwt
except ImportError:
    async def require_jwt():
        return {"sub": "admin"}

app = FastAPI(
    title="SecuBox P2P API",
    description="P2P network hub with peer discovery and master-link enrollment",
    version="1.3.0",
    docs_url="/docs",
    redoc_url=None
)

# Paths
P2P_DIR = Path("/var/lib/secubox/p2p")
PEERS_FILE = P2P_DIR / "peers.json"
SERVICES_FILE = P2P_DIR / "services.json"
PROFILES_FILE = P2P_DIR / "profiles.json"
THREATS_FILE = P2P_DIR / "threats.json"
NODE_ID_FILE = P2P_DIR / "node.id"
CONFIG_FILE = Path("/etc/secubox/p2p.toml")

# Master-Link paths
ML_DIR = P2P_DIR / "master-link"
ML_TOKENS_FILE = ML_DIR / "tokens.json"
ML_REQUESTS_FILE = ML_DIR / "requests.json"
ML_CONFIG_FILE = ML_DIR / "config.json"

# mDNS service type for SecuBox discovery
MDNS_SERVICE_TYPE = "_secubox._tcp"
API_PORT = 7331

# Master-Link defaults
ML_DEFAULT_TOKEN_TTL = 3600  # 1 hour
ML_DEFAULT_MAX_DEPTH = 3


def init_dirs():
    P2P_DIR.mkdir(parents=True, exist_ok=True)


def load_json(path: Path, default: Any = None) -> Any:
    if default is None:
        default = []
    if path.exists():
        try:
            with open(path) as f:
                return json.load(f)
        except:
            pass
    return default


def save_json(path: Path, data: Any):
    init_dirs()
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)


def get_node_id() -> str:
    """Get or generate unique node ID."""
    init_dirs()
    if NODE_ID_FILE.exists():
        return NODE_ID_FILE.read_text().strip()

    # Generate from MAC address or random
    node_id = None
    try:
        # Try to get MAC from first non-loopback interface
        result = subprocess.run(
            ["ip", "link", "show"],
            capture_output=True, text=True, timeout=5
        )
        mac_match = re.search(r'link/ether ([0-9a-f:]{17})', result.stdout)
        if mac_match:
            mac = mac_match.group(1).replace(':', '')
            node_id = f"sb-{mac}"
    except:
        pass

    if not node_id:
        import uuid
        node_id = f"sb-{uuid.uuid4().hex[:12]}"

    NODE_ID_FILE.write_text(node_id)
    return node_id


def get_hostname() -> str:
    """Get system hostname."""
    try:
        return socket.gethostname()
    except:
        return "secubox"


def get_lan_ip() -> Optional[str]:
    """Get LAN IP address."""
    try:
        # Try common interfaces
        for iface in ['br-lan', 'eth0', 'enp0s3', 'enp0s8']:
            result = subprocess.run(
                ["ip", "-4", "addr", "show", iface],
                capture_output=True, text=True, timeout=5
            )
            match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', result.stdout)
            if match:
                return match.group(1)

        # Fallback: get default route interface
        result = subprocess.run(
            ["ip", "-4", "route", "get", "1.1.1.1"],
            capture_output=True, text=True, timeout=5
        )
        match = re.search(r'src (\d+\.\d+\.\d+\.\d+)', result.stdout)
        if match:
            return match.group(1)
    except:
        pass
    return "127.0.0.1"


def get_wan_ip() -> Optional[str]:
    """Get WAN/public IP address."""
    try:
        result = subprocess.run(
            ["curl", "-s", "--connect-timeout", "3", "https://api.ipify.org"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except:
        pass
    return None


def get_wireguard_ips() -> List[str]:
    """Get WireGuard interface IPs."""
    wg_ips = []
    try:
        result = subprocess.run(
            ["ip", "-j", "addr", "show", "type", "wireguard"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            data = json.loads(result.stdout)
            for iface in data:
                for addr in iface.get('addr_info', []):
                    if addr.get('family') == 'inet':
                        wg_ips.append(addr.get('local'))
    except:
        pass
    return wg_ips


def get_node_addresses() -> List[Dict]:
    """Get all node addresses."""
    addresses = []

    lan_ip = get_lan_ip()
    if lan_ip:
        addresses.append({"type": "lan", "address": lan_ip, "port": API_PORT})

    wan_ip = get_wan_ip()
    if wan_ip:
        addresses.append({"type": "wan", "address": wan_ip, "port": API_PORT})

    for wg_ip in get_wireguard_ips():
        addresses.append({"type": "wireguard", "address": wg_ip, "port": API_PORT})

    return addresses


# ============== Master-Link Helpers ==============

def ml_init():
    """Initialize master-link directories and config."""
    ML_DIR.mkdir(parents=True, exist_ok=True)
    if not ML_CONFIG_FILE.exists():
        ml_config = {
            "enabled": True,
            "role": "master",
            "upstream": None,
            "depth": 0,
            "max_depth": ML_DEFAULT_MAX_DEPTH,
            "token_ttl": ML_DEFAULT_TOKEN_TTL,
            "auto_approve": False,
            "fingerprint": get_node_id()
        }
        save_json(ML_CONFIG_FILE, ml_config)


def get_ml_config() -> Dict:
    """Get master-link configuration."""
    ml_init()
    default = {
        "enabled": True,
        "role": "master",
        "upstream": None,
        "depth": 0,
        "max_depth": ML_DEFAULT_MAX_DEPTH,
        "token_ttl": ML_DEFAULT_TOKEN_TTL,
        "auto_approve": False,
        "fingerprint": get_node_id()
    }
    return load_json(ML_CONFIG_FILE, default)


def save_ml_config(config: Dict):
    """Save master-link configuration."""
    ml_init()
    save_json(ML_CONFIG_FILE, config)


def get_ml_tokens() -> List[Dict]:
    """Get all master-link tokens."""
    ml_init()
    return load_json(ML_TOKENS_FILE, [])


def save_ml_tokens(tokens: List[Dict]):
    """Save master-link tokens."""
    ml_init()
    save_json(ML_TOKENS_FILE, tokens)


def get_ml_requests() -> List[Dict]:
    """Get all join requests."""
    ml_init()
    return load_json(ML_REQUESTS_FILE, [])


def save_ml_requests(requests: List[Dict]):
    """Save join requests."""
    ml_init()
    save_json(ML_REQUESTS_FILE, requests)


def generate_token() -> str:
    """Generate a secure random token."""
    return secrets.token_hex(32)


def hash_token(token: str) -> str:
    """Hash a token for storage."""
    return hashlib.sha256(token.encode()).hexdigest()


def ml_token_generate(ttl: int = None, token_type: str = "join", auto_approve: bool = False) -> Dict:
    """Generate a new join token."""
    config = get_ml_config()
    tokens = get_ml_tokens()

    if ttl is None:
        ttl = config.get("token_ttl", ML_DEFAULT_TOKEN_TTL)

    token = generate_token()
    token_hash = hash_token(token)
    now = datetime.utcnow()
    expires = now + timedelta(seconds=ttl)

    token_entry = {
        "hash": token_hash,
        "type": token_type,
        "created": now.isoformat(),
        "expires": expires.isoformat(),
        "expires_ts": int(expires.timestamp()),
        "ttl": ttl,
        "status": "active",
        "auto_approve": auto_approve,
        "peer_fp": None,
        "used_by": None
    }
    tokens.append(token_entry)
    save_ml_tokens(tokens)

    # Build join URL
    lan_ip = get_lan_ip()

    return {
        "token": token,
        "token_hash": token_hash,
        "expires": expires.isoformat(),
        "ttl": ttl,
        "auto_approve": auto_approve,
        "url": f"http://{lan_ip}:{API_PORT}/master-link/?token={token}"
    }


def ml_token_validate(token: str) -> Dict:
    """Validate a token."""
    if not token:
        return {"valid": False, "error": "missing_token"}

    token_hash = hash_token(token)
    tokens = get_ml_tokens()
    now = datetime.utcnow()

    for t in tokens:
        if t.get("hash") == token_hash:
            # Check status
            if t.get("status") == "used":
                return {"valid": False, "error": "token_already_used"}
            if t.get("status") == "expired":
                return {"valid": False, "error": "token_expired"}
            if t.get("status") == "revoked":
                return {"valid": False, "error": "token_revoked"}

            # Check expiry
            expires_ts = t.get("expires_ts", 0)
            if now.timestamp() > expires_ts:
                # Mark as expired
                t["status"] = "expired"
                save_ml_tokens(tokens)
                return {"valid": False, "error": "token_expired"}

            return {
                "valid": True,
                "token_hash": token_hash,
                "expires": t.get("expires"),
                "auto_approve": t.get("auto_approve", False)
            }

    return {"valid": False, "error": "unknown_token"}


def ml_token_mark_used(token_hash: str, peer_fp: str):
    """Mark a token as used."""
    tokens = get_ml_tokens()
    for t in tokens:
        if t.get("hash") == token_hash:
            t["status"] = "used"
            t["peer_fp"] = peer_fp
            t["used_by"] = peer_fp
            t["used_at"] = datetime.utcnow().isoformat()
            break
    save_ml_tokens(tokens)


def ml_cleanup_tokens():
    """Remove expired tokens."""
    tokens = get_ml_tokens()
    now = datetime.utcnow().timestamp()
    cleaned = 0

    active_tokens = []
    for t in tokens:
        expires_ts = t.get("expires_ts", 0)
        if now > expires_ts or t.get("status") in ["used", "expired", "revoked"]:
            cleaned += 1
        else:
            active_tokens.append(t)

    if cleaned > 0:
        save_ml_tokens(active_tokens)

    return {"cleaned": cleaned}


async def discover_mdns(timeout: int = 5) -> List[Dict]:
    """Discover SecuBox peers via mDNS/Avahi."""
    peers = []

    try:
        proc = await asyncio.create_subprocess_exec(
            "avahi-browse", "-t", "-r", "-p", MDNS_SERVICE_TYPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout + 2)

        # Parse avahi-browse -p output
        # Format: +;iface;protocol;name;type;domain
        # =;iface;protocol;name;type;domain;hostname;address;port;txt
        current_service = {}
        for line in stdout.decode().split('\n'):
            parts = line.split(';')
            if len(parts) >= 8 and parts[0] == '=':
                name = parts[3]
                hostname = parts[6]
                address = parts[7]
                port = int(parts[8]) if parts[8].isdigit() else API_PORT

                peer_id = f"sb-{hashlib.md5(address.encode()).hexdigest()[:12]}"
                peers.append({
                    "id": peer_id,
                    "name": name or hostname,
                    "address": address,
                    "port": port,
                    "hostname": hostname,
                    "discovered_via": "mdns",
                    "discovered_at": datetime.utcnow().isoformat(),
                    "status": "online"
                })
    except FileNotFoundError:
        pass  # avahi-browse not installed
    except asyncio.TimeoutError:
        pass
    except Exception as e:
        print(f"mDNS discovery error: {e}")

    return peers


async def discover_network_scan(subnet: str = None, timeout: int = 5) -> List[Dict]:
    """Discover SecuBox peers via network scanning."""
    peers = []

    # Get subnet from LAN IP if not provided
    if not subnet:
        lan_ip = get_lan_ip()
        if lan_ip and lan_ip != "127.0.0.1":
            # Convert to /24 subnet
            subnet = '.'.join(lan_ip.split('.')[:3]) + '.0/24'
        else:
            return peers

    # Get ARP table
    arp_hosts = []
    try:
        result = subprocess.run(
            ["ip", "neigh", "show"],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.split('\n'):
            match = re.match(r'^(\d+\.\d+\.\d+\.\d+)\s+', line)
            if match and 'REACHABLE' in line or 'STALE' in line:
                arp_hosts.append(match.group(1))
    except:
        pass

    # Probe hosts for SecuBox
    async def probe_host(ip: str) -> Optional[Dict]:
        """Probe a single host for SecuBox."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-s", "--connect-timeout", "2", "-k",
                f"https://{ip}/cgi-bin/luci",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=3)
            body = stdout.decode().lower()

            is_secubox = any(m in body for m in [
                'data-secubox-theme', 'luci-static/secubox',
                'secubox-portal', 'luci-app-secubox'
            ])
            is_openwrt = 'luci' in body

            if is_secubox or is_openwrt:
                # Extract name from title
                name = "SecuBox" if is_secubox else "OpenWRT"
                title_match = re.search(r'<title>([^<]+)</title>', stdout.decode(), re.I)
                if title_match:
                    name = title_match.group(1).split(' - ')[0].strip()

                peer_id = f"sb-{hashlib.md5(ip.encode()).hexdigest()[:12]}"
                return {
                    "id": peer_id,
                    "name": name,
                    "address": ip,
                    "port": 443,
                    "is_secubox": is_secubox,
                    "is_openwrt": is_openwrt,
                    "discovered_via": "network_scan",
                    "discovered_at": datetime.utcnow().isoformat(),
                    "status": "online"
                }
        except:
            pass
        return None

    # Probe all ARP hosts concurrently
    if arp_hosts:
        tasks = [probe_host(ip) for ip in arp_hosts[:50]]  # Limit to 50 hosts
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, dict):
                peers.append(result)

    return peers


async def discover_peers(method: str = "all", timeout: int = 5) -> Dict:
    """Discover peers using specified method."""
    all_peers = []

    if method in ["all", "mdns"]:
        mdns_peers = await discover_mdns(timeout)
        all_peers.extend(mdns_peers)

    if method in ["all", "scan"]:
        scan_peers = await discover_network_scan(timeout=timeout)
        # Add only peers not already found via mDNS
        existing_addrs = {p["address"] for p in all_peers}
        for peer in scan_peers:
            if peer["address"] not in existing_addrs:
                all_peers.append(peer)

    # Deduplicate by address
    seen = set()
    unique_peers = []
    for peer in all_peers:
        if peer["address"] not in seen:
            seen.add(peer["address"])
            unique_peers.append(peer)

    return {
        "discovered": unique_peers,
        "count": len(unique_peers),
        "method": method,
        "timestamp": datetime.utcnow().isoformat()
    }


def get_self_peer() -> Dict:
    """Get local node as peer entry."""
    return {
        "id": get_node_id(),
        "name": f"{get_hostname()} (local)",
        "address": get_lan_ip(),
        "wan_address": get_wan_ip(),
        "wg_addresses": get_wireguard_ips(),
        "addresses": get_node_addresses(),
        "status": "online",
        "is_local": True,
        "added": datetime.utcnow().isoformat()
    }


# ============== Pydantic Models ==============

class PeerRequest(BaseModel):
    address: str
    name: Optional[str] = None
    wan_address: Optional[str] = None
    wg_address: Optional[str] = None


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


class DiscoverRequest(BaseModel):
    method: str = "all"  # all, mdns, scan
    timeout: int = 5


class JoinRequest(BaseModel):
    token: str
    fingerprint: str
    hostname: Optional[str] = None
    address: Optional[str] = None


class ApproveRequest(BaseModel):
    fingerprint: str
    action: str  # approve, reject, promote
    reason: Optional[str] = None


class TokenGenerateRequest(BaseModel):
    ttl: Optional[int] = None
    token_type: str = "join"
    auto_approve: bool = False


# ============== Status ==============

@app.get("/status")
async def get_status():
    """Get P2P network status (public)."""
    init_dirs()
    peers_data = load_json(PEERS_FILE, {"peers": []})
    services = load_json(SERVICES_FILE, [])
    threats = load_json(THREATS_FILE, {})

    peers = peers_data.get("peers", []) if isinstance(peers_data, dict) else peers_data
    online_peers = [p for p in peers if p.get("status") == "online"]

    # Get master-link status
    ml_config = get_ml_config()

    return {
        "online": True,
        "node_id": get_node_id(),
        "hostname": get_hostname(),
        "lan_ip": get_lan_ip(),
        "wan_ip": get_wan_ip(),
        "peer_count": len(peers),
        "online_peers": len(online_peers),
        "service_count": len(services) if isinstance(services, list) else 0,
        "threat_count": len(threats) if isinstance(threats, dict) else 0,
        "master_link": {
            "role": ml_config.get("role", "master"),
            "depth": ml_config.get("depth", 0),
            "upstream": ml_config.get("upstream")
        },
        "version": "1.3.0"
    }


# ============== Peer Discovery ==============

@app.get("/discover")
async def discover_get(method: str = "all", timeout: int = 5):
    """Discover peers (public read)."""
    return await discover_peers(method, timeout)


@app.post("/discover")
async def discover_post(req: DiscoverRequest, user: dict = Depends(require_jwt)):
    """Discover and optionally add peers."""
    result = await discover_peers(req.method, req.timeout)

    # Optionally auto-add discovered peers
    if result["discovered"]:
        peers_data = load_json(PEERS_FILE, {"peers": []})
        peers = peers_data.get("peers", []) if isinstance(peers_data, dict) else []
        existing_ids = {p.get("id") for p in peers}

        added = 0
        for peer in result["discovered"]:
            if peer["id"] not in existing_ids and not peer.get("is_local"):
                peers.append(peer)
                added += 1

        if added > 0:
            save_json(PEERS_FILE, {"peers": peers})
            result["added"] = added

    return result


@app.get("/discover/self")
async def get_self():
    """Get local node info for announcement."""
    return get_self_peer()


# ============== Peers ==============

@app.get("/peers")
async def list_peers():
    """List all known peers (public read)."""
    init_dirs()
    peers_data = load_json(PEERS_FILE, {"peers": []})
    peers = peers_data.get("peers", []) if isinstance(peers_data, dict) else peers_data

    # Ensure local node is in the list
    local_id = get_node_id()
    has_local = any(p.get("id") == local_id or p.get("is_local") for p in peers)

    if not has_local:
        peers.insert(0, get_self_peer())
        save_json(PEERS_FILE, {"peers": peers})

    return {"peers": peers, "count": len(peers)}


@app.post("/peers")
async def add_peer(req: PeerRequest, user: dict = Depends(require_jwt)):
    """Add a new peer manually."""
    init_dirs()
    peers_data = load_json(PEERS_FILE, {"peers": []})
    peers = peers_data.get("peers", []) if isinstance(peers_data, dict) else []

    peer_id = f"sb-{hashlib.md5(req.address.encode()).hexdigest()[:12]}"

    # Check if already exists
    if any(p.get("id") == peer_id or p.get("address") == req.address for p in peers):
        raise HTTPException(status_code=400, detail="Peer already exists")

    # Build addresses
    addresses = [{"type": "lan", "address": req.address, "port": API_PORT}]
    if req.wan_address:
        addresses.append({"type": "wan", "address": req.wan_address, "port": API_PORT})
    if req.wg_address:
        addresses.append({"type": "wireguard", "address": req.wg_address, "port": API_PORT})

    peer = {
        "id": peer_id,
        "name": req.name or f"Peer@{req.address}",
        "address": req.address,
        "wan_address": req.wan_address,
        "wg_address": req.wg_address,
        "addresses": addresses,
        "added": datetime.utcnow().isoformat(),
        "status": "pending"
    }
    peers.append(peer)
    save_json(PEERS_FILE, {"peers": peers})
    return {"status": "ok", "peer": peer}


@app.delete("/peers/{peer_id}")
async def remove_peer(peer_id: str, user: dict = Depends(require_jwt)):
    """Remove a peer."""
    init_dirs()
    peers_data = load_json(PEERS_FILE, {"peers": []})
    peers = peers_data.get("peers", []) if isinstance(peers_data, dict) else []

    # Don't allow removing local node
    local_id = get_node_id()
    if peer_id == local_id:
        raise HTTPException(status_code=400, detail="Cannot remove local node")

    original_count = len(peers)
    peers = [p for p in peers if p.get('id') != peer_id]

    if len(peers) == original_count:
        raise HTTPException(status_code=404, detail="Peer not found")

    save_json(PEERS_FILE, {"peers": peers})
    return {"status": "ok", "removed": peer_id}


@app.post("/peers/{peer_id}/probe")
async def probe_peer(peer_id: str, user: dict = Depends(require_jwt)):
    """Probe a peer to check if it's online."""
    init_dirs()
    peers_data = load_json(PEERS_FILE, {"peers": []})
    peers = peers_data.get("peers", []) if isinstance(peers_data, dict) else []

    peer = next((p for p in peers if p.get("id") == peer_id), None)
    if not peer:
        raise HTTPException(status_code=404, detail="Peer not found")

    address = peer.get("address")
    if not address:
        raise HTTPException(status_code=400, detail="Peer has no address")

    # Probe the peer
    try:
        proc = await asyncio.create_subprocess_exec(
            "curl", "-s", "--connect-timeout", "3", "-k",
            f"https://{address}/api/v1/p2p/status",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)

        if proc.returncode == 0:
            try:
                data = json.loads(stdout.decode())
                peer["status"] = "online"
                peer["last_seen"] = datetime.utcnow().isoformat()
                peer["remote_info"] = data
            except:
                peer["status"] = "online"
                peer["last_seen"] = datetime.utcnow().isoformat()
        else:
            peer["status"] = "offline"
    except:
        peer["status"] = "offline"

    save_json(PEERS_FILE, {"peers": peers})
    return {"status": "ok", "peer": peer}


# ============== Services ==============

@app.get("/services")
async def list_services():
    """List all P2P services (public read)."""
    init_dirs()
    services = load_json(SERVICES_FILE, [])
    return {"services": services if isinstance(services, list) else []}


@app.post("/services")
async def register_service(req: ServiceRequest, user: dict = Depends(require_jwt)):
    """Register a P2P service."""
    init_dirs()
    services = load_json(SERVICES_FILE, [])
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
    services = load_json(SERVICES_FILE, [])
    if isinstance(services, list):
        services = [s for s in services if s.get('name') != name]
        save_json(SERVICES_FILE, services)
    return {"status": "ok"}


# ============== Mesh Network ==============

@app.get("/mesh")
async def get_mesh_status():
    """Get mesh network topology (public read)."""
    init_dirs()
    peers_data = load_json(PEERS_FILE, {"peers": []})
    peers = peers_data.get("peers", []) if isinstance(peers_data, dict) else peers_data

    nodes = []
    links = []
    local_id = get_node_id()

    for peer in peers:
        node = {
            "id": peer.get('id', ''),
            "name": peer.get('name', 'Unknown'),
            "address": peer.get('address', ''),
            "status": peer.get('status', 'unknown'),
            "is_local": peer.get('is_local', False) or peer.get('id') == local_id
        }
        nodes.append(node)

        # Create links from local node to all peers
        if not node["is_local"]:
            links.append({
                "source": local_id,
                "target": peer.get('id'),
                "status": peer.get('status', 'unknown')
            })

    return {
        "nodes": nodes,
        "links": links,
        "total_nodes": len(nodes),
        "local_node": local_id
    }


# ============== Profiles ==============

@app.get("/profiles")
async def list_profiles():
    """List P2P profiles."""
    init_dirs()
    profiles = load_json(PROFILES_FILE, {})
    return {"profiles": profiles if isinstance(profiles, dict) else {}}


@app.post("/profiles")
async def create_profile(req: ProfileRequest, user: dict = Depends(require_jwt)):
    """Create a P2P profile."""
    init_dirs()
    profiles = load_json(PROFILES_FILE, {})
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
    profiles = load_json(PROFILES_FILE, {})
    if isinstance(profiles, dict) and name in profiles:
        del profiles[name]
        save_json(PROFILES_FILE, profiles)
    return {"status": "ok"}


# ============== Threat Intelligence ==============

@app.get("/threats")
async def list_threats():
    """List threat intelligence entries (public read)."""
    init_dirs()
    threats = load_json(THREATS_FILE, {})
    return {"threats": threats if isinstance(threats, dict) else {}}


@app.post("/threats")
async def report_threat(req: ThreatRequest, user: dict = Depends(require_jwt)):
    """Report a threat."""
    init_dirs()
    threats = load_json(THREATS_FILE, {})
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
    threats = load_json(THREATS_FILE, {})
    if isinstance(threats, dict) and ip in threats:
        del threats[ip]
        save_json(THREATS_FILE, threats)
    return {"status": "ok"}


# ============== WireGuard Mesh ==============

WG_MESH_CONFIG = P2P_DIR / "wg_mesh.json"
WG_INTERFACE = "wg-mesh"
WG_PORT = 51820
WG_NETWORK = "10.100.0.0/24"


def get_wg_mesh_config() -> Dict:
    """Get WireGuard mesh configuration."""
    default = {
        "enabled": False,
        "interface": WG_INTERFACE,
        "listen_port": WG_PORT,
        "network": WG_NETWORK,
        "private_key": None,
        "public_key": None,
        "peers": []
    }
    return load_json(WG_MESH_CONFIG, default)


def generate_wg_keypair() -> tuple:
    """Generate WireGuard keypair."""
    try:
        priv = subprocess.run(["wg", "genkey"], capture_output=True, text=True, timeout=5)
        private_key = priv.stdout.strip()

        pub = subprocess.run(["wg", "pubkey"], input=private_key, capture_output=True, text=True, timeout=5)
        public_key = pub.stdout.strip()

        return private_key, public_key
    except:
        return None, None


@app.get("/wireguard")
async def get_wireguard_status():
    """Get WireGuard mesh status (public read)."""
    config = get_wg_mesh_config()

    # Get actual interface status
    wg_status = {"running": False, "peers": []}
    try:
        result = subprocess.run(
            ["wg", "show", WG_INTERFACE],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            wg_status["running"] = True
            # Parse peers
            for line in result.stdout.split('\n'):
                if line.startswith('peer:'):
                    wg_status["peers"].append({"public_key": line.split(':')[1].strip()})
    except:
        pass

    return {
        "config": {
            "enabled": config.get("enabled", False),
            "interface": config.get("interface", WG_INTERFACE),
            "listen_port": config.get("listen_port", WG_PORT),
            "network": config.get("network", WG_NETWORK),
            "public_key": config.get("public_key"),
            "peer_count": len(config.get("peers", []))
        },
        "status": wg_status
    }


@app.post("/wireguard/init")
async def init_wireguard(user: dict = Depends(require_jwt)):
    """Initialize WireGuard mesh interface."""
    config = get_wg_mesh_config()

    # Generate keypair if not exists
    if not config.get("private_key"):
        private_key, public_key = generate_wg_keypair()
        if not private_key:
            raise HTTPException(status_code=500, detail="Failed to generate WireGuard keys")
        config["private_key"] = private_key
        config["public_key"] = public_key

    # Assign IP from network (based on node ID)
    node_id = get_node_id()
    ip_suffix = int(hashlib.md5(node_id.encode()).hexdigest()[:2], 16) % 253 + 1
    network_prefix = WG_NETWORK.rsplit('.', 2)[0]
    config["address"] = f"{network_prefix}.{ip_suffix}/24"

    save_json(WG_MESH_CONFIG, config)

    return {
        "status": "ok",
        "public_key": config["public_key"],
        "address": config["address"],
        "listen_port": config.get("listen_port", WG_PORT)
    }


@app.post("/wireguard/peer")
async def add_wireguard_peer(
    public_key: str,
    endpoint: str,
    allowed_ips: str = "10.100.0.0/24",
    user: dict = Depends(require_jwt)
):
    """Add a WireGuard mesh peer."""
    config = get_wg_mesh_config()
    peers = config.get("peers", [])

    # Check if already exists
    if any(p.get("public_key") == public_key for p in peers):
        raise HTTPException(status_code=400, detail="Peer already exists")

    peer = {
        "public_key": public_key,
        "endpoint": endpoint,
        "allowed_ips": allowed_ips,
        "added": datetime.utcnow().isoformat()
    }
    peers.append(peer)
    config["peers"] = peers
    save_json(WG_MESH_CONFIG, config)

    return {"status": "ok", "peer": peer}


@app.post("/wireguard/enable")
async def enable_wireguard(user: dict = Depends(require_jwt)):
    """Enable and start WireGuard mesh interface."""
    config = get_wg_mesh_config()

    if not config.get("private_key"):
        raise HTTPException(status_code=400, detail="WireGuard not initialized")

    # Create interface config
    wg_conf = f"""[Interface]
PrivateKey = {config['private_key']}
Address = {config.get('address', '10.100.0.1/24')}
ListenPort = {config.get('listen_port', WG_PORT)}
"""
    for peer in config.get("peers", []):
        wg_conf += f"""
[Peer]
PublicKey = {peer['public_key']}
Endpoint = {peer['endpoint']}
AllowedIPs = {peer.get('allowed_ips', '10.100.0.0/24')}
PersistentKeepalive = 25
"""

    # Write config and bring up interface
    conf_path = Path(f"/etc/wireguard/{WG_INTERFACE}.conf")
    conf_path.parent.mkdir(parents=True, exist_ok=True)
    conf_path.write_text(wg_conf)
    conf_path.chmod(0o600)

    try:
        subprocess.run(["wg-quick", "down", WG_INTERFACE], capture_output=True, timeout=10)
    except:
        pass

    result = subprocess.run(["wg-quick", "up", WG_INTERFACE], capture_output=True, text=True, timeout=10)
    if result.returncode != 0:
        raise HTTPException(status_code=500, detail=f"Failed to start WireGuard: {result.stderr}")

    config["enabled"] = True
    save_json(WG_MESH_CONFIG, config)

    return {"status": "ok", "message": "WireGuard mesh enabled"}


# ============== Remote Announcers ==============

ANNOUNCERS_FILE = P2P_DIR / "announcers.json"


def get_announcers() -> List[Dict]:
    """Get list of remote announcer servers."""
    return load_json(ANNOUNCERS_FILE, [])


@app.get("/announcers")
async def list_announcers():
    """List remote announcer servers (public read)."""
    announcers = get_announcers()
    return {"announcers": announcers, "count": len(announcers)}


@app.post("/announcers")
async def add_announcer(
    url: str,
    name: Optional[str] = None,
    user: dict = Depends(require_jwt)
):
    """Add a remote announcer server."""
    announcers = get_announcers()

    if any(a.get("url") == url for a in announcers):
        raise HTTPException(status_code=400, detail="Announcer already exists")

    announcer = {
        "id": hashlib.md5(url.encode()).hexdigest()[:12],
        "url": url,
        "name": name or url,
        "added": datetime.utcnow().isoformat(),
        "status": "unknown",
        "last_sync": None
    }
    announcers.append(announcer)
    save_json(ANNOUNCERS_FILE, announcers)

    return {"status": "ok", "announcer": announcer}


@app.delete("/announcers/{announcer_id}")
async def remove_announcer(announcer_id: str, user: dict = Depends(require_jwt)):
    """Remove an announcer server."""
    announcers = get_announcers()
    announcers = [a for a in announcers if a.get("id") != announcer_id]
    save_json(ANNOUNCERS_FILE, announcers)
    return {"status": "ok"}


@app.post("/announcers/sync")
async def sync_with_announcers(user: dict = Depends(require_jwt)):
    """Sync peer list with all remote announcers."""
    announcers = get_announcers()
    results = []
    all_remote_peers = []

    for announcer in announcers:
        url = announcer.get("url", "").rstrip('/')
        try:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-s", "--connect-timeout", "5", "-k",
                f"{url}/api/v1/p2p/peers",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)

            if proc.returncode == 0:
                data = json.loads(stdout.decode())
                peers = data.get("peers", [])
                announcer["status"] = "online"
                announcer["last_sync"] = datetime.utcnow().isoformat()
                announcer["peer_count"] = len(peers)

                # Add remote peers (exclude local nodes)
                for peer in peers:
                    if not peer.get("is_local"):
                        peer["discovered_via"] = f"announcer:{announcer['id']}"
                        peer["announcer_url"] = url
                        all_remote_peers.append(peer)

                results.append({"announcer": announcer["url"], "status": "ok", "peers": len(peers)})
            else:
                announcer["status"] = "error"
                results.append({"announcer": announcer["url"], "status": "error"})
        except Exception as e:
            announcer["status"] = "error"
            results.append({"announcer": announcer["url"], "status": "error", "error": str(e)})

    save_json(ANNOUNCERS_FILE, announcers)

    # Merge remote peers with local peers
    if all_remote_peers:
        peers_data = load_json(PEERS_FILE, {"peers": []})
        peers = peers_data.get("peers", []) if isinstance(peers_data, dict) else []
        existing_addrs = {p.get("address") for p in peers}

        added = 0
        for peer in all_remote_peers:
            if peer.get("address") and peer["address"] not in existing_addrs:
                peers.append(peer)
                existing_addrs.add(peer["address"])
                added += 1

        if added > 0:
            save_json(PEERS_FILE, {"peers": peers})

        results.append({"merged": added, "total_remote_peers": len(all_remote_peers)})

    return {"status": "ok", "results": results}


@app.post("/announce")
async def announce_self(user: dict = Depends(require_jwt)):
    """Announce local node to all remote announcers."""
    announcers = get_announcers()
    self_peer = get_self_peer()
    results = []

    for announcer in announcers:
        url = announcer.get("url", "").rstrip('/')
        try:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-s", "--connect-timeout", "5", "-k",
                "-X", "POST",
                "-H", "Content-Type: application/json",
                "-d", json.dumps({
                    "address": self_peer["address"],
                    "name": self_peer["name"],
                    "wan_address": self_peer.get("wan_address"),
                    "wg_address": self_peer.get("wg_addresses", [None])[0] if self_peer.get("wg_addresses") else None
                }),
                f"{url}/api/v1/p2p/peers",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)

            if proc.returncode == 0:
                results.append({"announcer": url, "status": "ok"})
            else:
                results.append({"announcer": url, "status": "error"})
        except Exception as e:
            results.append({"announcer": url, "status": "error", "error": str(e)})

    return {"status": "ok", "results": results}


# ============== Bridge Discovery ==============

@app.post("/discover/bridge")
async def discover_via_bridge(
    bridge_peer: str,
    user: dict = Depends(require_jwt)
):
    """Discover peers through a bridge peer (multi-hop discovery)."""
    # Query the bridge peer for its known peers
    try:
        proc = await asyncio.create_subprocess_exec(
            "curl", "-s", "--connect-timeout", "5", "-k",
            f"https://{bridge_peer}/api/v1/p2p/peers",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)

        if proc.returncode != 0:
            raise HTTPException(status_code=502, detail="Failed to reach bridge peer")

        data = json.loads(stdout.decode())
        remote_peers = data.get("peers", [])

        # Mark as discovered via bridge
        for peer in remote_peers:
            peer["discovered_via"] = f"bridge:{bridge_peer}"
            peer["bridge_peer"] = bridge_peer

        # Optionally add to local peer list
        peers_data = load_json(PEERS_FILE, {"peers": []})
        peers = peers_data.get("peers", []) if isinstance(peers_data, dict) else []
        existing_addrs = {p.get("address") for p in peers}

        added = 0
        for peer in remote_peers:
            if peer.get("address") and peer["address"] not in existing_addrs and not peer.get("is_local"):
                peers.append(peer)
                existing_addrs.add(peer["address"])
                added += 1

        if added > 0:
            save_json(PEERS_FILE, {"peers": peers})

        return {
            "status": "ok",
            "bridge_peer": bridge_peer,
            "discovered": len(remote_peers),
            "added": added,
            "peers": remote_peers
        }
    except json.JSONDecodeError:
        raise HTTPException(status_code=502, detail="Invalid response from bridge peer")
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Bridge peer timeout")


# ============== Master-Link ==============

@app.get("/master-link/status")
async def ml_status():
    """Get master-link status (public read)."""
    config = get_ml_config()
    requests = get_ml_requests()
    tokens = get_ml_tokens()

    # Count by status
    pending = sum(1 for r in requests if r.get("status") == "pending")
    approved = sum(1 for r in requests if r.get("status") == "approved")
    rejected = sum(1 for r in requests if r.get("status") == "rejected")

    # Count active tokens
    now = datetime.utcnow().timestamp()
    active_tokens = sum(1 for t in tokens
                       if t.get("status") == "active" and t.get("expires_ts", 0) > now)

    return {
        "enabled": config.get("enabled", True),
        "role": config.get("role", "master"),
        "depth": config.get("depth", 0),
        "max_depth": config.get("max_depth", ML_DEFAULT_MAX_DEPTH),
        "upstream": config.get("upstream"),
        "fingerprint": config.get("fingerprint", get_node_id()),
        "hostname": get_hostname(),
        "auto_approve": config.get("auto_approve", False),
        "peers": {
            "pending": pending,
            "approved": approved,
            "rejected": rejected,
            "total": len(requests)
        },
        "active_tokens": active_tokens
    }


@app.post("/master-link/token")
async def ml_generate_token(req: TokenGenerateRequest, user: dict = Depends(require_jwt)):
    """Generate a join token (auth required)."""
    config = get_ml_config()

    # Only master or sub-master can generate tokens
    role = config.get("role", "master")
    if role not in ["master", "sub-master"]:
        raise HTTPException(status_code=403, detail="Only master or sub-master nodes can generate tokens")

    result = ml_token_generate(
        ttl=req.ttl,
        token_type=req.token_type,
        auto_approve=req.auto_approve
    )
    return result


@app.post("/master-link/invite")
async def ml_generate_invite(
    ttl: int = 3600,
    auto_approve: bool = True,
    user: dict = Depends(require_jwt)
):
    """Generate a shareable invite URL (simplified flow)."""
    config = get_ml_config()
    role = config.get("role", "master")
    if role not in ["master", "sub-master"]:
        raise HTTPException(status_code=403, detail="Only master or sub-master can invite")

    # Generate token
    result = ml_token_generate(ttl=ttl, auto_approve=auto_approve)
    token = result["token"]

    # Build URLs
    lan_ip = get_lan_ip()
    wan_ip = get_wan_ip()
    hostname = get_hostname()
    fingerprint = config.get("fingerprint", get_node_id())

    # Web URL for browser
    web_url = f"https://{lan_ip}/master-link/?token={token}"

    # CLI one-liner for OpenWRT/Linux
    cli_cmd = f"wget -qO- 'http://{lan_ip}:{API_PORT}/api/v1/p2p/master-link/join-script?token={token}' | sh"

    return {
        "token": token,
        "expires": result["expires"],
        "auto_approve": auto_approve,
        "master": {
            "fingerprint": fingerprint,
            "hostname": hostname,
            "lan_ip": lan_ip,
            "wan_ip": wan_ip,
            "role": role,
            "depth": config.get("depth", 0)
        },
        "urls": {
            "web": web_url,
            "web_wan": f"https://{wan_ip}/master-link/?token={token}" if wan_ip else None,
            "api": f"http://{lan_ip}:{API_PORT}/api/v1/p2p/master-link/join"
        },
        "cli": {
            "command": cli_cmd,
            "curl": f"curl -s 'http://{lan_ip}:{API_PORT}/api/v1/p2p/master-link/join-script?token={token}' | sh"
        },
        "copy_paste": f"""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  SecuBox Mesh Invite - {hostname}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Option 1 - Web Browser:
  {web_url}

Option 2 - Command Line (OpenWRT/Linux):
  {cli_cmd}

Token: {token}
Expires: {result['expires']}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
    }


@app.get("/master-link/join-script")
async def ml_join_script(token: str, request: Request):
    """Return a shell script for joining (OpenWRT compatible)."""
    from fastapi.responses import PlainTextResponse

    # Get master info
    config = get_ml_config()
    master_ip = get_lan_ip()
    master_fp = config.get("fingerprint", get_node_id())
    master_hostname = get_hostname()

    script = f'''#!/bin/sh
# SecuBox Mesh Join Script
# Master: {master_hostname} ({master_fp})
# Generated: {datetime.utcnow().isoformat()}

set -e

MASTER_IP="{master_ip}"
MASTER_PORT="{API_PORT}"
TOKEN="{token}"

# Detect system type
if [ -f /etc/openwrt_release ]; then
    SYSTEM="openwrt"
    # Get fingerprint from OpenWRT
    if [ -f /etc/secubox/node.id ]; then
        FINGERPRINT=$(cat /etc/secubox/node.id)
    else
        FINGERPRINT="owrt-$(cat /sys/class/net/br-lan/address 2>/dev/null | tr -d ':' || echo $RANDOM)"
        mkdir -p /etc/secubox
        echo "$FINGERPRINT" > /etc/secubox/node.id
    fi
    HOSTNAME=$(uci get system.@system[0].hostname 2>/dev/null || hostname)
    ADDRESS=$(ip -4 addr show br-lan 2>/dev/null | grep -oP 'inet \\K[\\d.]+' | head -1)
    [ -z "$ADDRESS" ] && ADDRESS=$(ip route get 1 | grep -oP 'src \\K[\\d.]+')
else
    SYSTEM="linux"
    if [ -f /var/lib/secubox/p2p/node.id ]; then
        FINGERPRINT=$(cat /var/lib/secubox/p2p/node.id)
    else
        FINGERPRINT="sbx-$(cat /sys/class/net/eth0/address 2>/dev/null | tr -d ':' || hostname | md5sum | cut -c1-12)"
    fi
    HOSTNAME=$(hostname)
    ADDRESS=$(ip route get 1 2>/dev/null | grep -oP 'src \\K[\\d.]+' || echo "unknown")
fi

echo "╔══════════════════════════════════════════╗"
echo "║     SecuBox Mesh - Joining Network       ║"
echo "╠══════════════════════════════════════════╣"
echo "║ System:      $SYSTEM"
echo "║ Fingerprint: $FINGERPRINT"
echo "║ Hostname:    $HOSTNAME"
echo "║ Address:     $ADDRESS"
echo "║ Master:      $MASTER_IP"
echo "╚══════════════════════════════════════════╝"
echo ""

# Use wget (OpenWRT) or curl (Debian)
if command -v curl >/dev/null 2>&1; then
    RESPONSE=$(curl -s -X POST \\
        -H "Content-Type: application/json" \\
        -d "{{\\"token\\":\\"$TOKEN\\",\\"fingerprint\\":\\"$FINGERPRINT\\",\\"hostname\\":\\"$HOSTNAME\\",\\"address\\":\\"$ADDRESS\\"}}" \\
        "http://$MASTER_IP:$MASTER_PORT/api/v1/p2p/master-link/join")
elif command -v wget >/dev/null 2>&1; then
    RESPONSE=$(wget -qO- --post-data="{{\\"token\\":\\"$TOKEN\\",\\"fingerprint\\":\\"$FINGERPRINT\\",\\"hostname\\":\\"$HOSTNAME\\",\\"address\\":\\"$ADDRESS\\"}}" \\
        --header="Content-Type: application/json" \\
        "http://$MASTER_IP:$MASTER_PORT/api/v1/p2p/master-link/join" 2>/dev/null)
else
    echo "ERROR: Neither curl nor wget available"
    exit 1
fi

# Parse response
STATUS=$(echo "$RESPONSE" | grep -o '"status":"[^"]*"' | cut -d'"' -f4)

if [ "$STATUS" = "approved" ]; then
    echo "✓ SUCCESS: Joined mesh network!"
    echo "  Status: APPROVED"
    DEPTH=$(echo "$RESPONSE" | grep -o '"depth":[0-9]*' | cut -d':' -f2)
    [ -n "$DEPTH" ] && echo "  Depth: $DEPTH"

    # Save master info for OpenWRT
    if [ "$SYSTEM" = "openwrt" ]; then
        mkdir -p /etc/secubox
        echo "$MASTER_IP" > /etc/secubox/master.ip
        echo "$FINGERPRINT" > /etc/secubox/node.id
    fi
elif [ "$STATUS" = "pending" ]; then
    echo "⏳ PENDING: Waiting for master approval"
    echo "  Your fingerprint: $FINGERPRINT"
    echo "  Check back later or ask the master admin to approve."
else
    echo "✗ FAILED: $RESPONSE"
    exit 1
fi
'''
    return PlainTextResponse(content=script, media_type="text/plain")


@app.post("/master-link/token/validate")
async def ml_validate_token(token: str):
    """Validate a token (public)."""
    return ml_token_validate(token)


@app.post("/master-link/token/revoke")
async def ml_revoke_token(token: str, user: dict = Depends(require_jwt)):
    """Revoke a token."""
    token_hash = hash_token(token)
    tokens = get_ml_tokens()

    for t in tokens:
        if t.get("hash") == token_hash:
            t["status"] = "revoked"
            save_ml_tokens(tokens)
            return {"status": "ok", "revoked": token_hash}

    raise HTTPException(status_code=404, detail="Token not found")


@app.post("/master-link/token/cleanup")
async def ml_cleanup(user: dict = Depends(require_jwt)):
    """Cleanup expired tokens."""
    return ml_cleanup_tokens()


@app.post("/master-link/join")
async def ml_join(req: JoinRequest, request: Request):
    """Handle join request from new node (token validated)."""
    # Validate token
    validation = ml_token_validate(req.token)
    if not validation.get("valid"):
        raise HTTPException(status_code=403, detail=validation.get("error", "Invalid token"))

    token_hash = validation.get("token_hash")
    auto_approve = validation.get("auto_approve", False)

    # Get peer address from request if not provided
    peer_address = req.address
    if not peer_address:
        peer_address = request.client.host if request.client else "unknown"

    # Get config
    config = get_ml_config()
    my_depth = config.get("depth", 0)
    peer_depth = my_depth + 1

    # Store join request
    requests = get_ml_requests()
    now = datetime.utcnow()

    # Check if already exists
    existing = next((r for r in requests if r.get("fingerprint") == req.fingerprint), None)
    if existing:
        if existing.get("status") == "approved":
            return {
                "status": "approved",
                "fingerprint": req.fingerprint,
                "message": "Already approved"
            }
        elif existing.get("status") == "pending":
            return {
                "status": "pending",
                "fingerprint": req.fingerprint,
                "message": "Join request already pending"
            }

    join_request = {
        "fingerprint": req.fingerprint,
        "address": peer_address,
        "hostname": req.hostname or "unknown",
        "token_hash": token_hash,
        "timestamp": now.isoformat(),
        "status": "pending"
    }

    # Check global auto-approve or token auto-approve
    global_auto = config.get("auto_approve", False)
    if auto_approve or global_auto:
        # Auto-approve
        join_request["status"] = "approved"
        join_request["approved_at"] = now.isoformat()
        join_request["approved_by"] = config.get("fingerprint", get_node_id())
        join_request["depth"] = peer_depth

        # Mark token as used
        ml_token_mark_used(token_hash, req.fingerprint)

        # Add to peers
        _add_approved_peer(join_request)

        requests.append(join_request)
        save_ml_requests(requests)

        return {
            "success": True,
            "status": "approved",
            "fingerprint": req.fingerprint,
            "depth": peer_depth,
            "message": "Auto-approved"
        }

    # Manual approval required
    requests.append(join_request)
    save_ml_requests(requests)

    return {
        "success": True,
        "status": "pending",
        "fingerprint": req.fingerprint,
        "message": "Join request queued for approval"
    }


def _add_approved_peer(join_request: Dict):
    """Add approved peer to peer list."""
    peers_data = load_json(PEERS_FILE, {"peers": []})
    peers = peers_data.get("peers", []) if isinstance(peers_data, dict) else []

    peer_id = f"sb-{hashlib.md5(join_request['fingerprint'].encode()).hexdigest()[:12]}"

    # Check if already exists
    if any(p.get("id") == peer_id for p in peers):
        return

    peer = {
        "id": peer_id,
        "fingerprint": join_request["fingerprint"],
        "name": join_request.get("hostname", "Peer"),
        "address": join_request.get("address"),
        "depth": join_request.get("depth", 1),
        "role": join_request.get("role", "peer"),
        "added": datetime.utcnow().isoformat(),
        "joined_via": "master-link",
        "status": "online"
    }
    peers.append(peer)
    save_json(PEERS_FILE, {"peers": peers})


@app.post("/master-link/approve")
async def ml_approve(req: ApproveRequest, user: dict = Depends(require_jwt)):
    """Approve, reject, or promote a peer (auth required)."""
    requests = get_ml_requests()
    config = get_ml_config()
    now = datetime.utcnow()

    # Find the request
    join_request = next((r for r in requests if r.get("fingerprint") == req.fingerprint), None)
    if not join_request:
        raise HTTPException(status_code=404, detail="No pending request for this fingerprint")

    my_fp = config.get("fingerprint", get_node_id())
    my_depth = config.get("depth", 0)

    if req.action == "approve":
        if join_request.get("status") == "approved":
            return {"status": "already_approved", "fingerprint": req.fingerprint}

        peer_depth = my_depth + 1
        join_request["status"] = "approved"
        join_request["approved_at"] = now.isoformat()
        join_request["approved_by"] = my_fp
        join_request["depth"] = peer_depth

        # Mark token as used
        token_hash = join_request.get("token_hash")
        if token_hash:
            ml_token_mark_used(token_hash, req.fingerprint)

        # Add to peers
        _add_approved_peer(join_request)

        save_ml_requests(requests)

        return {
            "success": True,
            "fingerprint": req.fingerprint,
            "address": join_request.get("address"),
            "hostname": join_request.get("hostname"),
            "depth": peer_depth,
            "status": "approved"
        }

    elif req.action == "reject":
        join_request["status"] = "rejected"
        join_request["rejected_at"] = now.isoformat()
        join_request["rejected_by"] = my_fp
        join_request["reason"] = req.reason or "Rejected by admin"

        save_ml_requests(requests)

        return {
            "success": True,
            "fingerprint": req.fingerprint,
            "status": "rejected"
        }

    elif req.action == "promote":
        if join_request.get("status") != "approved":
            raise HTTPException(status_code=400, detail="Can only promote approved peers")

        # Check depth limit
        max_depth = config.get("max_depth", ML_DEFAULT_MAX_DEPTH)
        current_depth = join_request.get("depth", my_depth + 1)
        if current_depth >= max_depth:
            raise HTTPException(status_code=400, detail=f"Max depth ({max_depth}) reached")

        join_request["role"] = "sub-master"
        join_request["promoted_at"] = now.isoformat()
        join_request["promoted_by"] = my_fp

        save_ml_requests(requests)

        # Notify peer of promotion (background)
        peer_addr = join_request.get("address")
        if peer_addr:
            asyncio.create_task(_notify_peer_promotion(peer_addr, current_depth))

        return {
            "success": True,
            "fingerprint": req.fingerprint,
            "new_role": "sub-master",
            "depth": current_depth
        }

    else:
        raise HTTPException(status_code=400, detail=f"Invalid action: {req.action}")


async def _notify_peer_promotion(peer_addr: str, depth: int):
    """Notify a peer that they've been promoted."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "curl", "-s", "--connect-timeout", "5", "-k",
            "-X", "POST",
            "-H", "Content-Type: application/json",
            "-d", json.dumps({"action": "promote", "role": "sub-master", "depth": depth}),
            f"https://{peer_addr}/api/v1/p2p/master-link/status",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await asyncio.wait_for(proc.communicate(), timeout=10)
    except:
        pass  # Best effort


@app.get("/master-link/peers")
async def ml_list_peers():
    """List all join requests and their status (public read)."""
    requests = get_ml_requests()
    return {"peers": requests, "count": len(requests)}


@app.get("/master-link/tree")
async def ml_tree():
    """Get mesh hierarchy tree (public read)."""
    config = get_ml_config()
    requests = get_ml_requests()

    # Build tree starting from self
    my_fp = config.get("fingerprint", get_node_id())

    root = {
        "fingerprint": my_fp,
        "hostname": get_hostname(),
        "role": config.get("role", "master"),
        "depth": config.get("depth", 0),
        "address": get_lan_ip(),
        "children": []
    }

    # Add approved peers as children
    for req in requests:
        if req.get("status") == "approved":
            child = {
                "fingerprint": req.get("fingerprint"),
                "hostname": req.get("hostname", "unknown"),
                "address": req.get("address"),
                "role": req.get("role", "peer"),
                "depth": req.get("depth", root["depth"] + 1),
                "approved_at": req.get("approved_at"),
                "children": []  # Would need recursive fetch for sub-master children
            }
            root["children"].append(child)

    return {"tree": root}


@app.get("/master-link/config")
async def ml_get_config(user: dict = Depends(require_jwt)):
    """Get full master-link configuration (auth required)."""
    return get_ml_config()


@app.post("/master-link/config")
async def ml_set_config(
    role: Optional[str] = None,
    upstream: Optional[str] = None,
    depth: Optional[int] = None,
    max_depth: Optional[int] = None,
    auto_approve: Optional[bool] = None,
    token_ttl: Optional[int] = None,
    user: dict = Depends(require_jwt)
):
    """Update master-link configuration (auth required)."""
    config = get_ml_config()

    if role is not None:
        if role not in ["master", "sub-master", "peer"]:
            raise HTTPException(status_code=400, detail="Invalid role")
        config["role"] = role

    if upstream is not None:
        config["upstream"] = upstream

    if depth is not None:
        config["depth"] = depth

    if max_depth is not None:
        config["max_depth"] = max_depth

    if auto_approve is not None:
        config["auto_approve"] = auto_approve

    if token_ttl is not None:
        config["token_ttl"] = token_ttl

    save_ml_config(config)
    return {"status": "ok", "config": config}


@app.post("/master-link/join-with-token")
async def ml_join_upstream(
    master_addr: str,
    token: str,
    user: dict = Depends(require_jwt)
):
    """Join a mesh as peer using a token (peer-side operation)."""
    my_fp = get_node_id()
    my_hostname = get_hostname()
    my_addr = get_lan_ip()

    # Send join request to master
    try:
        proc = await asyncio.create_subprocess_exec(
            "curl", "-s", "--connect-timeout", "10", "-k",
            "-X", "POST",
            "-H", "Content-Type: application/json",
            "-d", json.dumps({
                "token": token,
                "fingerprint": my_fp,
                "hostname": my_hostname,
                "address": my_addr
            }),
            f"http://{master_addr}:{API_PORT}/api/v1/p2p/master-link/join",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)

        if proc.returncode != 0:
            raise HTTPException(status_code=502, detail="Failed to reach master")

        result = json.loads(stdout.decode())

        # If approved, update local config
        if result.get("status") == "approved":
            config = get_ml_config()
            config["role"] = "peer"
            config["upstream"] = master_addr
            config["depth"] = result.get("depth", 1)
            save_ml_config(config)

        return result

    except json.JSONDecodeError:
        raise HTTPException(status_code=502, detail="Invalid response from master")
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Master timeout")


# ============== Health ==============

@app.get("/health")
async def health():
    return {"status": "ok", "service": "secubox-p2p", "version": "1.3.0"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
