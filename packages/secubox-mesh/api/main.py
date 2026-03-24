"""
SecuBox Mesh DNS API

FastAPI backend for Meshname DNS management for Yggdrasil mesh networks.
"""

import json
import subprocess
import time
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel

app = FastAPI(
    title="SecuBox Mesh DNS API",
    description="Meshname DNS management for Yggdrasil mesh networks",
    version="1.0.0"
)

# Configuration
CONFIG_PATH = Path("/etc/secubox/mesh.toml")
DATA_PATH = Path("/var/lib/secubox/mesh")
SERVICES_FILE = DATA_PATH / "services.json"
DOMAINS_FILE = DATA_PATH / "domains.json"


class ServiceAnnounce(BaseModel):
    name: str
    type: str
    port: int


class ServiceRevoke(BaseModel):
    name: str


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
        "ipv6": None
    }

    try:
        # Check if yggdrasil is running
        result = subprocess.run(
            ["systemctl", "is-active", "yggdrasil"],
            capture_output=True,
            text=True
        )
        info["running"] = result.returncode == 0

        if info["running"]:
            # Get Yggdrasil address
            result = subprocess.run(
                ["yggdrasilctl", "-json", "getSelf"],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                data = json.loads(result.stdout)
                info["ipv6"] = data.get("address") or data.get("Address")
    except (subprocess.SubprocessError, json.JSONDecodeError, FileNotFoundError):
        pass

    return info


def ipv6_to_meshname(ipv6: str) -> str:
    """Convert Yggdrasil IPv6 to meshname domain."""
    # This is a simplified implementation
    # Real implementation would use proper base32 encoding
    if not ipv6:
        return ""

    # Remove colons and convert to lowercase
    clean = ipv6.replace(":", "").lower()
    # Use first 16 characters for a short meshname
    short = clean[:16]
    return f"{short}.meshname"


@app.get("/status")
async def get_status():
    """Get mesh DNS status."""
    ygg_info = get_yggdrasil_info()
    services = load_json(SERVICES_FILE, {"services": []})
    domains = load_json(DOMAINS_FILE, {"domains": [], "last_sync": None})

    # Check if mesh DNS service is running
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
        "yggdrasil_running": ygg_info["running"],
        "yggdrasil_ipv6": ygg_info["ipv6"],
        "mesh_dns_running": mesh_running,
        "sync_status": "Idle",
        "local_services_count": len(services.get("services", [])),
        "remote_domains_count": len(domains.get("domains", [])),
        "last_sync": domains.get("last_sync")
    }


@app.get("/services")
async def get_services():
    """Get local announced services."""
    data = load_json(SERVICES_FILE, {"services": []})
    ygg_info = get_yggdrasil_info()

    # Add meshname to each service
    for service in data.get("services", []):
        if ygg_info["ipv6"]:
            service["meshname"] = f"{service['name']}.{ipv6_to_meshname(ygg_info['ipv6'])}"
        else:
            service["meshname"] = None

    return data


@app.post("/announce")
async def announce_service(service: ServiceAnnounce):
    """Announce a service to the mesh network."""
    data = load_json(SERVICES_FILE, {"services": []})

    # Check if service already exists
    for existing in data["services"]:
        if existing["name"] == service.name:
            raise HTTPException(status_code=400, detail="Service already exists")

    # Add new service
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
async def revoke_service(service: ServiceRevoke):
    """Revoke a service from the mesh network."""
    data = load_json(SERVICES_FILE, {"services": []})

    # Find and remove service
    found = False
    data["services"] = [s for s in data["services"] if s["name"] != service.name or not (found := True)]

    if not found:
        raise HTTPException(status_code=404, detail="Service not found")

    save_json(SERVICES_FILE, data)
    return {"status": "success"}


@app.get("/domains")
async def get_domains():
    """Get discovered remote domains."""
    data = load_json(DOMAINS_FILE, {"domains": [], "last_sync": None})
    return data


@app.post("/sync")
async def sync_domains():
    """Sync domains from the mesh network."""
    # In a real implementation, this would query peers for their services
    # For now, we just update the timestamp
    data = load_json(DOMAINS_FILE, {"domains": []})
    data["last_sync"] = int(time.time())
    save_json(DOMAINS_FILE, data)

    return {"status": "success", "domains_count": len(data.get("domains", []))}


@app.get("/resolve")
async def resolve_domain(domain: str = Query(..., description="Meshname domain to resolve")):
    """Resolve a meshname domain to IPv6."""
    if not domain:
        raise HTTPException(status_code=400, detail="Domain is required")

    # Check local cache first
    data = load_json(DOMAINS_FILE, {"domains": []})
    for d in data.get("domains", []):
        if d["name"] == domain:
            return {
                "domain": domain,
                "ipv6": d["ipv6"],
                "type": d.get("type", "unknown"),
                "source": "cache"
            }

    # In a real implementation, this would query the mesh network
    # For demo purposes, return not found
    raise HTTPException(status_code=404, detail="Domain not found")


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "secubox-mesh"}
