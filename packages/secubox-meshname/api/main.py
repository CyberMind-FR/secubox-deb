"""SecuBox Meshname API - Mesh Network Domain Resolution"""
import asyncio
import subprocess
import os
import json
import re
from pathlib import Path
from datetime import datetime
from typing import Optional
from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel
from secubox_core.auth import require_jwt
from secubox_core.config import get_config

app = FastAPI(title="SecuBox Meshname")
config = get_config("meshname")

# Configuration paths
CONFIG_DIR = "/etc/secubox/meshname"
STATE_FILE = "/var/lib/secubox/meshname/state.json"
HOSTS_FILE = "/etc/hosts"
DNSMASQ_MESH_CONF = "/etc/dnsmasq.d/meshname.conf"
AVAHI_SERVICES_DIR = "/etc/avahi/services"

# Ensure directories exist
Path(CONFIG_DIR).mkdir(parents=True, exist_ok=True)
Path("/var/lib/secubox/meshname").mkdir(parents=True, exist_ok=True)


class MeshNode(BaseModel):
    name: str
    ip: str
    domain: Optional[str] = None
    services: list[str] = []


class DomainMapping(BaseModel):
    hostname: str
    ip: str
    ttl: int = 300


class MeshConfig(BaseModel):
    enabled: bool = True
    mesh_domain: str = "mesh.local"
    publish_mdns: bool = True
    auto_discover: bool = True


def _load_state() -> dict:
    """Load module state."""
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, 'r') as f:
                return json.load(f)
        except Exception:
            pass
    return {
        "enabled": False,
        "mesh_domain": "mesh.local",
        "nodes": [],
        "mappings": [],
        "publish_mdns": True,
        "auto_discover": True
    }


def _save_state(state: dict):
    """Save module state."""
    try:
        with open(STATE_FILE, 'w') as f:
            json.dump(state, f, indent=2)
    except Exception:
        pass


def _check_avahi_available() -> bool:
    """Check if Avahi is available."""
    try:
        result = subprocess.run(
            ["systemctl", "is-active", "avahi-daemon"],
            capture_output=True, text=True, timeout=5
        )
        return result.stdout.strip() == "active"
    except Exception:
        return False


def _check_dnsmasq_available() -> bool:
    """Check if dnsmasq is available."""
    try:
        result = subprocess.run(
            ["systemctl", "is-active", "dnsmasq"],
            capture_output=True, text=True, timeout=5
        )
        return result.stdout.strip() == "active"
    except Exception:
        return False


def _discover_mdns_hosts() -> list[dict]:
    """Discover mDNS hosts on the network."""
    hosts = []
    try:
        # Use avahi-browse to discover hosts
        result = subprocess.run(
            ["avahi-browse", "-atrp", "--no-db-lookup"],
            capture_output=True, text=True, timeout=30
        )

        for line in result.stdout.split('\n'):
            if line.startswith('='):
                # Format: =;interface;protocol;name;type;domain;hostname;ip;port;txt
                parts = line.split(';')
                if len(parts) >= 8:
                    hosts.append({
                        "name": parts[3],
                        "type": parts[4],
                        "hostname": parts[6],
                        "ip": parts[7],
                        "port": parts[8] if len(parts) > 8 else ""
                    })
    except Exception:
        pass

    return hosts


def _get_local_hostname() -> str:
    """Get local hostname."""
    try:
        return subprocess.run(
            ["hostname"],
            capture_output=True, text=True, timeout=5
        ).stdout.strip()
    except Exception:
        return "secubox"


def _get_local_ips() -> list[str]:
    """Get local IP addresses."""
    ips = []
    try:
        result = subprocess.run(
            ["hostname", "-I"],
            capture_output=True, text=True, timeout=5
        )
        ips = result.stdout.strip().split()
    except Exception:
        pass
    return ips


def _generate_dnsmasq_config(state: dict) -> str:
    """Generate dnsmasq configuration for mesh DNS."""
    lines = [
        "# Meshname DNS Configuration - Auto-generated",
        f"# Mesh domain: {state.get('mesh_domain', 'mesh.local')}",
        "",
    ]

    mesh_domain = state.get("mesh_domain", "mesh.local")

    # Add domain authority
    lines.append(f"domain={mesh_domain}")
    lines.append(f"local=/{mesh_domain}/")
    lines.append("")

    # Add node mappings
    for node in state.get("nodes", []):
        hostname = node.get("name", "")
        ip = node.get("ip", "")
        if hostname and ip:
            fqdn = f"{hostname}.{mesh_domain}"
            lines.append(f"address=/{fqdn}/{ip}")

    # Add custom mappings
    for mapping in state.get("mappings", []):
        hostname = mapping.get("hostname", "")
        ip = mapping.get("ip", "")
        if hostname and ip:
            lines.append(f"address=/{hostname}/{ip}")

    return '\n'.join(lines)


def _apply_dnsmasq_config(config_content: str):
    """Apply dnsmasq configuration."""
    try:
        with open(DNSMASQ_MESH_CONF, 'w') as f:
            f.write(config_content)

        # Reload dnsmasq
        subprocess.run(
            ["systemctl", "reload", "dnsmasq"],
            capture_output=True, timeout=10
        )
        return True
    except Exception:
        return False


def _create_avahi_service(name: str, type: str, port: int, txt: list[str] = None) -> str:
    """Create Avahi service definition XML."""
    txt_records = ""
    if txt:
        txt_records = "\n".join([f"      <txt-record>{t}</txt-record>" for t in txt])

    return f"""<?xml version="1.0" standalone='no'?>
<!DOCTYPE service-group SYSTEM "avahi-service.dtd">
<service-group>
  <name replace-wildcards="yes">{name}</name>
  <service>
    <type>{type}</type>
    <port>{port}</port>
{txt_records}
  </service>
</service-group>
"""


def _publish_avahi_service(name: str, service_type: str, port: int):
    """Publish a service via Avahi."""
    try:
        service_file = os.path.join(AVAHI_SERVICES_DIR, f"secubox-{name}.service")
        content = _create_avahi_service(name, service_type, port)
        with open(service_file, 'w') as f:
            f.write(content)
        return True
    except Exception:
        return False


@app.get("/status")
async def status():
    """Public status endpoint."""
    return {
        "module": "meshname",
        "status": "ok",
        "version": "1.0.0"
    }


@app.get("/service", dependencies=[Depends(require_jwt)])
async def get_service_status():
    """Get mesh DNS service status."""
    state = _load_state()

    return {
        "enabled": state.get("enabled", False),
        "mesh_domain": state.get("mesh_domain", "mesh.local"),
        "avahi_available": _check_avahi_available(),
        "dnsmasq_available": _check_dnsmasq_available(),
        "nodes_count": len(state.get("nodes", [])),
        "mappings_count": len(state.get("mappings", [])),
        "local_hostname": _get_local_hostname(),
        "local_ips": _get_local_ips()
    }


@app.post("/enable", dependencies=[Depends(require_jwt)])
async def enable_meshname(enabled: bool = True):
    """Enable or disable mesh DNS."""
    state = _load_state()
    state["enabled"] = enabled
    _save_state(state)

    if enabled:
        # Apply dnsmasq configuration
        config_content = _generate_dnsmasq_config(state)
        _apply_dnsmasq_config(config_content)
    else:
        # Remove dnsmasq config
        if os.path.exists(DNSMASQ_MESH_CONF):
            os.remove(DNSMASQ_MESH_CONF)
            subprocess.run(["systemctl", "reload", "dnsmasq"], capture_output=True, timeout=10)

    return {"success": True, "enabled": enabled}


@app.get("/nodes", dependencies=[Depends(require_jwt)])
async def get_nodes():
    """Get registered mesh nodes."""
    state = _load_state()
    return {"nodes": state.get("nodes", []), "mesh_domain": state.get("mesh_domain", "mesh.local")}


@app.post("/nodes", dependencies=[Depends(require_jwt)])
async def add_node(node: MeshNode):
    """Add a mesh node."""
    state = _load_state()

    # Validate IP
    if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', node.ip):
        raise HTTPException(status_code=400, detail="Invalid IP address")

    # Remove existing node with same name
    state["nodes"] = [n for n in state.get("nodes", []) if n["name"] != node.name]

    state.setdefault("nodes", []).append({
        "name": node.name,
        "ip": node.ip,
        "domain": node.domain or f"{node.name}.{state.get('mesh_domain', 'mesh.local')}",
        "services": node.services,
        "added": datetime.now().isoformat()
    })
    _save_state(state)

    # Update dnsmasq if enabled
    if state.get("enabled", False):
        config_content = _generate_dnsmasq_config(state)
        _apply_dnsmasq_config(config_content)

    return {"success": True, "name": node.name}


@app.delete("/nodes/{name}", dependencies=[Depends(require_jwt)])
async def remove_node(name: str):
    """Remove a mesh node."""
    state = _load_state()
    state["nodes"] = [n for n in state.get("nodes", []) if n["name"] != name]
    _save_state(state)

    # Update dnsmasq if enabled
    if state.get("enabled", False):
        config_content = _generate_dnsmasq_config(state)
        _apply_dnsmasq_config(config_content)

    return {"success": True}


@app.get("/mappings", dependencies=[Depends(require_jwt)])
async def get_mappings():
    """Get custom domain mappings."""
    state = _load_state()
    return {"mappings": state.get("mappings", [])}


@app.post("/mappings", dependencies=[Depends(require_jwt)])
async def add_mapping(mapping: DomainMapping):
    """Add a custom domain mapping."""
    state = _load_state()

    # Validate IP
    if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', mapping.ip):
        raise HTTPException(status_code=400, detail="Invalid IP address")

    # Remove existing mapping with same hostname
    state["mappings"] = [m for m in state.get("mappings", []) if m["hostname"] != mapping.hostname]

    state.setdefault("mappings", []).append({
        "hostname": mapping.hostname,
        "ip": mapping.ip,
        "ttl": mapping.ttl,
        "added": datetime.now().isoformat()
    })
    _save_state(state)

    # Update dnsmasq if enabled
    if state.get("enabled", False):
        config_content = _generate_dnsmasq_config(state)
        _apply_dnsmasq_config(config_content)

    return {"success": True, "hostname": mapping.hostname}


@app.delete("/mappings/{hostname}", dependencies=[Depends(require_jwt)])
async def remove_mapping(hostname: str):
    """Remove a domain mapping."""
    state = _load_state()
    state["mappings"] = [m for m in state.get("mappings", []) if m["hostname"] != hostname]
    _save_state(state)

    # Update dnsmasq if enabled
    if state.get("enabled", False):
        config_content = _generate_dnsmasq_config(state)
        _apply_dnsmasq_config(config_content)

    return {"success": True}


@app.get("/discover", dependencies=[Depends(require_jwt)])
async def discover_hosts():
    """Discover mDNS hosts on the network."""
    if not _check_avahi_available():
        return {"hosts": [], "error": "Avahi not available"}

    hosts = _discover_mdns_hosts()

    # Deduplicate by hostname
    seen = set()
    unique_hosts = []
    for host in hosts:
        key = f"{host['hostname']}:{host['ip']}"
        if key not in seen:
            seen.add(key)
            unique_hosts.append(host)

    return {"hosts": unique_hosts}


@app.post("/discover/import", dependencies=[Depends(require_jwt)])
async def import_discovered_hosts(hostnames: list[str]):
    """Import discovered hosts as mesh nodes."""
    discovered = _discover_mdns_hosts()
    state = _load_state()

    imported = []
    for hostname in hostnames:
        host = next((h for h in discovered if h["hostname"] == hostname), None)
        if host:
            name = host["hostname"].replace(".local", "").replace(".", "-")
            state.setdefault("nodes", []).append({
                "name": name,
                "ip": host["ip"],
                "domain": f"{name}.{state.get('mesh_domain', 'mesh.local')}",
                "services": [host.get("type", "")],
                "added": datetime.now().isoformat()
            })
            imported.append(name)

    _save_state(state)

    # Update dnsmasq if enabled
    if state.get("enabled", False):
        config_content = _generate_dnsmasq_config(state)
        _apply_dnsmasq_config(config_content)

    return {"success": True, "imported": imported}


@app.get("/config", dependencies=[Depends(require_jwt)])
async def get_config_endpoint():
    """Get mesh configuration."""
    state = _load_state()
    return {
        "mesh_domain": state.get("mesh_domain", "mesh.local"),
        "publish_mdns": state.get("publish_mdns", True),
        "auto_discover": state.get("auto_discover", True)
    }


@app.post("/config", dependencies=[Depends(require_jwt)])
async def set_config(mesh_config: MeshConfig):
    """Set mesh configuration."""
    state = _load_state()
    state["mesh_domain"] = mesh_config.mesh_domain
    state["publish_mdns"] = mesh_config.publish_mdns
    state["auto_discover"] = mesh_config.auto_discover
    _save_state(state)

    # Update dnsmasq if enabled
    if state.get("enabled", False):
        config_content = _generate_dnsmasq_config(state)
        _apply_dnsmasq_config(config_content)

    return {"success": True}


@app.get("/resolve/{hostname}", dependencies=[Depends(require_jwt)])
async def resolve_hostname(hostname: str):
    """Resolve a hostname through mesh DNS."""
    state = _load_state()
    mesh_domain = state.get("mesh_domain", "mesh.local")

    # Check nodes
    for node in state.get("nodes", []):
        if node["name"] == hostname or node.get("domain") == hostname:
            return {"hostname": hostname, "ip": node["ip"], "source": "mesh"}
        if f"{node['name']}.{mesh_domain}" == hostname:
            return {"hostname": hostname, "ip": node["ip"], "source": "mesh"}

    # Check mappings
    for mapping in state.get("mappings", []):
        if mapping["hostname"] == hostname:
            return {"hostname": hostname, "ip": mapping["ip"], "source": "custom"}

    # Try system resolver
    try:
        result = subprocess.run(
            ["getent", "hosts", hostname],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            parts = result.stdout.split()
            if parts:
                return {"hostname": hostname, "ip": parts[0], "source": "system"}
    except Exception:
        pass

    raise HTTPException(status_code=404, detail="Hostname not found")


@app.get("/stats", dependencies=[Depends(require_jwt)])
async def get_stats():
    """Get mesh DNS statistics."""
    state = _load_state()

    return {
        "enabled": state.get("enabled", False),
        "mesh_domain": state.get("mesh_domain", "mesh.local"),
        "nodes_count": len(state.get("nodes", [])),
        "mappings_count": len(state.get("mappings", [])),
        "avahi_available": _check_avahi_available(),
        "dnsmasq_available": _check_dnsmasq_available()
    }


@app.get("/info", dependencies=[Depends(require_jwt)])
async def info():
    """Protected info endpoint."""
    return {"config": dict(config)}
