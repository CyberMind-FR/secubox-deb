"""
SecuBox Exposure Manager API
Service exposure management - Tor, SSL, DNS, Mesh
"""

from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional, List
from pathlib import Path
import subprocess
import os
import json
import re

# Import shared auth
import sys
sys.path.insert(0, '/usr/lib/secubox/core')
try:
    from secubox_core.auth import require_jwt
except ImportError:
    async def require_jwt():
        return {"sub": "dev"}

app = FastAPI(title="SecuBox Exposure Manager API", version="1.0.0")

# Configuration
TOR_DATA = Path("/var/lib/tor/hidden_services")
TOR_CONFIG = Path("/etc/tor/torrc")
CONFIG_FILE = Path("/etc/secubox/exposure.json")

DEFAULT_CONFIG = {
    "known_services": []
}


# Models
class TorAddRequest(BaseModel):
    service: str
    local_port: int = 80
    onion_port: int = 80


class TorRemoveRequest(BaseModel):
    service: str


class SslAddRequest(BaseModel):
    service: str
    domain: str
    local_port: int = 80


class SslRemoveRequest(BaseModel):
    service: str


class EmancipateRequest(BaseModel):
    service: str
    port: int
    domain: Optional[str] = None
    tor: bool = False
    dns: bool = False
    mesh: bool = False


class RevokeRequest(BaseModel):
    service: str
    tor: bool = False
    dns: bool = False
    mesh: bool = False


class FixPortRequest(BaseModel):
    service: str
    port: int


# Helpers
def run_cmd(cmd: list, timeout: int = 30) -> tuple:
    """Run command and return (success, stdout, stderr)"""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.returncode == 0, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return False, "", "Command timed out"
    except Exception as e:
        return False, "", str(e)


def load_config() -> dict:
    """Load exposure configuration"""
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text())
        except:
            pass
    return DEFAULT_CONFIG.copy()


def save_config(config: dict):
    """Save exposure configuration"""
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(config, indent=2))


def scan_services() -> list:
    """Scan listening services"""
    services = []

    # Use ss to get listening ports
    success, out, _ = run_cmd(["ss", "-tlnp"])
    if not success:
        return services

    seen_ports = set()
    for line in out.split('\n'):
        if 'LISTEN' not in line:
            continue

        parts = line.split()
        if len(parts) < 5:
            continue

        # Parse address:port
        addr = parts[3]
        if ':' in addr:
            addr_parts = addr.rsplit(':', 1)
            port = addr_parts[-1]
            address = addr_parts[0] if len(addr_parts) > 1 else "0.0.0.0"
        else:
            continue

        if port in seen_ports:
            continue
        seen_ports.add(port)

        # Determine if external
        external = "0.0.0.0" in address or "::" in address or "*" in address

        # Get process name
        proc = "unknown"
        if 'users:' in line:
            match = re.search(r'users:\(\("([^"]+)"', line)
            if match:
                proc = match.group(1)

        # Map process to friendly name
        name_map = {
            "sshd": "SSH",
            "nginx": "Nginx",
            "haproxy": "HAProxy",
            "tor": "Tor",
            "python3": "Python App",
            "uvicorn": "Uvicorn API",
            "dnsmasq": "DNS",
        }
        name = name_map.get(proc, proc)

        services.append({
            "port": int(port),
            "address": address,
            "process": proc,
            "name": name,
            "external": external
        })

    return sorted(services, key=lambda x: x["port"])


def get_tor_services() -> list:
    """Get Tor hidden services"""
    services = []

    if not TOR_DATA.exists():
        return services

    for dir_path in TOR_DATA.iterdir():
        if not dir_path.is_dir():
            continue

        svc_name = dir_path.name
        hostname_file = dir_path / "hostname"
        onion = ""

        if hostname_file.exists():
            onion = hostname_file.read_text().strip()

        # Get port from torrc
        port = "80"
        backend = "127.0.0.1:80"

        if TOR_CONFIG.exists():
            torrc = TOR_CONFIG.read_text()
            # Look for HiddenServiceDir followed by HiddenServicePort
            pattern = rf'HiddenServiceDir\s+{re.escape(str(dir_path))}\s*\n\s*HiddenServicePort\s+(\d+)\s+(.+)'
            match = re.search(pattern, torrc)
            if match:
                port = match.group(1)
                backend = match.group(2)

        if onion:
            services.append({
                "service": svc_name,
                "onion": onion,
                "port": port,
                "backend": backend
            })

    return services


def get_ssl_backends() -> list:
    """Get SSL backends from HAProxy/nginx config"""
    backends = []

    # Check HAProxy backends
    haproxy_cfg = Path("/etc/haproxy/haproxy.cfg")
    if haproxy_cfg.exists():
        # Parse haproxy config for backends with SSL
        cfg = haproxy_cfg.read_text()
        # Simplified parsing - real implementation would be more sophisticated

    # Check nginx vhosts
    nginx_dir = Path("/etc/nginx/sites-enabled")
    if nginx_dir.exists():
        for vhost in nginx_dir.iterdir():
            if vhost.is_file():
                content = vhost.read_text()
                # Check for SSL cert
                if "ssl_certificate" in content:
                    # Extract server_name
                    match = re.search(r'server_name\s+([^;]+);', content)
                    if match:
                        domain = match.group(1).strip().split()[0]
                        backends.append({
                            "service": vhost.name,
                            "domain": domain,
                            "backend": "nginx"
                        })

    return backends


# Public endpoints
@app.get("/status")
async def get_status():
    """Get exposure status overview"""
    services = scan_services()
    tor_services = get_tor_services()
    ssl_backends = get_ssl_backends()

    external_count = sum(1 for s in services if s["external"])

    return {
        "services": {
            "total": len(services),
            "external": external_count
        },
        "tor": {
            "count": len(tor_services),
            "services": tor_services
        },
        "ssl": {
            "count": len(ssl_backends),
            "backends": ssl_backends
        }
    }


@app.get("/scan")
async def scan():
    """Scan listening services"""
    return {"services": scan_services()}


@app.get("/tor_list")
async def tor_list():
    """List Tor hidden services"""
    return {"services": get_tor_services()}


@app.get("/ssl_list")
async def ssl_list():
    """List SSL backends"""
    return {"backends": get_ssl_backends()}


@app.get("/emancipated")
async def get_emancipated():
    """Get list of emancipated services"""
    config = load_config()
    return {"services": config.get("emancipated", [])}


# Protected endpoints
@app.post("/tor/add")
async def tor_add(req: TorAddRequest, user: dict = Depends(require_jwt)):
    """Add Tor hidden service"""
    # Sanitize service name
    name = "".join(c for c in req.service if c.isalnum() or c in "_-")

    hs_dir = TOR_DATA / name
    if hs_dir.exists():
        raise HTTPException(status_code=400, detail="Hidden service already exists")

    # Add to torrc
    if TOR_CONFIG.exists():
        torrc = TOR_CONFIG.read_text()
    else:
        torrc = ""

    torrc += f"\n# Hidden service: {name}\n"
    torrc += f"HiddenServiceDir {hs_dir}\n"
    torrc += f"HiddenServicePort {req.onion_port} 127.0.0.1:{req.local_port}\n"

    TOR_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    TOR_CONFIG.write_text(torrc)

    # Reload Tor
    run_cmd(["systemctl", "reload", "tor"])

    # Wait for onion address (Tor generates it on reload)
    import time
    for _ in range(10):
        time.sleep(1)
        hostname_file = hs_dir / "hostname"
        if hostname_file.exists():
            onion = hostname_file.read_text().strip()
            return {
                "success": True,
                "message": "Hidden service created",
                "onion": onion
            }

    return {
        "success": True,
        "message": "Hidden service created, onion address pending"
    }


@app.post("/tor/remove")
async def tor_remove(req: TorRemoveRequest, user: dict = Depends(require_jwt)):
    """Remove Tor hidden service"""
    name = "".join(c for c in req.service if c.isalnum() or c in "_-")
    hs_dir = TOR_DATA / name

    if not hs_dir.exists():
        raise HTTPException(status_code=404, detail="Hidden service not found")

    # Remove from torrc
    if TOR_CONFIG.exists():
        torrc = TOR_CONFIG.read_text()
        # Remove the hidden service config block
        pattern = rf'# Hidden service: {re.escape(name)}\n.*?HiddenServiceDir {re.escape(str(hs_dir))}\n.*?HiddenServicePort [^\n]+\n'
        torrc = re.sub(pattern, '', torrc, flags=re.DOTALL)
        TOR_CONFIG.write_text(torrc)

    # Remove directory
    import shutil
    shutil.rmtree(hs_dir, ignore_errors=True)

    # Reload Tor
    run_cmd(["systemctl", "reload", "tor"])

    return {"success": True, "message": "Hidden service removed"}


@app.post("/ssl/add")
async def ssl_add(req: SslAddRequest, user: dict = Depends(require_jwt)):
    """Add SSL backend"""
    # This would integrate with HAProxy or nginx
    # Simplified implementation

    config = load_config()
    if "ssl_backends" not in config:
        config["ssl_backends"] = []

    config["ssl_backends"].append({
        "service": req.service,
        "domain": req.domain,
        "local_port": req.local_port
    })

    save_config(config)

    return {"success": True, "message": "SSL backend configured"}


@app.post("/ssl/remove")
async def ssl_remove(req: SslRemoveRequest, user: dict = Depends(require_jwt)):
    """Remove SSL backend"""
    config = load_config()

    if "ssl_backends" in config:
        config["ssl_backends"] = [
            b for b in config["ssl_backends"]
            if b["service"] != req.service
        ]
        save_config(config)

    return {"success": True, "message": "SSL backend removed"}


@app.post("/emancipate")
async def emancipate(req: EmancipateRequest, user: dict = Depends(require_jwt)):
    """Emancipate a service (expose via Tor/DNS/Mesh)"""
    config = load_config()

    if "emancipated" not in config:
        config["emancipated"] = []

    # Check if already emancipated
    for svc in config["emancipated"]:
        if svc["name"] == req.service:
            raise HTTPException(status_code=400, detail="Service already emancipated")

    result = {
        "name": req.service,
        "port": req.port,
        "domain": req.domain,
        "tor": req.tor,
        "dns": req.dns,
        "mesh": req.mesh
    }

    # If Tor requested, create hidden service
    if req.tor:
        tor_req = TorAddRequest(service=req.service, local_port=req.port)
        tor_result = await tor_add(tor_req, user)
        if tor_result.get("onion"):
            result["onion"] = tor_result["onion"]

    config["emancipated"].append(result)
    save_config(config)

    return {"success": True, "message": "Service emancipated", "output": result}


@app.post("/revoke")
async def revoke(req: RevokeRequest, user: dict = Depends(require_jwt)):
    """Revoke service exposure"""
    config = load_config()

    if "emancipated" not in config:
        return {"success": True, "message": "No emancipated services"}

    # Find and remove
    found = None
    for svc in config["emancipated"]:
        if svc["name"] == req.service:
            found = svc
            break

    if not found:
        raise HTTPException(status_code=404, detail="Service not found")

    # If Tor was enabled, remove hidden service
    if found.get("tor") and req.tor:
        tor_req = TorRemoveRequest(service=req.service)
        await tor_remove(tor_req, user)

    config["emancipated"] = [
        s for s in config["emancipated"]
        if s["name"] != req.service
    ]
    save_config(config)

    return {"success": True, "message": "Service revoked"}


@app.get("/info")
async def get_info():
    """Get module info"""
    return {
        "module": "secubox-exposure",
        "version": "1.0.0",
        "description": "Service exposure management - Tor, SSL, DNS, Mesh"
    }
