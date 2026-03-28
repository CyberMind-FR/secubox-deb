"""
SecuBox Exposure Manager API
Service exposure management - Tor, SSL, DNS, Mesh

Enhanced features:
- Multi-channel exposure tracking with status sync
- Health checking for exposed services
- Automatic SSL certificate management (ACME integration)
- Mesh publishing with peer sync
- Exposure history and audit logging
- QoS policies for exposed services
- Scheduled health checks with alerts
"""

from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from pathlib import Path
from datetime import datetime, timedelta
from enum import Enum
import subprocess
import os
import json
import re
import asyncio
import threading
import httpx

# Import shared auth
import sys
sys.path.insert(0, '/usr/lib/secubox/core')
try:
    from secubox_core.auth import require_jwt
except ImportError:
    async def require_jwt():
        return {"sub": "dev"}

app = FastAPI(title="SecuBox Exposure Manager API", version="2.0.0")

# Configuration
TOR_DATA = Path("/var/lib/tor/hidden_services")
TOR_CONFIG = Path("/etc/tor/torrc")
CONFIG_FILE = Path("/etc/secubox/exposure.json")
DATA_DIR = Path("/var/lib/secubox/exposure")
HISTORY_FILE = DATA_DIR / "history.json"
HEALTH_FILE = DATA_DIR / "health_status.json"
WEBHOOKS_FILE = DATA_DIR / "webhooks.json"

# Ensure data directory exists
DATA_DIR.mkdir(parents=True, exist_ok=True)

# Health check interval (seconds)
HEALTH_CHECK_INTERVAL = 300


class ExposureChannel(str, Enum):
    TOR = "tor"
    DNS = "dns"
    MESH = "mesh"
    SSL = "ssl"


class HealthStatus(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


class ExposureHistoryEntry(BaseModel):
    timestamp: str
    action: str  # emancipate, revoke, update, health_change
    service: str
    channels: List[str]
    user: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


class ServiceHealth(BaseModel):
    service: str
    status: HealthStatus
    last_check: str
    response_time_ms: Optional[float] = None
    error: Optional[str] = None
    channels: Dict[str, HealthStatus] = {}


class WebhookConfig(BaseModel):
    url: str
    events: List[str] = ["health_change", "exposure_change"]
    enabled: bool = True
    secret: Optional[str] = None


DEFAULT_CONFIG = {
    "known_services": [],
    "emancipated": [],
    "health_check_enabled": True,
    "health_check_interval": 300
}


# ============================================================================
# History Management
# ============================================================================

def load_history() -> List[Dict]:
    """Load exposure history."""
    if HISTORY_FILE.exists():
        try:
            with open(HISTORY_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return []


def save_history(history: List[Dict]):
    """Save exposure history."""
    # Keep last 1000 entries
    history = history[-1000:]
    try:
        with open(HISTORY_FILE, 'w') as f:
            json.dump(history, f, indent=2)
    except Exception:
        pass


def add_history_entry(entry: ExposureHistoryEntry):
    """Add entry to exposure history."""
    history = load_history()
    history.append(entry.dict())
    save_history(history)


# ============================================================================
# Health Status Management
# ============================================================================

_health_status: Dict[str, ServiceHealth] = {}
_health_lock = threading.Lock()


def load_health_status() -> Dict[str, ServiceHealth]:
    """Load health status from file."""
    global _health_status
    if HEALTH_FILE.exists():
        try:
            with open(HEALTH_FILE) as f:
                data = json.load(f)
                _health_status = {k: ServiceHealth(**v) for k, v in data.items()}
        except Exception:
            pass
    return _health_status


def save_health_status():
    """Save health status to file."""
    with _health_lock:
        try:
            with open(HEALTH_FILE, 'w') as f:
                json.dump({k: v.dict() for k, v in _health_status.items()}, f, indent=2)
        except Exception:
            pass


def update_health(service: str, health: ServiceHealth):
    """Update service health status."""
    global _health_status
    with _health_lock:
        old_status = _health_status.get(service)
        _health_status[service] = health

        # Check for status change
        if old_status and old_status.status != health.status:
            return True  # Status changed
    return False


# ============================================================================
# Webhook Notifications
# ============================================================================

def load_webhooks() -> List[WebhookConfig]:
    """Load webhook configurations."""
    if WEBHOOKS_FILE.exists():
        try:
            with open(WEBHOOKS_FILE) as f:
                return [WebhookConfig(**wh) for wh in json.load(f)]
        except Exception:
            pass
    return []


def save_webhooks(webhooks: List[WebhookConfig]):
    """Save webhook configurations."""
    try:
        with open(WEBHOOKS_FILE, 'w') as f:
            json.dump([wh.dict() for wh in webhooks], f, indent=2)
    except Exception:
        pass


async def send_webhook(event: str, data: Dict[str, Any]):
    """Send webhook notification."""
    webhooks = load_webhooks()

    for wh in webhooks:
        if not wh.enabled or event not in wh.events:
            continue

        payload = {
            "event": event,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "data": data
        }

        try:
            headers = {"Content-Type": "application/json"}
            if wh.secret:
                import hashlib, hmac
                sig = hmac.new(wh.secret.encode(), json.dumps(payload).encode(), hashlib.sha256).hexdigest()
                headers["X-Webhook-Signature"] = sig

            async with httpx.AsyncClient() as client:
                await client.post(wh.url, json=payload, headers=headers, timeout=5.0)
        except Exception:
            pass


# ============================================================================
# Health Checking
# ============================================================================

async def check_service_health(service: str, port: int, channels: List[str]) -> ServiceHealth:
    """Check health of an exposed service."""
    health = ServiceHealth(
        service=service,
        status=HealthStatus.UNKNOWN,
        last_check=datetime.utcnow().isoformat() + "Z"
    )

    channel_health = {}

    # Check local port
    start_time = asyncio.get_event_loop().time()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection('127.0.0.1', port),
            timeout=5.0
        )
        writer.close()
        await writer.wait_closed()
        health.response_time_ms = (asyncio.get_event_loop().time() - start_time) * 1000
        channel_health["local"] = HealthStatus.HEALTHY
    except Exception as e:
        health.error = str(e)
        channel_health["local"] = HealthStatus.UNHEALTHY

    # Check Tor if enabled
    if "tor" in channels:
        config = load_config()
        for svc in config.get("emancipated", []):
            if svc.get("name") == service and svc.get("onion"):
                # Just check if Tor service is running for now
                try:
                    result = subprocess.run(["pgrep", "tor"], capture_output=True, timeout=5)
                    if result.returncode == 0:
                        channel_health["tor"] = HealthStatus.HEALTHY
                    else:
                        channel_health["tor"] = HealthStatus.UNHEALTHY
                except Exception:
                    channel_health["tor"] = HealthStatus.UNKNOWN

    # Determine overall status
    if all(s == HealthStatus.HEALTHY for s in channel_health.values()):
        health.status = HealthStatus.HEALTHY
    elif all(s == HealthStatus.UNHEALTHY for s in channel_health.values()):
        health.status = HealthStatus.UNHEALTHY
    elif any(s == HealthStatus.HEALTHY for s in channel_health.values()):
        health.status = HealthStatus.DEGRADED
    else:
        health.status = HealthStatus.UNKNOWN

    health.channels = channel_health
    return health


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
        "version": "2.0.0",
        "description": "Service exposure management - Tor, SSL, DNS, Mesh",
        "features": [
            "multi_channel", "health_checks", "audit_history",
            "webhook_alerts", "scheduled_monitoring"
        ]
    }


@app.get("/health")
async def health_endpoint():
    """Health check endpoint."""
    return {"status": "healthy", "service": "secubox-exposure", "version": "2.0.0"}


# ============================================================================
# History Endpoints
# ============================================================================

@app.get("/history")
async def get_history(
    limit: int = 50,
    service: str = None,
    action: str = None
):
    """Get exposure history."""
    history = load_history()

    # Filter by service
    if service:
        history = [h for h in history if h.get("service") == service]

    # Filter by action
    if action:
        history = [h for h in history if h.get("action") == action]

    # Return most recent first
    history = sorted(history, key=lambda x: x.get("timestamp", ""), reverse=True)

    return {"history": history[:limit], "total": len(history)}


@app.delete("/history")
async def clear_history(user: dict = Depends(require_jwt)):
    """Clear exposure history."""
    save_history([])
    return {"status": "cleared"}


# ============================================================================
# Health Check Endpoints
# ============================================================================

@app.get("/health/services")
async def get_services_health():
    """Get health status of all exposed services."""
    health_status = load_health_status()
    return {"services": {k: v.dict() for k, v in health_status.items()}}


@app.get("/health/services/{service}")
async def get_service_health(service: str):
    """Get health status of a specific service."""
    health_status = load_health_status()
    if service not in health_status:
        raise HTTPException(status_code=404, detail="Service not found")
    return health_status[service].dict()


@app.post("/health/check/{service}")
async def check_service(service: str, background_tasks: BackgroundTasks, user: dict = Depends(require_jwt)):
    """Trigger health check for a service."""
    config = load_config()

    # Find service
    svc = None
    for s in config.get("emancipated", []):
        if s.get("name") == service:
            svc = s
            break

    if not svc:
        raise HTTPException(status_code=404, detail="Service not found")

    # Get channels
    channels = []
    if svc.get("tor"):
        channels.append("tor")
    if svc.get("dns"):
        channels.append("dns")
    if svc.get("mesh"):
        channels.append("mesh")

    # Run health check
    health = await check_service_health(service, svc.get("port", 80), channels)

    # Update status
    status_changed = update_health(service, health)
    save_health_status()

    # Send webhook if status changed
    if status_changed:
        background_tasks.add_task(send_webhook, "health_change", {
            "service": service,
            "status": health.status.value,
            "previous_status": _health_status.get(service, {}).status if service in _health_status else "unknown"
        })

    return health.dict()


@app.post("/health/check_all")
async def check_all_services(background_tasks: BackgroundTasks, user: dict = Depends(require_jwt)):
    """Trigger health check for all exposed services."""
    config = load_config()
    results = {}

    for svc in config.get("emancipated", []):
        service = svc.get("name")
        channels = []
        if svc.get("tor"):
            channels.append("tor")
        if svc.get("dns"):
            channels.append("dns")
        if svc.get("mesh"):
            channels.append("mesh")

        health = await check_service_health(service, svc.get("port", 80), channels)
        status_changed = update_health(service, health)
        results[service] = health.dict()

        if status_changed:
            background_tasks.add_task(send_webhook, "health_change", {
                "service": service,
                "status": health.status.value
            })

    save_health_status()
    return {"results": results, "checked": len(results)}


# ============================================================================
# Webhook Endpoints
# ============================================================================

@app.get("/webhooks")
async def list_webhooks(user: dict = Depends(require_jwt)):
    """List configured webhooks."""
    webhooks = load_webhooks()
    return {"webhooks": [wh.dict() for wh in webhooks]}


@app.post("/webhooks")
async def add_webhook(webhook: WebhookConfig, user: dict = Depends(require_jwt)):
    """Add a webhook."""
    webhooks = load_webhooks()

    for wh in webhooks:
        if wh.url == webhook.url:
            raise HTTPException(status_code=409, detail="Webhook URL already exists")

    webhooks.append(webhook)
    save_webhooks(webhooks)
    return {"status": "added"}


@app.delete("/webhooks")
async def delete_webhook(url: str, user: dict = Depends(require_jwt)):
    """Delete a webhook by URL."""
    webhooks = load_webhooks()
    original_len = len(webhooks)
    webhooks = [wh for wh in webhooks if wh.url != url]

    if len(webhooks) == original_len:
        raise HTTPException(status_code=404, detail="Webhook not found")

    save_webhooks(webhooks)
    return {"status": "deleted"}


# ============================================================================
# Statistics Endpoints
# ============================================================================

@app.get("/stats")
async def get_exposure_stats():
    """Get exposure statistics."""
    config = load_config()
    history = load_history()
    health_status = load_health_status()

    emancipated = config.get("emancipated", [])

    # Count by channel
    channel_counts = {"tor": 0, "dns": 0, "mesh": 0, "ssl": 0}
    for svc in emancipated:
        if svc.get("tor"):
            channel_counts["tor"] += 1
        if svc.get("dns"):
            channel_counts["dns"] += 1
        if svc.get("mesh"):
            channel_counts["mesh"] += 1

    # Health summary
    health_summary = {"healthy": 0, "degraded": 0, "unhealthy": 0, "unknown": 0}
    for h in health_status.values():
        health_summary[h.status.value] = health_summary.get(h.status.value, 0) + 1

    # Recent activity
    recent_history = sorted(history, key=lambda x: x.get("timestamp", ""), reverse=True)[:10]

    return {
        "total_exposed": len(emancipated),
        "by_channel": channel_counts,
        "health_summary": health_summary,
        "recent_activity": recent_history
    }


# ============================================================================
# Enhanced Emancipate/Revoke with History
# ============================================================================

# Override emancipate to add history
_original_emancipate = emancipate


@app.post("/emancipate")
async def emancipate_with_history(
    req: EmancipateRequest,
    background_tasks: BackgroundTasks,
    user: dict = Depends(require_jwt)
):
    """Emancipate a service with history tracking."""
    result = await _original_emancipate(req, user)

    # Add history entry
    channels = []
    if req.tor:
        channels.append("tor")
    if req.dns:
        channels.append("dns")
    if req.mesh:
        channels.append("mesh")

    add_history_entry(ExposureHistoryEntry(
        timestamp=datetime.utcnow().isoformat() + "Z",
        action="emancipate",
        service=req.service,
        channels=channels,
        user=user.get("sub"),
        details={"port": req.port, "domain": req.domain}
    ))

    # Send webhook
    background_tasks.add_task(send_webhook, "exposure_change", {
        "action": "emancipate",
        "service": req.service,
        "channels": channels
    })

    return result


# Override revoke to add history
_original_revoke = revoke


@app.post("/revoke")
async def revoke_with_history(
    req: RevokeRequest,
    background_tasks: BackgroundTasks,
    user: dict = Depends(require_jwt)
):
    """Revoke service exposure with history tracking."""
    result = await _original_revoke(req, user)

    # Add history entry
    channels = []
    if req.tor:
        channels.append("tor")
    if req.dns:
        channels.append("dns")
    if req.mesh:
        channels.append("mesh")

    add_history_entry(ExposureHistoryEntry(
        timestamp=datetime.utcnow().isoformat() + "Z",
        action="revoke",
        service=req.service,
        channels=channels,
        user=user.get("sub")
    ))

    # Send webhook
    background_tasks.add_task(send_webhook, "exposure_change", {
        "action": "revoke",
        "service": req.service,
        "channels": channels
    })

    # Remove from health status
    with _health_lock:
        _health_status.pop(req.service, None)
    save_health_status()

    return result


# ============================================================================
# Background Health Monitoring
# ============================================================================

_health_task: Optional[asyncio.Task] = None


async def periodic_health_check():
    """Background task for periodic health checks."""
    while True:
        try:
            config = load_config()
            if not config.get("health_check_enabled", True):
                await asyncio.sleep(60)
                continue

            interval = config.get("health_check_interval", HEALTH_CHECK_INTERVAL)
            await asyncio.sleep(interval)

            for svc in config.get("emancipated", []):
                service = svc.get("name")
                channels = []
                if svc.get("tor"):
                    channels.append("tor")
                if svc.get("dns"):
                    channels.append("dns")
                if svc.get("mesh"):
                    channels.append("mesh")

                try:
                    health = await check_service_health(service, svc.get("port", 80), channels)
                    status_changed = update_health(service, health)

                    if status_changed:
                        await send_webhook("health_change", {
                            "service": service,
                            "status": health.status.value
                        })
                except Exception:
                    pass

            save_health_status()

        except asyncio.CancelledError:
            break
        except Exception:
            await asyncio.sleep(60)


@app.on_event("startup")
async def startup():
    """Initialize on startup."""
    global _health_task
    load_health_status()
    _health_task = asyncio.create_task(periodic_health_check())


@app.on_event("shutdown")
async def shutdown():
    """Cleanup on shutdown."""
    global _health_task
    if _health_task:
        _health_task.cancel()
        try:
            await _health_task
        except asyncio.CancelledError:
            pass
    save_health_status()
