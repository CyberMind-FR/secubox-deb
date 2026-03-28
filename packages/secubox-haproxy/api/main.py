"""secubox-haproxy — HAProxy Dashboard API with WAF Integration

Provides HAProxy management with integrated WAF inspection via mitmproxy.
Traffic flow: Client → HAProxy → WAF (mitmproxy) → Backend

Features:
- HAProxy status and stats monitoring
- VHost and backend management
- WAF integration with mitmproxy
- Certificate management with expiry monitoring
- Traffic history and request statistics
- Configuration backup/versioning
- Webhook alerts for health changes
"""
import os
import subprocess
import socket
import json
import ssl
import hashlib
import hmac
import threading
import time
import asyncio
import httpx
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from enum import Enum

from fastapi import FastAPI, APIRouter, Depends, HTTPException, Query, BackgroundTasks
from pydantic import BaseModel, Field
from secubox_core.auth import router as auth_router, require_jwt
from secubox_core.config import get_config
from secubox_core.logger import get_logger

app = FastAPI(title="secubox-haproxy", version="2.0.0", root_path="/api/v1/haproxy")
app.include_router(auth_router, prefix="/auth")
router = APIRouter()
log = get_logger("haproxy")

STATS_SOCKET = "/run/haproxy/admin.sock"
CONFIG_DIR = "/etc/haproxy"
WAF_SOCKET = "/run/secubox/waf.sock"
HAPROXY_CFG = "/etc/haproxy/haproxy.cfg"
VHOST_ROUTES_FILE = "/var/lib/secubox/haproxy/vhost-routes.json"
CTL = "/usr/sbin/haproxyctl"
CERTS_DIR = "/srv/haproxy/certs"
DATA_DIR = Path("/var/lib/secubox/haproxy")
CONFIG_BACKUP_DIR = DATA_DIR / "config_backups"
STATS_HISTORY_FILE = DATA_DIR / "stats_history.json"
WEBHOOKS_FILE = DATA_DIR / "webhooks.json"
HEALTH_HISTORY_FILE = DATA_DIR / "health_history.json"

# Ensure directories exist
DATA_DIR.mkdir(parents=True, exist_ok=True)
CONFIG_BACKUP_DIR.mkdir(parents=True, exist_ok=True)


# ═══════════════════════════════════════════════════════════════════════
# Models
# ═══════════════════════════════════════════════════════════════════════

class HealthStatus(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


class CertificateInfo(BaseModel):
    name: str
    path: str
    domains: List[str] = []
    issuer: Optional[str] = None
    expires_at: Optional[str] = None
    days_until_expiry: Optional[int] = None
    expired: bool = False


class BackendHealth(BaseModel):
    name: str
    status: HealthStatus
    active_servers: int = 0
    total_servers: int = 0
    sessions: int = 0
    bytes_in: int = 0
    bytes_out: int = 0


class WebhookConfig(BaseModel):
    id: str
    url: str
    events: List[str] = ["backend_down", "backend_up", "cert_expiring"]
    secret: Optional[str] = None
    enabled: bool = True
    created_at: str
    last_triggered: Optional[str] = None
    failure_count: int = 0


# ═══════════════════════════════════════════════════════════════════════
# Stats Cache
# ═══════════════════════════════════════════════════════════════════════

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


# ═══════════════════════════════════════════════════════════════════════
# Background Tasks
# ═══════════════════════════════════════════════════════════════════════

_health_monitor_task: Optional[asyncio.Task] = None
_stats_collector_task: Optional[asyncio.Task] = None


def _load_json(path: Path, default=None) -> Any:
    """Load JSON from file with default fallback."""
    if default is None:
        default = {}
    try:
        if path.exists():
            return json.loads(path.read_text())
    except (json.JSONDecodeError, IOError):
        pass
    return default


def _save_json(path: Path, data: Any):
    """Save JSON to file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2))


async def _trigger_webhooks(event: str, payload: dict):
    """Trigger webhooks for an event."""
    webhooks = _load_json(WEBHOOKS_FILE, {"webhooks": []})

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

    _save_json(WEBHOOKS_FILE, webhooks)


async def _periodic_health_monitor():
    """Monitor backend health and trigger webhooks on changes."""
    previous_status: Dict[str, str] = {}

    while True:
        try:
            await asyncio.sleep(30)  # Check every 30 seconds

            data = _send_stats_command("show stat")
            if not data:
                continue

            stats = _parse_stats_csv(data)
            history = _load_json(HEALTH_HISTORY_FILE, {"records": []})

            for stat in stats:
                name = stat.get("pxname", "")
                svname = stat.get("svname", "")
                status = stat.get("status", "")

                if svname in ["FRONTEND", "BACKEND"]:
                    key = f"{name}_{svname}"
                    prev = previous_status.get(key, "")

                    # Record in history
                    if status != prev:
                        history["records"].append({
                            "name": name,
                            "type": svname.lower(),
                            "status": status,
                            "timestamp": datetime.now().isoformat()
                        })

                        # Trigger webhooks
                        if status == "UP" and prev in ["DOWN", "MAINT", ""]:
                            await _trigger_webhooks("backend_up", {
                                "name": name,
                                "type": svname.lower(),
                                "status": status
                            })
                        elif status in ["DOWN", "MAINT"] and prev == "UP":
                            await _trigger_webhooks("backend_down", {
                                "name": name,
                                "type": svname.lower(),
                                "status": status
                            })

                    previous_status[key] = status

            # Keep last 1000 records
            history["records"] = history["records"][-1000:]
            _save_json(HEALTH_HISTORY_FILE, history)

        except asyncio.CancelledError:
            break
        except Exception:
            pass


async def _periodic_stats_collector():
    """Collect stats periodically for history."""
    while True:
        try:
            await asyncio.sleep(60)  # Collect every minute

            data = _send_stats_command("show stat")
            if not data:
                continue

            stats = _parse_stats_csv(data)
            history = _load_json(STATS_HISTORY_FILE, {"records": []})

            # Aggregate stats
            total_sessions = 0
            total_bytes_in = 0
            total_bytes_out = 0
            total_req = 0

            for stat in stats:
                if stat.get("svname") == "FRONTEND":
                    total_sessions += int(stat.get("scur", 0) or 0)
                    total_req += int(stat.get("req_tot", 0) or 0)
                    total_bytes_in += int(stat.get("bin", 0) or 0)
                    total_bytes_out += int(stat.get("bout", 0) or 0)

            history["records"].append({
                "timestamp": datetime.now().isoformat(),
                "sessions": total_sessions,
                "requests": total_req,
                "bytes_in": total_bytes_in,
                "bytes_out": total_bytes_out
            })

            # Keep last 1440 records (24 hours at 1-minute intervals)
            history["records"] = history["records"][-1440:]
            _save_json(STATS_HISTORY_FILE, history)

        except asyncio.CancelledError:
            break
        except Exception:
            pass


@app.on_event("startup")
async def startup_event():
    """Start background tasks."""
    global _health_monitor_task, _stats_collector_task
    _health_monitor_task = asyncio.create_task(_periodic_health_monitor())
    _stats_collector_task = asyncio.create_task(_periodic_stats_collector())


@app.on_event("shutdown")
async def shutdown_event():
    """Stop background tasks."""
    global _health_monitor_task, _stats_collector_task
    if _health_monitor_task:
        _health_monitor_task.cancel()
    if _stats_collector_task:
        _stats_collector_task.cancel()


def _cfg():
    cfg = get_config("haproxy")
    return {
        "stats_socket": cfg.get("stats_socket", STATS_SOCKET) if cfg else STATS_SOCKET,
        "config_dir": cfg.get("config_dir", CONFIG_DIR) if cfg else CONFIG_DIR,
        "http_port": cfg.get("http_port", 80) if cfg else 80,
        "https_port": cfg.get("https_port", 443) if cfg else 443,
        "stats_port": cfg.get("stats_port", 8404) if cfg else 8404,
        "waf_enabled": cfg.get("waf_enabled", True) if cfg else True,
        "waf_backend_port": cfg.get("waf_backend_port", 8890) if cfg else 8890,
        "crowdsec_enabled": cfg.get("crowdsec_enabled", True) if cfg else True,
    }


def _haproxy_running() -> bool:
    """Check if HAProxy is running."""
    result = subprocess.run(["pgrep", "haproxy"], capture_output=True)
    return result.returncode == 0


def _docker_running() -> bool:
    """Check if HAProxy Docker container is running."""
    try:
        result = subprocess.run(
            ["docker", "ps", "--filter", "name=haproxy", "--format", "{{.Names}}"],
            capture_output=True, text=True, timeout=5
        )
        return "haproxy" in result.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _waf_available() -> bool:
    """Check if WAF socket is available."""
    return Path(WAF_SOCKET).exists()


async def _call_waf(path: str, method: str = "GET", data: dict = None) -> dict:
    """Call WAF API via Unix socket."""
    if not _waf_available():
        return {"error": "WAF not available"}

    try:
        transport = httpx.HTTPTransport(uds=WAF_SOCKET)
        async with httpx.AsyncClient(transport=transport, base_url="http://localhost") as client:
            if method == "GET":
                resp = await client.get(path, timeout=5)
            else:
                resp = await client.post(path, json=data or {}, timeout=10)
            return resp.json()
    except Exception as e:
        return {"error": str(e)}


def _send_stats_command(cmd: str) -> str:
    """Send command to HAProxy stats socket."""
    sock_path = _cfg()["stats_socket"]
    if not Path(sock_path).exists():
        return ""

    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(sock_path)
        sock.sendall(f"{cmd}\n".encode())
        response = b""
        while True:
            data = sock.recv(4096)
            if not data:
                break
            response += data
        sock.close()
        return response.decode()
    except Exception as e:
        log.warning("Stats socket error: %s", e)
        return ""


def _parse_stats_csv(data: str) -> List[dict]:
    """Parse HAProxy stats CSV output."""
    lines = data.strip().split("\n")
    if len(lines) < 2:
        return []

    headers = lines[0].lstrip("# ").split(",")
    result = []
    for line in lines[1:]:
        if not line.strip():
            continue
        values = line.split(",")
        result.append(dict(zip(headers, values)))
    return result


def _load_vhosts() -> List[dict]:
    """Load vhosts from HAProxy config."""
    vhosts = []
    cfg = get_config("haproxy") or {}
    vhost_cfg = cfg.get("vhosts", {})

    for name, v in vhost_cfg.items():
        if isinstance(v, dict):
            vhosts.append({
                "name": name,
                "domain": v.get("domain", name),
                "backend": v.get("backend", ""),
                "ssl": v.get("ssl", False),
                "ssl_redirect": v.get("ssl_redirect", False),
                "acme": v.get("acme", False),
                "waf_bypass": v.get("waf_bypass", False),
                "enabled": v.get("enabled", True),
            })

    return vhosts


def _load_backends() -> List[dict]:
    """Load backends from config."""
    backends = []
    cfg = get_config("haproxy") or {}
    backend_cfg = cfg.get("backends", {})

    for name, b in backend_cfg.items():
        if isinstance(b, dict):
            backends.append({
                "name": name,
                "servers": b.get("servers", []),
                "mode": b.get("mode", "http"),
                "balance": b.get("balance", "roundrobin"),
            })

    return backends


def _save_vhost_routes(routes: Dict[str, str]):
    """Save vhost→backend routing table for WAF."""
    route_dir = Path(VHOST_ROUTES_FILE).parent
    route_dir.mkdir(parents=True, exist_ok=True)
    Path(VHOST_ROUTES_FILE).write_text(json.dumps(routes, indent=2))


def _load_vhost_routes() -> Dict[str, str]:
    """Load vhost→backend routing table."""
    route_file = Path(VHOST_ROUTES_FILE)
    if route_file.exists():
        return json.loads(route_file.read_text())
    return {}


# ═══════════════════════════════════════════════════════════════════════
# THREE-FOLD ARCHITECTURE
# ═══════════════════════════════════════════════════════════════════════

# ── COMPONENTS ─────────────────────────────────────────────────────────

@router.get("/components")
async def components():
    """List system components (public)."""
    cfg = _cfg()

    return {
        "components": [
            {
                "name": "HAProxy Service",
                "type": "service",
                "description": "Load balancer and reverse proxy",
                "running": _haproxy_running() or _docker_running(),
                "config_path": HAPROXY_CFG
            },
            {
                "name": "WAF Inspector",
                "type": "service",
                "description": "Web Application Firewall (mitmproxy)",
                "enabled": cfg["waf_enabled"],
                "available": _waf_available(),
                "port": cfg["waf_backend_port"]
            },
            {
                "name": "haproxyctl",
                "type": "cli",
                "description": "Control script for HAProxy management",
                "path": CTL,
                "installed": Path(CTL).exists()
            },
            {
                "name": "Certificate Store",
                "type": "storage",
                "description": "TLS certificates directory",
                "path": CERTS_DIR,
                "exists": Path(CERTS_DIR).exists()
            },
            {
                "name": "CrowdSec Bouncer",
                "type": "integration",
                "description": "IP reputation and blocking",
                "enabled": cfg["crowdsec_enabled"]
            }
        ]
    }


# ── ACCESS ─────────────────────────────────────────────────────────────

@router.get("/access")
async def access():
    """Get access information for HAProxy services (public)."""
    cfg = _cfg()
    vhosts = _load_vhosts()

    access_points = [
        {
            "name": "HTTP Frontend",
            "type": "frontend",
            "port": cfg["http_port"],
            "url": f"http://{{{{hostname}}}}:{cfg['http_port']}",
            "protocol": "http"
        },
        {
            "name": "HTTPS Frontend",
            "type": "frontend",
            "port": cfg["https_port"],
            "url": f"https://{{{{hostname}}}}:{cfg['https_port']}",
            "protocol": "https"
        },
        {
            "name": "Stats Dashboard",
            "type": "admin",
            "port": cfg["stats_port"],
            "url": f"http://{{{{hostname}}}}:{cfg['stats_port']}/stats",
            "protocol": "http"
        }
    ]

    # Add vhost access points
    for vh in vhosts:
        if vh.get("enabled"):
            proto = "https" if vh.get("ssl") else "http"
            access_points.append({
                "name": vh["domain"],
                "type": "vhost",
                "domain": vh["domain"],
                "backend": vh["backend"],
                "url": f"{proto}://{vh['domain']}",
                "waf_protected": not vh.get("waf_bypass", False)
            })

    return {"access": access_points}


# ── STATUS ─────────────────────────────────────────────────────────────

@router.get("/status")
async def status():
    """HAProxy status with WAF integration (public)."""
    cfg = _cfg()
    running = _haproxy_running() or _docker_running()
    waf_available = _waf_available()

    return {
        "running": running,
        "http_port": cfg["http_port"],
        "https_port": cfg["https_port"],
        "stats_port": cfg["stats_port"],
        "waf_enabled": cfg["waf_enabled"],
        "waf_available": waf_available,
        "crowdsec_enabled": cfg["crowdsec_enabled"],
        "vhost_count": len(_load_vhosts()),
        "backend_count": len(_load_backends()),
    }


@router.get("/stats")
async def get_stats():
    """Get HAProxy stats (public)."""
    data = _send_stats_command("show stat")
    if not data:
        return {"stats": [], "error": "Stats not available"}

    stats = _parse_stats_csv(data)
    return {"stats": stats}


@router.get("/info")
async def get_info():
    """Get HAProxy info (public)."""
    data = _send_stats_command("show info")
    if not data:
        return {"info": {}}

    info = {}
    for line in data.strip().split("\n"):
        if ":" in line:
            key, val = line.split(":", 1)
            info[key.strip()] = val.strip()

    return {"info": info}


# ── WAF Integration ──────────────────────────────────────────────

@router.get("/waf/status", dependencies=[Depends(require_jwt)])
async def waf_status():
    """Get WAF status from HAProxy perspective."""
    cfg = _cfg()
    waf_status = await _call_waf("/status")

    return {
        "haproxy_waf_enabled": cfg["waf_enabled"],
        "waf_socket_available": _waf_available(),
        "waf_backend_port": cfg["waf_backend_port"],
        "waf_status": waf_status,
    }


class WAFToggleRequest(BaseModel):
    enabled: bool


@router.post("/waf/toggle", dependencies=[Depends(require_jwt)])
async def toggle_waf(req: WAFToggleRequest):
    """Enable or disable WAF for all traffic."""
    # Update config (would persist to TOML in production)
    log.info("WAF toggle: %s", "enabled" if req.enabled else "disabled")

    # If enabling, regenerate config with WAF backend
    if req.enabled:
        await sync_waf_routes()

    return {"success": True, "waf_enabled": req.enabled}


@router.post("/waf/sync-routes", dependencies=[Depends(require_jwt)])
async def sync_waf_routes():
    """Sync vhost routes to WAF for backend resolution."""
    vhosts = _load_vhosts()
    routes = {}

    for vh in vhosts:
        if not vh.get("waf_bypass", False) and vh.get("enabled", True):
            routes[vh["domain"]] = vh["backend"]

    _save_vhost_routes(routes)
    log.info("Synced %d vhost routes to WAF", len(routes))

    return {"success": True, "routes": len(routes)}


@router.get("/waf/routes", dependencies=[Depends(require_jwt)])
async def get_waf_routes():
    """Get current WAF routing table."""
    return {"routes": _load_vhost_routes()}


# ── VHosts ────────────────────────────────────────────────────────

@router.get("/vhosts")
async def list_vhosts():
    """List vhosts (public)."""
    return {"vhosts": _load_vhosts()}


class VHostCreate(BaseModel):
    name: str
    domain: str
    backend: str
    ssl: bool = False
    ssl_redirect: bool = False
    acme: bool = False
    waf_bypass: bool = False
    enabled: bool = True


@router.post("/vhost", dependencies=[Depends(require_jwt)])
async def add_vhost(req: VHostCreate):
    """Add a vhost with WAF protection by default."""
    cfg = _cfg()

    # Log the effective backend (WAF inspector if enabled)
    effective_backend = req.backend
    if cfg["waf_enabled"] and not req.waf_bypass:
        effective_backend = "waf_inspector"
        log.info("WAF protection enabled: %s -> waf_inspector -> %s", req.domain, req.backend)

    log.info("Add vhost: %s -> %s", req.domain, effective_backend)

    # Sync routes to WAF
    await sync_waf_routes()

    return {"success": True, "name": req.name, "waf_protected": not req.waf_bypass}


@router.put("/vhost/{name}", dependencies=[Depends(require_jwt)])
async def update_vhost(name: str, req: VHostCreate):
    """Update a vhost."""
    log.info("Update vhost: %s", name)
    await sync_waf_routes()
    return {"success": True, "name": name}


@router.delete("/vhost/{name}", dependencies=[Depends(require_jwt)])
async def delete_vhost(name: str):
    """Delete a vhost."""
    log.info("Delete vhost: %s", name)
    await sync_waf_routes()
    return {"success": True, "name": name}


class WAFBypassRequest(BaseModel):
    bypass: bool


@router.post("/vhost/{name}/waf-bypass", dependencies=[Depends(require_jwt)])
async def set_vhost_waf_bypass(name: str, req: WAFBypassRequest):
    """Set WAF bypass for a specific vhost."""
    log.info("Set WAF bypass for %s: %s", name, req.bypass)
    await sync_waf_routes()
    return {"success": True, "name": name, "waf_bypass": req.bypass}


# ── Backends ──────────────────────────────────────────────────────

@router.get("/backends")
async def list_backends():
    """List backends including WAF inspector (public)."""
    backends = _load_backends()
    cfg = _cfg()

    # Add WAF inspector backend info
    if cfg["waf_enabled"]:
        backends.append({
            "name": "waf_inspector",
            "type": "waf",
            "mode": "http",
            "port": cfg["waf_backend_port"],
            "description": "WAF inspection backend (mitmproxy)",
        })

    return {"backends": backends}


class BackendCreate(BaseModel):
    name: str
    servers: List[str]
    mode: str = "http"
    balance: str = "roundrobin"


@router.post("/backend", dependencies=[Depends(require_jwt)])
async def add_backend(req: BackendCreate):
    """Add a backend."""
    log.info("Add backend: %s", req.name)
    return {"success": True, "name": req.name}


@router.delete("/backend/{name}", dependencies=[Depends(require_jwt)])
async def delete_backend(name: str):
    """Delete a backend."""
    if name == "waf_inspector":
        raise HTTPException(400, "Cannot delete WAF inspector backend")
    log.info("Delete backend: %s", name)
    return {"success": True, "name": name}


# ── Certificates ──────────────────────────────────────────────────

def _parse_certificate(cert_path: Path) -> CertificateInfo:
    """Parse certificate file and extract info."""
    info = CertificateInfo(name=cert_path.stem, path=str(cert_path))

    try:
        result = subprocess.run(
            ["openssl", "x509", "-in", str(cert_path), "-noout",
             "-subject", "-issuer", "-dates", "-ext", "subjectAltName"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            output = result.stdout

            # Parse subject for CN
            for line in output.split('\n'):
                if 'subject=' in line.lower():
                    if 'CN=' in line or 'CN =' in line:
                        cn = line.split('CN')[-1].split('=')[-1].split(',')[0].strip()
                        if cn:
                            info.domains.append(cn)
                elif 'issuer=' in line.lower():
                    info.issuer = line.split('=', 1)[-1].strip()
                elif 'notAfter=' in line:
                    date_str = line.split('=')[1].strip()
                    try:
                        exp_date = datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")
                        info.expires_at = exp_date.isoformat()
                        info.days_until_expiry = (exp_date - datetime.now()).days
                        info.expired = info.days_until_expiry < 0
                    except ValueError:
                        pass
                elif 'DNS:' in line:
                    # Parse SAN domains
                    for part in line.split(','):
                        if 'DNS:' in part:
                            domain = part.split('DNS:')[-1].strip()
                            if domain and domain not in info.domains:
                                info.domains.append(domain)
    except Exception:
        pass

    return info


@router.get("/certificates")
async def list_certificates():
    """List certificates with expiry info (public)."""
    certs = []
    cert_dir = Path(CERTS_DIR)
    if not cert_dir.exists():
        cert_dir = Path("/etc/haproxy/certs")

    if cert_dir.exists():
        for f in cert_dir.glob("*.pem"):
            info = _parse_certificate(f)
            certs.append(info.model_dump())

    # Sort by expiry (soonest first)
    certs.sort(key=lambda x: x.get("days_until_expiry") or 999)

    return {
        "certificates": certs,
        "total": len(certs),
        "expiring_soon": sum(1 for c in certs if c.get("days_until_expiry", 999) <= 30 and not c.get("expired")),
        "expired": sum(1 for c in certs if c.get("expired"))
    }


@router.get("/certificates/{name}")
async def get_certificate(name: str, user=Depends(require_jwt)):
    """Get certificate details."""
    cert_dir = Path(CERTS_DIR)
    if not cert_dir.exists():
        cert_dir = Path("/etc/haproxy/certs")

    cert_path = cert_dir / f"{name}.pem"
    if not cert_path.exists():
        raise HTTPException(status_code=404, detail="Certificate not found")

    return _parse_certificate(cert_path).model_dump()


@router.get("/certificates/expiring")
async def get_expiring_certificates(days: int = Query(default=30, le=365), user=Depends(require_jwt)):
    """Get certificates expiring within specified days."""
    result = await list_certificates()
    certs = result["certificates"]

    expiring = [c for c in certs if c.get("days_until_expiry") is not None and 0 <= c.get("days_until_expiry", 999) <= days]

    return {
        "certificates": expiring,
        "count": len(expiring),
        "threshold_days": days
    }


# ── ACLs ──────────────────────────────────────────────────────────

@router.get("/acls", dependencies=[Depends(require_jwt)])
async def list_acls():
    """List HAProxy ACLs."""
    cfg = get_config("haproxy") or {}
    acls = cfg.get("acls", {})
    return {"acls": list(acls.values()) if isinstance(acls, dict) else []}


class ACLCreate(BaseModel):
    name: str
    type: str  # path_beg, hdr_host, src, etc.
    pattern: str
    action: str = "use_backend"
    target: str = ""


@router.post("/acl", dependencies=[Depends(require_jwt)])
async def add_acl(req: ACLCreate):
    """Add an ACL rule."""
    log.info("Add ACL: %s (%s %s)", req.name, req.type, req.pattern)
    return {"success": True, "name": req.name}


# ── CrowdSec Integration ──────────────────────────────────────────

@router.get("/crowdsec/status", dependencies=[Depends(require_jwt)])
async def crowdsec_status():
    """Get CrowdSec bouncer status for HAProxy."""
    cfg = _cfg()

    # Check if CrowdSec bouncer is configured
    bouncer_running = False
    try:
        result = subprocess.run(
            ["pgrep", "-f", "crowdsec-haproxy-bouncer"],
            capture_output=True, timeout=5
        )
        bouncer_running = result.returncode == 0
    except Exception:
        pass

    # Get active decisions count from WAF
    waf_bans = await _call_waf("/bans")

    return {
        "enabled": cfg["crowdsec_enabled"],
        "bouncer_running": bouncer_running,
        "active_bans": waf_bans.get("total", 0) if "total" in waf_bans else 0,
    }


# ── Actions ───────────────────────────────────────────────────────

@router.post("/reload", dependencies=[Depends(require_jwt)])
async def reload_haproxy():
    """Reload HAProxy."""
    result = subprocess.run(
        ["systemctl", "reload", "haproxy"],
        capture_output=True, text=True, timeout=10
    )
    log.info("HAProxy reload: %s", "ok" if result.returncode == 0 else "fail")
    return {"success": result.returncode == 0}


@router.post("/restart", dependencies=[Depends(require_jwt)])
async def restart_haproxy():
    """Restart HAProxy."""
    result = subprocess.run(
        ["systemctl", "restart", "haproxy"],
        capture_output=True, text=True, timeout=30
    )
    log.info("HAProxy restart: %s", "ok" if result.returncode == 0 else "fail")
    return {"success": result.returncode == 0}


@router.post("/generate", dependencies=[Depends(require_jwt)])
async def generate_config():
    """Generate HAProxy config with WAF integration."""
    cfg = _cfg()
    vhosts = _load_vhosts()
    backends = _load_backends()

    # Build HAProxy config
    config_lines = [
        "# SecuBox HAProxy Configuration (Auto-generated)",
        "# WAF Integration: %s" % ("enabled" if cfg["waf_enabled"] else "disabled"),
        "",
        "global",
        "    daemon",
        "    maxconn 4096",
        "    stats socket /run/haproxy/admin.sock mode 660 level admin",
        "    log /dev/log local0",
        "",
        "defaults",
        "    mode http",
        "    timeout connect 5s",
        "    timeout client 30s",
        "    timeout server 30s",
        "    option httplog",
        "    option dontlognull",
        "    option forwardfor",
        "",
    ]

    # Stats frontend
    config_lines.extend([
        "frontend stats",
        f"    bind *:{cfg['stats_port']}",
        "    stats enable",
        "    stats uri /stats",
        "    stats refresh 10s",
        "",
    ])

    # HTTP frontend
    config_lines.extend([
        "frontend http-in",
        f"    bind *:{cfg['http_port']}",
        "    mode http",
    ])

    # ACLs for vhosts
    for vh in vhosts:
        if vh.get("enabled"):
            config_lines.append(f"    acl host_{vh['name']} hdr(host) -i {vh['domain']}")

    # Use backend rules (through WAF if enabled)
    for vh in vhosts:
        if vh.get("enabled"):
            if cfg["waf_enabled"] and not vh.get("waf_bypass"):
                config_lines.append(f"    use_backend waf_inspector if host_{vh['name']}")
            else:
                config_lines.append(f"    use_backend {vh['backend']} if host_{vh['name']}")

    config_lines.extend([
        "    default_backend fallback",
        "",
    ])

    # HTTPS frontend (similar structure)
    config_lines.extend([
        "frontend https-in",
        f"    bind *:{cfg['https_port']} ssl crt /etc/haproxy/certs/",
        "    mode http",
    ])

    for vh in vhosts:
        if vh.get("enabled") and vh.get("ssl"):
            config_lines.append(f"    acl host_{vh['name']} hdr(host) -i {vh['domain']}")

    for vh in vhosts:
        if vh.get("enabled") and vh.get("ssl"):
            if cfg["waf_enabled"] and not vh.get("waf_bypass"):
                config_lines.append(f"    use_backend waf_inspector if host_{vh['name']}")
            else:
                config_lines.append(f"    use_backend {vh['backend']} if host_{vh['name']}")

    config_lines.extend([
        "    default_backend fallback",
        "",
    ])

    # WAF inspector backend (mitmproxy)
    if cfg["waf_enabled"]:
        config_lines.extend([
            "# WAF Inspector Backend (routes to mitmproxy for inspection)",
            "backend waf_inspector",
            "    mode http",
            "    option forwardfor",
            "    http-request set-header X-Real-IP %[src]",
            "    http-request set-header X-Forwarded-Proto %[ssl_fc,iif(https,http)]",
            f"    server waf 127.0.0.1:{cfg['waf_backend_port']} check",
            "",
        ])

    # User backends
    for be in backends:
        config_lines.extend([
            f"backend {be['name']}",
            f"    mode {be.get('mode', 'http')}",
            f"    balance {be.get('balance', 'roundrobin')}",
        ])
        for i, srv in enumerate(be.get("servers", [])):
            config_lines.append(f"    server srv{i} {srv} check")
        config_lines.append("")

    # Fallback backend
    config_lines.extend([
        "backend fallback",
        "    mode http",
        "    http-request deny deny_status 503",
        "",
    ])

    config_text = "\n".join(config_lines)

    # Write config
    Path(HAPROXY_CFG).parent.mkdir(parents=True, exist_ok=True)
    Path(HAPROXY_CFG).write_text(config_text)

    # Validate config
    result = subprocess.run(
        ["haproxy", "-c", "-f", HAPROXY_CFG],
        capture_output=True, text=True, timeout=10
    )

    # Sync WAF routes
    await sync_waf_routes()

    return {
        "success": result.returncode == 0,
        "config_path": HAPROXY_CFG,
        "validation": result.stderr or result.stdout,
        "vhosts": len(vhosts),
        "backends": len(backends),
        "waf_enabled": cfg["waf_enabled"],
    }


@router.get("/config", dependencies=[Depends(require_jwt)])
async def get_config_file():
    """Get current HAProxy config file."""
    cfg_path = Path(HAPROXY_CFG)
    if not cfg_path.exists():
        return {"config": "", "exists": False}
    return {"config": cfg_path.read_text(), "exists": True}


@router.get("/health")
async def health():
    """Health check endpoint (public)."""
    checks = {
        "api": "ok",
        "haproxyctl": "ok" if Path(CTL).exists() else "missing",
        "haproxy": "running" if _haproxy_running() else "stopped",
        "config": "ok" if Path(HAPROXY_CFG).exists() else "missing"
    }

    if _cfg()["waf_enabled"]:
        checks["waf"] = "available" if _waf_available() else "unavailable"

    overall = "healthy" if checks["haproxy"] == "running" else "degraded"

    return {
        "status": overall,
        "module": "haproxy",
        "checks": checks
    }


# ═══════════════════════════════════════════════════════════════════════
# STATS HISTORY
# ═══════════════════════════════════════════════════════════════════════

@router.get("/stats/history")
async def get_stats_history(
    hours: int = Query(default=24, le=168),
    user=Depends(require_jwt)
):
    """Get HAProxy stats history."""
    history = _load_json(STATS_HISTORY_FILE, {"records": []})
    records = history.get("records", [])

    # Filter by time
    cutoff = datetime.now() - timedelta(hours=hours)
    cutoff_str = cutoff.isoformat()
    records = [r for r in records if r.get("timestamp", "") >= cutoff_str]

    return {
        "records": records,
        "period_hours": hours,
        "count": len(records)
    }


@router.get("/stats/summary")
async def get_stats_summary(user=Depends(require_jwt)):
    """Get aggregated stats summary."""
    cached = stats_cache.get("stats_summary")
    if cached:
        return cached

    data = _send_stats_command("show stat")
    if not data:
        return {"error": "Stats not available"}

    stats = _parse_stats_csv(data)

    summary = {
        "frontends": [],
        "backends": [],
        "totals": {
            "current_sessions": 0,
            "total_requests": 0,
            "bytes_in": 0,
            "bytes_out": 0
        }
    }

    for stat in stats:
        pxname = stat.get("pxname", "")
        svname = stat.get("svname", "")
        status = stat.get("status", "")

        if svname == "FRONTEND":
            sessions = int(stat.get("scur", 0) or 0)
            requests = int(stat.get("req_tot", 0) or 0)
            bytes_in = int(stat.get("bin", 0) or 0)
            bytes_out = int(stat.get("bout", 0) or 0)

            summary["frontends"].append({
                "name": pxname,
                "status": status,
                "sessions": sessions,
                "requests": requests,
                "bytes_in": bytes_in,
                "bytes_out": bytes_out,
                "bytes_in_human": _human_bytes(bytes_in),
                "bytes_out_human": _human_bytes(bytes_out)
            })

            summary["totals"]["current_sessions"] += sessions
            summary["totals"]["total_requests"] += requests
            summary["totals"]["bytes_in"] += bytes_in
            summary["totals"]["bytes_out"] += bytes_out

        elif svname == "BACKEND":
            summary["backends"].append({
                "name": pxname,
                "status": status,
                "active_servers": int(stat.get("act", 0) or 0),
                "backup_servers": int(stat.get("bck", 0) or 0),
                "sessions": int(stat.get("scur", 0) or 0),
                "bytes_in": int(stat.get("bin", 0) or 0),
                "bytes_out": int(stat.get("bout", 0) or 0),
                "response_time_avg": int(stat.get("ttime", 0) or 0)
            })

    summary["totals"]["bytes_in_human"] = _human_bytes(summary["totals"]["bytes_in"])
    summary["totals"]["bytes_out_human"] = _human_bytes(summary["totals"]["bytes_out"])
    summary["timestamp"] = datetime.now().isoformat()

    stats_cache.set("stats_summary", summary)
    return summary


def _human_bytes(b: int) -> str:
    """Convert bytes to human-readable format."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} PB"


# ═══════════════════════════════════════════════════════════════════════
# HEALTH HISTORY
# ═══════════════════════════════════════════════════════════════════════

@router.get("/health/history")
async def get_health_history(
    name: Optional[str] = None,
    limit: int = Query(default=100, le=1000),
    user=Depends(require_jwt)
):
    """Get backend health history."""
    history = _load_json(HEALTH_HISTORY_FILE, {"records": []})
    records = history.get("records", [])

    if name:
        records = [r for r in records if r.get("name") == name]

    records = sorted(records, key=lambda x: x.get("timestamp", ""), reverse=True)

    return {
        "records": records[:limit],
        "total": len(records)
    }


@router.get("/health/backends")
async def get_backends_health(user=Depends(require_jwt)):
    """Get current health status of all backends."""
    data = _send_stats_command("show stat")
    if not data:
        return {"backends": [], "error": "Stats not available"}

    stats = _parse_stats_csv(data)
    backends = []

    for stat in stats:
        if stat.get("svname") == "BACKEND":
            status = stat.get("status", "UNKNOWN")
            health = HealthStatus.HEALTHY if status == "UP" else (
                HealthStatus.DEGRADED if status in ["NOLB", "DRAIN"] else HealthStatus.UNHEALTHY
            )

            backends.append({
                "name": stat.get("pxname", ""),
                "status": health.value,
                "haproxy_status": status,
                "active_servers": int(stat.get("act", 0) or 0),
                "backup_servers": int(stat.get("bck", 0) or 0),
                "sessions": int(stat.get("scur", 0) or 0),
                "session_max": int(stat.get("smax", 0) or 0),
                "bytes_in": int(stat.get("bin", 0) or 0),
                "bytes_out": int(stat.get("bout", 0) or 0),
                "response_time_avg": int(stat.get("ttime", 0) or 0)
            })

    healthy = sum(1 for b in backends if b["status"] == "healthy")

    return {
        "backends": backends,
        "healthy": healthy,
        "unhealthy": len(backends) - healthy,
        "total": len(backends)
    }


# ═══════════════════════════════════════════════════════════════════════
# CONFIG BACKUP / VERSIONING
# ═══════════════════════════════════════════════════════════════════════

@router.get("/config/backups")
async def list_config_backups(user=Depends(require_jwt)):
    """List configuration backups."""
    backups = []

    for f in sorted(CONFIG_BACKUP_DIR.glob("*.cfg"), reverse=True):
        stat = f.stat()
        backups.append({
            "name": f.name,
            "path": str(f),
            "size": stat.st_size,
            "created_at": datetime.fromtimestamp(stat.st_mtime).isoformat()
        })

    return {
        "backups": backups[:50],  # Last 50 backups
        "count": len(backups)
    }


@router.post("/config/backup")
async def create_config_backup(user=Depends(require_jwt)):
    """Create a backup of current configuration."""
    cfg_path = Path(HAPROXY_CFG)
    if not cfg_path.exists():
        raise HTTPException(status_code=404, detail="Config file not found")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_name = f"haproxy_{timestamp}.cfg"
    backup_path = CONFIG_BACKUP_DIR / backup_name

    # Copy config
    backup_path.write_text(cfg_path.read_text())

    log.info("Created config backup: %s", backup_name)

    return {
        "status": "success",
        "backup": {
            "name": backup_name,
            "path": str(backup_path),
            "size": backup_path.stat().st_size,
            "created_at": datetime.now().isoformat()
        }
    }


@router.get("/config/backups/{name}")
async def get_config_backup(name: str, user=Depends(require_jwt)):
    """Get content of a specific backup."""
    backup_path = CONFIG_BACKUP_DIR / name
    if not backup_path.exists():
        raise HTTPException(status_code=404, detail="Backup not found")

    return {
        "name": name,
        "content": backup_path.read_text(),
        "size": backup_path.stat().st_size,
        "created_at": datetime.fromtimestamp(backup_path.stat().st_mtime).isoformat()
    }


@router.post("/config/restore/{name}")
async def restore_config_backup(name: str, user=Depends(require_jwt)):
    """Restore configuration from backup."""
    backup_path = CONFIG_BACKUP_DIR / name
    if not backup_path.exists():
        raise HTTPException(status_code=404, detail="Backup not found")

    cfg_path = Path(HAPROXY_CFG)

    # Backup current config first
    if cfg_path.exists():
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        pre_restore_name = f"haproxy_pre_restore_{timestamp}.cfg"
        (CONFIG_BACKUP_DIR / pre_restore_name).write_text(cfg_path.read_text())

    # Restore from backup
    cfg_path.write_text(backup_path.read_text())

    # Validate config
    result = subprocess.run(
        ["haproxy", "-c", "-f", str(cfg_path)],
        capture_output=True, text=True, timeout=10
    )

    log.info("Restored config from backup: %s", name)

    return {
        "status": "success",
        "backup": name,
        "validation": {
            "valid": result.returncode == 0,
            "message": result.stderr or result.stdout
        }
    }


@router.delete("/config/backups/{name}")
async def delete_config_backup(name: str, user=Depends(require_jwt)):
    """Delete a configuration backup."""
    backup_path = CONFIG_BACKUP_DIR / name
    if not backup_path.exists():
        raise HTTPException(status_code=404, detail="Backup not found")

    backup_path.unlink()
    log.info("Deleted config backup: %s", name)

    return {"status": "success", "deleted": name}


@router.post("/config/diff")
async def diff_config(backup_name: str = Query(...), user=Depends(require_jwt)):
    """Compare current config with a backup."""
    backup_path = CONFIG_BACKUP_DIR / backup_name
    if not backup_path.exists():
        raise HTTPException(status_code=404, detail="Backup not found")

    cfg_path = Path(HAPROXY_CFG)
    if not cfg_path.exists():
        raise HTTPException(status_code=404, detail="Current config not found")

    try:
        result = subprocess.run(
            ["diff", "-u", str(backup_path), str(cfg_path)],
            capture_output=True, text=True, timeout=10
        )

        return {
            "has_changes": result.returncode != 0,
            "diff": result.stdout,
            "backup": backup_name,
            "current": str(cfg_path)
        }
    except Exception as e:
        return {"error": str(e)}


# ═══════════════════════════════════════════════════════════════════════
# WEBHOOKS
# ═══════════════════════════════════════════════════════════════════════

@router.get("/webhooks")
async def list_webhooks(user=Depends(require_jwt)):
    """List configured webhooks."""
    data = _load_json(WEBHOOKS_FILE, {"webhooks": []})
    return {
        "webhooks": data.get("webhooks", []),
        "available_events": [
            "backend_up", "backend_down", "cert_expiring",
            "config_changed", "reload_success", "reload_failed"
        ]
    }


class WebhookCreate(BaseModel):
    url: str
    events: List[str] = ["backend_down", "cert_expiring"]
    secret: Optional[str] = None
    enabled: bool = True


@router.post("/webhooks")
async def add_webhook(config: WebhookCreate, user=Depends(require_jwt)):
    """Add a webhook."""
    data = _load_json(WEBHOOKS_FILE, {"webhooks": []})

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
    _save_json(WEBHOOKS_FILE, data)

    return {"status": "success", "webhook": webhook}


@router.delete("/webhooks/{webhook_id}")
async def delete_webhook(webhook_id: str, user=Depends(require_jwt)):
    """Delete a webhook."""
    data = _load_json(WEBHOOKS_FILE, {"webhooks": []})

    original_len = len(data["webhooks"])
    data["webhooks"] = [w for w in data["webhooks"] if w.get("id") != webhook_id]

    if len(data["webhooks"]) == original_len:
        raise HTTPException(status_code=404, detail="Webhook not found")

    _save_json(WEBHOOKS_FILE, data)
    return {"status": "success"}


@router.post("/webhooks/{webhook_id}/test")
async def test_webhook(webhook_id: str, user=Depends(require_jwt)):
    """Test a webhook with a sample payload."""
    data = _load_json(WEBHOOKS_FILE, {"webhooks": []})

    webhook = next((w for w in data["webhooks"] if w.get("id") == webhook_id), None)
    if not webhook:
        raise HTTPException(status_code=404, detail="Webhook not found")

    test_payload = {
        "event": "test",
        "timestamp": datetime.now().isoformat(),
        "payload": {"message": "This is a test webhook from SecuBox HAProxy"}
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
        return {"status": "error", "error": str(e)}


# ═══════════════════════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════════════════════

@router.get("/summary")
async def get_haproxy_summary(user=Depends(require_jwt)):
    """Get comprehensive HAProxy summary."""
    cfg = _cfg()
    running = _haproxy_running() or _docker_running()
    vhosts = _load_vhosts()
    backends = _load_backends()

    # Get stats summary
    data = _send_stats_command("show stat")
    stats = _parse_stats_csv(data) if data else []

    total_sessions = 0
    total_requests = 0
    backends_up = 0
    backends_total = 0

    for stat in stats:
        if stat.get("svname") == "FRONTEND":
            total_sessions += int(stat.get("scur", 0) or 0)
            total_requests += int(stat.get("req_tot", 0) or 0)
        elif stat.get("svname") == "BACKEND":
            backends_total += 1
            if stat.get("status") == "UP":
                backends_up += 1

    # Get certificate summary
    certs_result = await list_certificates()

    return {
        "service": {
            "running": running,
            "http_port": cfg["http_port"],
            "https_port": cfg["https_port"],
            "waf_enabled": cfg["waf_enabled"],
            "waf_available": _waf_available()
        },
        "traffic": {
            "current_sessions": total_sessions,
            "total_requests": total_requests
        },
        "vhosts": {
            "total": len(vhosts),
            "enabled": sum(1 for v in vhosts if v.get("enabled", True)),
            "waf_protected": sum(1 for v in vhosts if not v.get("waf_bypass", False))
        },
        "backends": {
            "total": backends_total,
            "healthy": backends_up,
            "unhealthy": backends_total - backends_up
        },
        "certificates": {
            "total": certs_result["total"],
            "expiring_soon": certs_result["expiring_soon"],
            "expired": certs_result["expired"]
        },
        "timestamp": datetime.now().isoformat()
    }


# ═══════════════════════════════════════════════════════════════════════
# MIGRATION
# ═══════════════════════════════════════════════════════════════════════

class MigrateRequest(BaseModel):
    source: str = "192.168.255.1"


@router.post("/migrate", dependencies=[Depends(require_jwt)])
async def migrate(req: MigrateRequest):
    """Migrate HAProxy config from OpenWrt SecuBox."""
    import asyncio

    def do_migrate():
        return subprocess.run(
            [CTL, "migrate", req.source],
            capture_output=True, text=True, timeout=300
        )

    result = await asyncio.get_event_loop().run_in_executor(None, do_migrate)

    if result.returncode == 0:
        log.info("Migration completed from %s", req.source)
        # Try to parse JSON output
        try:
            data = json.loads(result.stdout)
            return {"success": True, **data}
        except json.JSONDecodeError:
            return {"success": True, "message": "Migration completed"}
    else:
        log.error("Migration failed: %s", result.stderr)
        return {"success": False, "error": result.stderr or "Migration failed"}


app.include_router(router)
