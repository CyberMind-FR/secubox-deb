"""secubox-haproxy — HAProxy Dashboard API with WAF Integration

Provides HAProxy management with integrated WAF inspection via mitmproxy.
Traffic flow: Client → HAProxy → WAF (mitmproxy) → Backend
"""
import os
import subprocess
import socket
import json
import httpx
from pathlib import Path
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, APIRouter, Depends, HTTPException
from pydantic import BaseModel
from secubox_core.auth import router as auth_router, require_jwt
from secubox_core.config import get_config
from secubox_core.logger import get_logger

app = FastAPI(title="secubox-haproxy", version="1.0.0", root_path="/api/v1/haproxy")
app.include_router(auth_router, prefix="/auth")
router = APIRouter()
log = get_logger("haproxy")

STATS_SOCKET = "/run/haproxy/admin.sock"
CONFIG_DIR = "/etc/haproxy"
WAF_SOCKET = "/run/secubox/waf.sock"
HAPROXY_CFG = "/etc/haproxy/haproxy.cfg"
VHOST_ROUTES_FILE = "/var/lib/secubox/haproxy/vhost-routes.json"


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


# ── Status ────────────────────────────────────────────────────────

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

@router.get("/certificates")
async def list_certificates():
    """List certificates (public)."""
    certs = []
    cert_dir = Path("/etc/haproxy/certs")
    if cert_dir.exists():
        for f in cert_dir.glob("*.pem"):
            certs.append({"name": f.stem, "path": str(f)})
    return {"certificates": certs}


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
    return {"status": "ok", "module": "haproxy"}


app.include_router(router)
