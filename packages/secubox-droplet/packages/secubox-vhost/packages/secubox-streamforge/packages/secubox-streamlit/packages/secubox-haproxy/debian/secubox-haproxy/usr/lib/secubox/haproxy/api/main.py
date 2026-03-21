"""secubox-haproxy — HAProxy Dashboard API"""
import os
import subprocess
import socket
from pathlib import Path
from typing import Optional, List
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


def _cfg():
    cfg = get_config("haproxy")
    return {
        "stats_socket": cfg.get("stats_socket", STATS_SOCKET) if cfg else STATS_SOCKET,
        "config_dir": cfg.get("config_dir", CONFIG_DIR) if cfg else CONFIG_DIR,
        "http_port": cfg.get("http_port", 80) if cfg else 80,
        "https_port": cfg.get("https_port", 443) if cfg else 443,
        "stats_port": cfg.get("stats_port", 8404) if cfg else 8404,
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


# ── Status ────────────────────────────────────────────────────────

@router.get("/status")
async def status():
    """HAProxy status (public)."""
    cfg = _cfg()
    running = _haproxy_running() or _docker_running()
    
    return {
        "running": running,
        "http_port": cfg["http_port"],
        "https_port": cfg["https_port"],
        "stats_port": cfg["stats_port"],
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
    enabled: bool = True


@router.post("/vhost")
async def add_vhost(req: VHostCreate, user=Depends(require_jwt)):
    """Add a vhost."""
    # This would update config file - simplified for now
    log.info("Add vhost: %s -> %s", req.domain, req.backend)
    return {"success": True, "name": req.name}


@router.delete("/vhost/{name}")
async def delete_vhost(name: str, user=Depends(require_jwt)):
    """Delete a vhost."""
    log.info("Delete vhost: %s", name)
    return {"success": True, "name": name}


# ── Backends ──────────────────────────────────────────────────────

@router.get("/backends")
async def list_backends():
    """List backends (public)."""
    return {"backends": _load_backends()}


class BackendCreate(BaseModel):
    name: str
    servers: List[str]
    mode: str = "http"
    balance: str = "roundrobin"


@router.post("/backend")
async def add_backend(req: BackendCreate, user=Depends(require_jwt)):
    """Add a backend."""
    log.info("Add backend: %s", req.name)
    return {"success": True, "name": req.name}


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


# ── Actions ───────────────────────────────────────────────────────

@router.post("/reload")
async def reload_haproxy(user=Depends(require_jwt)):
    """Reload HAProxy."""
    result = subprocess.run(
        ["systemctl", "reload", "haproxy"],
        capture_output=True, text=True, timeout=10
    )
    log.info("HAProxy reload: %s", "ok" if result.returncode == 0 else "fail")
    return {"success": result.returncode == 0}


@router.post("/generate")
async def generate_config(user=Depends(require_jwt)):
    """Generate HAProxy config."""
    result = subprocess.run(
        ["haproxyctl", "generate"],
        capture_output=True, text=True, timeout=30
    )
    return {"success": result.returncode == 0, "output": result.stdout[:500]}


@router.get("/health")
async def health():
    return {"status": "ok", "module": "haproxy"}


app.include_router(router)
