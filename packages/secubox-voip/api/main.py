"""secubox-voip — FastAPI application for VoIP/PBX management.

Provides Asterisk/FreePBX Docker container management with extension,
trunk, route, IVR, and voicemail configuration.
"""
import asyncio
import hashlib
import json
import secrets
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any

from fastapi import FastAPI, APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from secubox_core.auth import router as auth_router, require_jwt
from secubox_core.logger import get_logger

app = FastAPI(title="secubox-voip", version="1.0.0", root_path="/api/v1/voip")
app.include_router(auth_router, prefix="/auth")
router = APIRouter()
log = get_logger("voip")

# Configuration
CONFIG_FILE = Path("/etc/secubox/voip.toml")
CONTAINER_NAME = "secbx-freepbx"
DEFAULT_CONFIG = {
    "enabled": False,
    "image": "tiredofit/freepbx:latest",
    "http_port": 8180,
    "sip_port": 5060,
    "rtp_start": 10000,
    "rtp_end": 20000,
    "data_path": "/srv/voip",
    "timezone": "Europe/Paris",
    "domain": "voip.secubox.local",
    "haproxy": False,
}

# Data files
EXTENSIONS_FILE = Path("/etc/secubox/voip-extensions.json")
TRUNKS_FILE = Path("/etc/secubox/voip-trunks.json")
ROUTES_FILE = Path("/etc/secubox/voip-routes.json")
IVR_FILE = Path("/etc/secubox/voip-ivr.json")


# ============================================================================
# Password Hashing (PBKDF2-SHA256)
# ============================================================================

def hash_password(password: str, salt: str = None) -> dict:
    """Hash password using PBKDF2-SHA256 with random salt.

    Returns:
        dict with 'hash' and 'salt' fields for storage
    """
    if salt is None:
        salt = secrets.token_hex(16)

    # PBKDF2 with SHA256, 100000 iterations (OWASP recommendation)
    pw_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        100000
    ).hex()

    return {"hash": pw_hash, "salt": salt}


def verify_password(password: str, stored_hash: str, salt: str) -> bool:
    """Verify password against stored hash."""
    computed = hash_password(password, salt)
    return secrets.compare_digest(computed["hash"], stored_hash)


# ============================================================================
# Models
# ============================================================================

class VoIPConfig(BaseModel):
    enabled: bool = False
    image: str = "tiredofit/freepbx:latest"
    http_port: int = 8180
    sip_port: int = 5060
    rtp_start: int = 10000
    rtp_end: int = 20000
    data_path: str = "/srv/voip"
    timezone: str = "Europe/Paris"
    domain: str = "voip.secubox.local"
    haproxy: bool = False


class Extension(BaseModel):
    number: str
    name: str
    password: Optional[str] = None
    voicemail: bool = False
    context: str = "from-internal"


class Trunk(BaseModel):
    name: str
    type: str = "sip"  # sip, pjsip, iax2
    host: str
    username: Optional[str] = None
    password: Optional[str] = None
    context: str = "from-trunk"
    codecs: List[str] = ["ulaw", "alaw", "g722"]


class Route(BaseModel):
    name: str
    direction: str = "outbound"  # inbound, outbound
    pattern: str
    trunk: Optional[str] = None
    destination: Optional[str] = None
    priority: int = 1


class IVRMenu(BaseModel):
    name: str
    description: str = ""
    announcement: Optional[str] = None
    timeout: int = 10
    options: Dict[str, str] = {}


# ============================================================================
# Helpers
# ============================================================================

def get_config() -> dict:
    """Load VoIP configuration."""
    if CONFIG_FILE.exists():
        try:
            import tomllib
            return tomllib.loads(CONFIG_FILE.read_text())
        except Exception:
            pass
    return DEFAULT_CONFIG.copy()


def save_config(config: dict):
    """Save VoIP configuration."""
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    lines = ["# VoIP/PBX configuration"]
    for k, v in config.items():
        if isinstance(v, bool):
            lines.append(f"{k} = {str(v).lower()}")
        elif isinstance(v, int):
            lines.append(f"{k} = {v}")
        elif isinstance(v, list):
            lines.append(f'{k} = {v}')
        else:
            lines.append(f'{k} = "{v}"')
    CONFIG_FILE.write_text("\n".join(lines) + "\n")


def load_json(path: Path) -> List[dict]:
    """Load JSON data file."""
    if path.exists():
        try:
            return json.loads(path.read_text())
        except Exception:
            pass
    return []


def save_json(path: Path, data: List[dict]):
    """Save JSON data file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2))


def detect_runtime() -> Optional[str]:
    """Detect container runtime."""
    if shutil.which("podman"):
        return "podman"
    if shutil.which("docker"):
        return "docker"
    return None


def get_container_status() -> dict:
    """Get FreePBX container status."""
    rt = detect_runtime()
    if not rt:
        return {"status": "no_runtime", "uptime": ""}

    try:
        result = subprocess.run(
            [rt, "ps", "--filter", f"name={CONTAINER_NAME}", "--format", "{{.Status}}"],
            capture_output=True, text=True, timeout=5
        )
        if result.stdout.strip():
            return {"status": "running", "uptime": result.stdout.strip()}

        result = subprocess.run(
            [rt, "ps", "-a", "--filter", f"name={CONTAINER_NAME}", "--format", "{{.Status}}"],
            capture_output=True, text=True, timeout=5
        )
        if result.stdout.strip():
            return {"status": "stopped", "uptime": ""}

        return {"status": "not_installed", "uptime": ""}
    except Exception:
        return {"status": "error", "uptime": ""}


def is_running() -> bool:
    """Check if FreePBX container is running."""
    return get_container_status()["status"] == "running"


def run_asterisk_cmd(cmd: str) -> str:
    """Run Asterisk CLI command inside container."""
    rt = detect_runtime()
    if not rt or not is_running():
        return ""
    try:
        result = subprocess.run(
            [rt, "exec", CONTAINER_NAME, "asterisk", "-rx", cmd],
            capture_output=True, text=True, timeout=10
        )
        return result.stdout
    except Exception:
        return ""


# ============================================================================
# Public Endpoints
# ============================================================================

@router.get("/health")
async def health():
    """Health check."""
    return {"status": "ok", "module": "voip"}


@router.get("/status")
async def status():
    """Get VoIP service status."""
    cfg = get_config()
    rt = detect_runtime()
    container = get_container_status()
    extensions = load_json(EXTENSIONS_FILE)
    trunks = load_json(TRUNKS_FILE)
    routes = load_json(ROUTES_FILE)

    # Disk usage
    disk_usage = ""
    data_path = Path(cfg.get("data_path", "/srv/voip"))
    if data_path.exists():
        try:
            result = subprocess.run(
                ["du", "-sh", str(data_path)],
                capture_output=True, text=True, timeout=10
            )
            disk_usage = result.stdout.split()[0] if result.stdout else ""
        except Exception:
            pass

    # Active channels (if running)
    active_channels = 0
    if is_running():
        try:
            output = run_asterisk_cmd("core show channels count")
            for line in output.split("\n"):
                if "active channel" in line.lower():
                    parts = line.split()
                    if parts and parts[0].isdigit():
                        active_channels = int(parts[0])
                    break
        except Exception:
            pass

    return {
        "enabled": cfg.get("enabled", False),
        "image": cfg.get("image", "tiredofit/freepbx:latest"),
        "http_port": cfg.get("http_port", 8180),
        "sip_port": cfg.get("sip_port", 5060),
        "data_path": cfg.get("data_path", "/srv/voip"),
        "timezone": cfg.get("timezone", "Europe/Paris"),
        "domain": cfg.get("domain", "voip.secubox.local"),
        "haproxy": cfg.get("haproxy", False),
        "docker_available": rt is not None,
        "runtime": rt or "none",
        "container_status": container["status"],
        "container_uptime": container["uptime"],
        "disk_usage": disk_usage,
        "extensions_count": len(extensions),
        "trunks_count": len(trunks),
        "routes_count": len(routes),
        "active_channels": active_channels,
    }


# ============================================================================
# Protected Endpoints
# ============================================================================

@router.get("/config")
async def get_voip_config(user=Depends(require_jwt)):
    """Get VoIP configuration."""
    return get_config()


@router.post("/config")
async def set_voip_config(config: VoIPConfig, user=Depends(require_jwt)):
    """Update VoIP configuration."""
    cfg = get_config()
    cfg.update(config.dict())
    save_config(cfg)
    log.info(f"Config updated by {user.get('sub', 'unknown')}")
    return {"success": True}


# ============================================================================
# Extension Management
# ============================================================================

@router.get("/extensions")
async def list_extensions(user=Depends(require_jwt)):
    """List all extensions."""
    extensions = load_json(EXTENSIONS_FILE)
    # Get registration status if running
    if is_running():
        output = run_asterisk_cmd("pjsip show endpoints")
        for ext in extensions:
            ext["registered"] = ext["number"] in output
    return {"extensions": extensions}


@router.post("/extension")
async def create_extension(ext: Extension, user=Depends(require_jwt)):
    """Create a new extension."""
    extensions = load_json(EXTENSIONS_FILE)

    # Check for duplicate
    for e in extensions:
        if e["number"] == ext.number:
            return {"success": False, "error": "Extension already exists"}

    ext_data = {
        "id": f"ext_{ext.number}",
        "number": ext.number,
        "name": ext.name,
        "voicemail": ext.voicemail,
        "context": ext.context,
        "created": datetime.now().isoformat(),
    }
    # Store password securely (PBKDF2-SHA256)
    if ext.password:
        pw_data = hash_password(ext.password)
        ext_data["password_hash"] = pw_data["hash"]
        ext_data["password_salt"] = pw_data["salt"]

    extensions.append(ext_data)
    save_json(EXTENSIONS_FILE, extensions)

    log.info(f"Extension {ext.number} created by {user.get('sub', 'unknown')}")
    return {"success": True, "extension": ext_data}


@router.delete("/extension/{ext_number}")
async def delete_extension(ext_number: str, user=Depends(require_jwt)):
    """Delete an extension."""
    extensions = load_json(EXTENSIONS_FILE)
    new_extensions = [e for e in extensions if e["number"] != ext_number]

    if len(new_extensions) == len(extensions):
        return {"success": False, "error": "Extension not found"}

    save_json(EXTENSIONS_FILE, new_extensions)
    log.info(f"Extension {ext_number} deleted by {user.get('sub', 'unknown')}")
    return {"success": True}


# ============================================================================
# Trunk Management
# ============================================================================

@router.get("/trunks")
async def list_trunks(user=Depends(require_jwt)):
    """List all trunks."""
    trunks = load_json(TRUNKS_FILE)
    # Get status if running
    if is_running():
        output = run_asterisk_cmd("pjsip show registrations")
        for trunk in trunks:
            trunk["status"] = "Registered" if trunk["name"] in output else "Not Registered"
    return {"trunks": trunks}


@router.post("/trunk")
async def create_trunk(trunk: Trunk, user=Depends(require_jwt)):
    """Create a new trunk."""
    trunks = load_json(TRUNKS_FILE)

    # Check for duplicate
    for t in trunks:
        if t["name"] == trunk.name:
            return {"success": False, "error": "Trunk already exists"}

    trunk_id = f"trunk_{len(trunks)+1}"
    trunk_data = {
        "id": trunk_id,
        "name": trunk.name,
        "type": trunk.type,
        "host": trunk.host,
        "username": trunk.username,
        "context": trunk.context,
        "codecs": trunk.codecs,
        "created": datetime.now().isoformat(),
    }
    # Store password securely (PBKDF2-SHA256)
    if trunk.password:
        pw_data = hash_password(trunk.password)
        trunk_data["password_hash"] = pw_data["hash"]
        trunk_data["password_salt"] = pw_data["salt"]

    trunks.append(trunk_data)
    save_json(TRUNKS_FILE, trunks)

    log.info(f"Trunk {trunk.name} created by {user.get('sub', 'unknown')}")
    return {"success": True, "trunk": trunk_data}


@router.delete("/trunk/{trunk_id}")
async def delete_trunk(trunk_id: str, user=Depends(require_jwt)):
    """Delete a trunk."""
    trunks = load_json(TRUNKS_FILE)
    new_trunks = [t for t in trunks if t["id"] != trunk_id]

    if len(new_trunks) == len(trunks):
        return {"success": False, "error": "Trunk not found"}

    save_json(TRUNKS_FILE, new_trunks)
    log.info(f"Trunk {trunk_id} deleted by {user.get('sub', 'unknown')}")
    return {"success": True}


# ============================================================================
# Route Management
# ============================================================================

@router.get("/routes/inbound")
async def list_inbound_routes(user=Depends(require_jwt)):
    """List inbound routes."""
    routes = load_json(ROUTES_FILE)
    inbound = [r for r in routes if r.get("direction") == "inbound"]
    return {"routes": inbound}


@router.get("/routes/outbound")
async def list_outbound_routes(user=Depends(require_jwt)):
    """List outbound routes."""
    routes = load_json(ROUTES_FILE)
    outbound = [r for r in routes if r.get("direction") == "outbound"]
    return {"routes": outbound}


@router.post("/route")
async def create_route(route: Route, user=Depends(require_jwt)):
    """Create a new route."""
    routes = load_json(ROUTES_FILE)

    route_id = f"route_{len(routes)+1}"
    route_data = {
        "id": route_id,
        "name": route.name,
        "direction": route.direction,
        "pattern": route.pattern,
        "trunk": route.trunk,
        "destination": route.destination,
        "priority": route.priority,
        "created": datetime.now().isoformat(),
    }

    routes.append(route_data)
    save_json(ROUTES_FILE, routes)

    log.info(f"Route {route.name} created by {user.get('sub', 'unknown')}")
    return {"success": True, "route": route_data}


@router.delete("/route/{route_id}")
async def delete_route(route_id: str, user=Depends(require_jwt)):
    """Delete a route."""
    routes = load_json(ROUTES_FILE)
    new_routes = [r for r in routes if r["id"] != route_id]

    if len(new_routes) == len(routes):
        return {"success": False, "error": "Route not found"}

    save_json(ROUTES_FILE, new_routes)
    log.info(f"Route {route_id} deleted by {user.get('sub', 'unknown')}")
    return {"success": True}


# ============================================================================
# IVR Management
# ============================================================================

@router.get("/ivr")
async def list_ivr(user=Depends(require_jwt)):
    """List IVR menus."""
    ivr_menus = load_json(IVR_FILE)
    return {"ivr": ivr_menus}


@router.post("/ivr")
async def create_ivr(ivr: IVRMenu, user=Depends(require_jwt)):
    """Create a new IVR menu."""
    ivr_menus = load_json(IVR_FILE)

    ivr_id = f"ivr_{len(ivr_menus)+1}"
    ivr_data = {
        "id": ivr_id,
        "name": ivr.name,
        "description": ivr.description,
        "announcement": ivr.announcement,
        "timeout": ivr.timeout,
        "options": ivr.options,
        "created": datetime.now().isoformat(),
    }

    ivr_menus.append(ivr_data)
    save_json(IVR_FILE, ivr_menus)

    log.info(f"IVR {ivr.name} created by {user.get('sub', 'unknown')}")
    return {"success": True, "ivr": ivr_data}


@router.delete("/ivr/{ivr_id}")
async def delete_ivr(ivr_id: str, user=Depends(require_jwt)):
    """Delete an IVR menu."""
    ivr_menus = load_json(IVR_FILE)
    new_ivr = [i for i in ivr_menus if i["id"] != ivr_id]

    if len(new_ivr) == len(ivr_menus):
        return {"success": False, "error": "IVR not found"}

    save_json(IVR_FILE, new_ivr)
    log.info(f"IVR {ivr_id} deleted by {user.get('sub', 'unknown')}")
    return {"success": True}


# ============================================================================
# Voicemail
# ============================================================================

@router.get("/voicemail")
async def list_voicemail(user=Depends(require_jwt)):
    """List voicemail boxes."""
    extensions = load_json(EXTENSIONS_FILE)
    voicemail = [e for e in extensions if e.get("voicemail")]

    # Get voicemail status if running
    if is_running():
        output = run_asterisk_cmd("voicemail show users")
        for vm in voicemail:
            vm["messages"] = 0
            for line in output.split("\n"):
                if vm["number"] in line:
                    parts = line.split()
                    for i, p in enumerate(parts):
                        if p.isdigit() and i > 0:
                            vm["messages"] = int(p)
                            break
                    break

    return {"voicemail": voicemail}


# ============================================================================
# CDR (Call Detail Records)
# ============================================================================

@router.get("/cdr")
async def get_cdr(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    user=Depends(require_jwt)
):
    """Get call detail records."""
    cdr_file = Path("/srv/voip/cdr/Master.csv")
    records = []

    if cdr_file.exists():
        try:
            import csv
            with open(cdr_file, "r") as f:
                reader = csv.DictReader(f)
                all_records = list(reader)
                # Return newest first
                all_records.reverse()
                records = all_records[offset:offset+limit]
        except Exception as e:
            log.error(f"CDR read error: {e}")

    return {"cdr": records, "total": len(records)}


# ============================================================================
# SIP Status
# ============================================================================

@router.get("/sip/peers")
async def get_sip_peers(user=Depends(require_jwt)):
    """Get SIP peer status."""
    if not is_running():
        return {"peers": [], "error": "PBX not running"}

    output = run_asterisk_cmd("pjsip show endpoints")
    peers = []

    for line in output.split("\n"):
        line = line.strip()
        if line and not line.startswith("Endpoint") and not line.startswith("="):
            parts = line.split()
            if len(parts) >= 2:
                peers.append({
                    "endpoint": parts[0],
                    "status": " ".join(parts[1:])
                })

    return {"peers": peers}


@router.get("/channels")
async def get_active_channels(user=Depends(require_jwt)):
    """Get active call channels."""
    if not is_running():
        return {"channels": [], "error": "PBX not running"}

    output = run_asterisk_cmd("core show channels")
    channels = []

    for line in output.split("\n"):
        line = line.strip()
        if "/" in line and "Channel" not in line:
            parts = line.split()
            if len(parts) >= 4:
                channels.append({
                    "channel": parts[0],
                    "state": parts[3] if len(parts) > 3 else "",
                    "duration": parts[-1] if ":" in parts[-1] else ""
                })

    return {"channels": channels}


# ============================================================================
# Container Management
# ============================================================================

@router.get("/container/status")
async def get_container_info(user=Depends(require_jwt)):
    """Get container status information."""
    return get_container_status()


@router.post("/container/install")
async def install_voip(user=Depends(require_jwt)):
    """Install FreePBX container."""
    rt = detect_runtime()
    if not rt:
        return {"success": False, "error": "No container runtime (docker/podman) found"}

    cfg = get_config()
    data_path = Path(cfg.get("data_path", "/srv/voip"))

    # Create directories
    (data_path / "data").mkdir(parents=True, exist_ok=True)
    (data_path / "logs").mkdir(parents=True, exist_ok=True)
    (data_path / "cdr").mkdir(parents=True, exist_ok=True)

    image = cfg.get("image", "tiredofit/freepbx:latest")
    log.info(f"Installing FreePBX ({image}) by {user.get('sub', 'unknown')}")

    try:
        result = subprocess.run(
            [rt, "pull", image],
            capture_output=True, text=True, timeout=600
        )
        if result.returncode != 0:
            return {"success": False, "error": result.stderr.strip(), "output": result.stdout}

        return {"success": True, "output": "Image pulled successfully"}
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Pull timeout"}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.post("/container/start")
async def start_voip(user=Depends(require_jwt)):
    """Start FreePBX container."""
    if is_running():
        return {"success": False, "error": "Already running"}

    rt = detect_runtime()
    if not rt:
        return {"success": False, "error": "No container runtime"}

    cfg = get_config()
    data_path = Path(cfg.get("data_path", "/srv/voip"))
    http_port = cfg.get("http_port", 8180)
    sip_port = cfg.get("sip_port", 5060)
    rtp_start = cfg.get("rtp_start", 10000)
    rtp_end = cfg.get("rtp_end", 20000)
    image = cfg.get("image", "tiredofit/freepbx:latest")
    tz = cfg.get("timezone", "Europe/Paris")

    # Ensure directories exist
    (data_path / "data").mkdir(parents=True, exist_ok=True)
    (data_path / "logs").mkdir(parents=True, exist_ok=True)
    (data_path / "cdr").mkdir(parents=True, exist_ok=True)

    # Build run command
    cmd = [
        rt, "run", "-d",
        "--name", CONTAINER_NAME,
        "-v", f"{data_path}/data:/data",
        "-v", f"{data_path}/logs:/var/log",
        "-v", f"{data_path}/cdr:/var/log/asterisk/cdr-csv",
        "-e", f"TZ={tz}",
        "-e", "ENABLE_FAIL2BAN=FALSE",
        "-e", "ENABLE_XMPP=FALSE",
        "-p", f"127.0.0.1:{http_port}:80",
        "-p", f"{sip_port}:5060/udp",
        "-p", f"{sip_port}:5060/tcp",
        "-p", f"5061:5061/tcp",  # SIP TLS
        "-p", f"{rtp_start}-{rtp_end}:{rtp_start}-{rtp_end}/udp",
        "--restart", "unless-stopped",
    ]

    cmd.append(image)

    log.info(f"Starting FreePBX by {user.get('sub', 'unknown')}")

    try:
        # Remove existing stopped container
        subprocess.run([rt, "rm", "-f", CONTAINER_NAME], capture_output=True, timeout=10)

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        await asyncio.sleep(5)

        if is_running():
            return {"success": True}
        else:
            return {"success": False, "error": result.stderr.strip() or "Failed to start"}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.post("/container/stop")
async def stop_voip(user=Depends(require_jwt)):
    """Stop FreePBX container."""
    rt = detect_runtime()
    if not rt:
        return {"success": False, "error": "No container runtime"}

    log.info(f"Stopping FreePBX by {user.get('sub', 'unknown')}")

    try:
        subprocess.run([rt, "stop", CONTAINER_NAME], capture_output=True, timeout=30)
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.post("/container/restart")
async def restart_voip(user=Depends(require_jwt)):
    """Restart FreePBX container."""
    await stop_voip(user)
    await asyncio.sleep(3)
    return await start_voip(user)


@router.post("/container/uninstall")
async def uninstall_voip(user=Depends(require_jwt)):
    """Uninstall FreePBX container."""
    rt = detect_runtime()
    if not rt:
        return {"success": False, "error": "No container runtime"}

    log.info(f"Uninstalling FreePBX by {user.get('sub', 'unknown')}")

    try:
        subprocess.run([rt, "stop", CONTAINER_NAME], capture_output=True, timeout=30)
        subprocess.run([rt, "rm", "-f", CONTAINER_NAME], capture_output=True, timeout=10)
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ============================================================================
# Logs
# ============================================================================

@router.get("/logs")
async def get_logs(
    lines: int = Query(50, ge=1, le=500),
    log_type: str = Query("all", pattern="^(all|asterisk|freepbx)$"),
    user=Depends(require_jwt)
):
    """Get container and Asterisk logs."""
    rt = detect_runtime()
    if not rt:
        return {"logs": "No container runtime"}

    try:
        result = subprocess.run(
            [rt, "logs", "--tail", str(lines), CONTAINER_NAME],
            capture_output=True, text=True, timeout=10
        )
        logs = result.stdout + result.stderr
        return {"logs": logs}
    except Exception:
        return {"logs": "No logs available"}


app.include_router(router)
