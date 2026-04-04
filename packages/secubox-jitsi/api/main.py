"""
SecuBox-Deb :: Jitsi Meet API
CyberMind - https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate

Jitsi Meet video conferencing with Docker-based deployment.
Provides room management, authentication, recording (Jibri), and streaming.
"""
import asyncio
import json
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

try:
    from secubox_core.auth import router as auth_router, require_jwt
    from secubox_core.logger import get_logger
except ImportError:
    def require_jwt():
        return {"sub": "admin"}
    class Logger:
        def info(self, msg): print(f"INFO: {msg}")
        def error(self, msg): print(f"ERROR: {msg}")
        def warning(self, msg): print(f"WARN: {msg}")
    def get_logger(name): return Logger()
    auth_router = None

app = FastAPI(
    title="secubox-jitsi",
    version="1.0.0",
    root_path="/api/v1/jitsi"
)
if auth_router:
    app.include_router(auth_router, prefix="/auth")

router = APIRouter()
log = get_logger("jitsi")

# ============================================================================
# Configuration
# ============================================================================

CONFIG_FILE = Path("/etc/secubox/jitsi.toml")
DATA_DIR = Path("/srv/jitsi")
RECORDINGS_DIR = DATA_DIR / "recordings"
CONTAINER_PREFIX = "secbx-jitsi"
JITSI_CONTAINERS = {
    "web": f"{CONTAINER_PREFIX}-web",
    "prosody": f"{CONTAINER_PREFIX}-prosody",
    "jicofo": f"{CONTAINER_PREFIX}-jicofo",
    "jvb": f"{CONTAINER_PREFIX}-jvb",
    "jibri": f"{CONTAINER_PREFIX}-jibri",
}

DEFAULT_CONFIG = {
    "enabled": False,
    "domain": "meet.secubox.local",
    "public_url": "https://meet.secubox.local",
    "timezone": "Europe/Paris",
    "http_port": 8443,
    "https_port": 443,
    "jvb_port": 10000,
    "auth_enabled": False,
    "auth_type": "internal",  # internal, jwt, ldap
    "jwt_secret": "",
    "jwt_app_id": "secubox",
    "ldap_url": "",
    "ldap_base": "",
    "enable_lobby": True,
    "enable_breakout_rooms": True,
    "enable_recording": False,
    "enable_streaming": False,
    "jibri_enabled": False,
    "max_participants": 100,
    "welcome_message": "Welcome to SecuBox Meeting",
    "haproxy": False,
}


# ============================================================================
# Models
# ============================================================================

class JitsiConfig(BaseModel):
    enabled: bool = False
    domain: str = "meet.secubox.local"
    public_url: str = "https://meet.secubox.local"
    timezone: str = "Europe/Paris"
    http_port: int = 8443
    https_port: int = 443
    auth_enabled: bool = False
    auth_type: str = "internal"
    jwt_secret: str = ""
    jwt_app_id: str = "secubox"
    enable_lobby: bool = True
    enable_breakout_rooms: bool = True
    enable_recording: bool = False
    max_participants: int = 100
    welcome_message: str = "Welcome to SecuBox Meeting"


class AuthConfig(BaseModel):
    auth_type: str = "internal"
    jwt_secret: Optional[str] = None
    jwt_app_id: str = "secubox"
    ldap_url: Optional[str] = None
    ldap_base: Optional[str] = None


class RoomCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=64)
    password: Optional[str] = None
    moderator_password: Optional[str] = None
    max_participants: int = Field(default=50, ge=2, le=500)


# ============================================================================
# Helpers
# ============================================================================

def get_config() -> dict:
    """Load Jitsi configuration."""
    if CONFIG_FILE.exists():
        try:
            import tomllib
            return {**DEFAULT_CONFIG, **tomllib.loads(CONFIG_FILE.read_text())}
        except Exception:
            pass
    return DEFAULT_CONFIG.copy()


def save_config(config: dict):
    """Save Jitsi configuration."""
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    lines = ["# SecuBox Jitsi Meet configuration"]
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


def detect_runtime() -> Optional[str]:
    """Detect container runtime (docker or podman)."""
    if shutil.which("podman"):
        return "podman"
    if shutil.which("docker"):
        return "docker"
    return None


def run_compose(cmd: List[str], timeout: int = 300) -> subprocess.CompletedProcess:
    """Run docker-compose command."""
    rt = detect_runtime()
    if not rt:
        raise HTTPException(500, "No container runtime found")

    compose_cmd = "docker-compose" if rt == "docker" else "podman-compose"
    compose_file = DATA_DIR / "docker-compose.yml"

    if not compose_file.exists():
        raise HTTPException(400, "Jitsi not installed")

    return subprocess.run(
        [compose_cmd, "-f", str(compose_file)] + cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=str(DATA_DIR)
    )


def get_container_status(name: str) -> dict:
    """Get specific container status."""
    rt = detect_runtime()
    if not rt:
        return {"status": "no_runtime", "uptime": ""}

    try:
        result = subprocess.run(
            [rt, "ps", "--filter", f"name={name}", "--format", "{{.Status}}"],
            capture_output=True, text=True, timeout=5
        )
        if result.stdout.strip():
            return {"status": "running", "uptime": result.stdout.strip()}

        result = subprocess.run(
            [rt, "ps", "-a", "--filter", f"name={name}", "--format", "{{.Status}}"],
            capture_output=True, text=True, timeout=5
        )
        if result.stdout.strip():
            return {"status": "stopped", "uptime": ""}

        return {"status": "not_installed", "uptime": ""}
    except Exception:
        return {"status": "error", "uptime": ""}


def is_jitsi_running() -> bool:
    """Check if main Jitsi containers are running."""
    for name in ["web", "prosody", "jicofo", "jvb"]:
        if get_container_status(JITSI_CONTAINERS[name])["status"] != "running":
            return False
    return True


def get_all_container_status() -> Dict[str, dict]:
    """Get status of all Jitsi containers."""
    return {
        name: get_container_status(container)
        for name, container in JITSI_CONTAINERS.items()
    }


def generate_compose_file(config: dict) -> str:
    """Generate docker-compose.yml for Jitsi."""
    domain = config.get("domain", "meet.secubox.local")
    public_url = config.get("public_url", f"https://{domain}")
    tz = config.get("timezone", "Europe/Paris")
    http_port = config.get("http_port", 8443)
    https_port = config.get("https_port", 443)
    jvb_port = config.get("jvb_port", 10000)
    auth_enabled = config.get("auth_enabled", False)
    auth_type = config.get("auth_type", "internal")
    jibri_enabled = config.get("jibri_enabled", False)

    auth_env = ""
    if auth_enabled:
        if auth_type == "jwt":
            auth_env = f"""
      - ENABLE_AUTH=1
      - AUTH_TYPE=jwt
      - JWT_APP_ID={config.get('jwt_app_id', 'secubox')}
      - JWT_APP_SECRET={config.get('jwt_secret', '')}
      - JWT_ACCEPTED_ISSUERS=secubox
      - JWT_ACCEPTED_AUDIENCES=secubox"""
        elif auth_type == "ldap":
            auth_env = f"""
      - ENABLE_AUTH=1
      - AUTH_TYPE=ldap
      - LDAP_URL={config.get('ldap_url', '')}
      - LDAP_BASE={config.get('ldap_base', '')}"""
        else:
            auth_env = """
      - ENABLE_AUTH=1
      - AUTH_TYPE=internal"""

    jibri_service = ""
    if jibri_enabled:
        jibri_service = f"""
  jibri:
    image: jitsi/jibri:stable
    container_name: {JITSI_CONTAINERS['jibri']}
    restart: unless-stopped
    privileged: true
    shm_size: 2gb
    volumes:
      - ./jibri:/config:Z
      - ./recordings:/recordings:Z
    environment:
      - XMPP_AUTH_DOMAIN=auth.{domain}
      - XMPP_INTERNAL_MUC_DOMAIN=internal-muc.{domain}
      - XMPP_RECORDER_DOMAIN=recorder.{domain}
      - XMPP_SERVER={JITSI_CONTAINERS['prosody']}
      - JIBRI_XMPP_USER=jibri
      - JIBRI_RECORDER_USER=recorder
      - JIBRI_RECORDING_DIR=/recordings
      - TZ={tz}
    depends_on:
      - prosody"""

    return f"""# SecuBox Jitsi Meet Docker Compose
# Auto-generated - do not edit manually

version: '3.8'

services:
  web:
    image: jitsi/web:stable
    container_name: {JITSI_CONTAINERS['web']}
    restart: unless-stopped
    ports:
      - "127.0.0.1:{http_port}:80"
      - "127.0.0.1:{https_port}:443"
    volumes:
      - ./web:/config:Z
      - ./web/crontabs:/var/spool/cron/crontabs:Z
      - ./transcripts:/usr/share/jitsi-meet/transcripts:Z
    environment:
      - ENABLE_COLIBRI_WEBSOCKET=1
      - ENABLE_FLOC=0
      - ENABLE_LETSENCRYPT=0
      - ENABLE_XMPP_WEBSOCKET=1
      - DISABLE_HTTPS=0
      - PUBLIC_URL={public_url}
      - TZ={tz}{auth_env}
    depends_on:
      - prosody
    networks:
      - jitsi-net

  prosody:
    image: jitsi/prosody:stable
    container_name: {JITSI_CONTAINERS['prosody']}
    restart: unless-stopped
    expose:
      - '5222'
      - '5347'
      - '5280'
    volumes:
      - ./prosody/config:/config:Z
      - ./prosody/prosody-plugins-custom:/prosody-plugins-custom:Z
    environment:
      - XMPP_DOMAIN={domain}
      - XMPP_AUTH_DOMAIN=auth.{domain}
      - XMPP_MUC_DOMAIN=muc.{domain}
      - XMPP_INTERNAL_MUC_DOMAIN=internal-muc.{domain}
      - XMPP_GUEST_DOMAIN=guest.{domain}
      - XMPP_RECORDER_DOMAIN=recorder.{domain}
      - XMPP_CROSS_DOMAIN=true
      - TZ={tz}
      - JICOFO_AUTH_USER=focus
      - JVB_AUTH_USER=jvb
      - JIBRI_XMPP_USER=jibri
      - JIBRI_RECORDER_USER=recorder{auth_env}
    networks:
      - jitsi-net

  jicofo:
    image: jitsi/jicofo:stable
    container_name: {JITSI_CONTAINERS['jicofo']}
    restart: unless-stopped
    volumes:
      - ./jicofo:/config:Z
    environment:
      - XMPP_DOMAIN={domain}
      - XMPP_AUTH_DOMAIN=auth.{domain}
      - XMPP_INTERNAL_MUC_DOMAIN=internal-muc.{domain}
      - XMPP_MUC_DOMAIN=muc.{domain}
      - XMPP_SERVER={JITSI_CONTAINERS['prosody']}
      - JICOFO_AUTH_USER=focus
      - TZ={tz}
      - ENABLE_AUTO_OWNER=true
      - ENABLE_CODEC_VP8=true
      - ENABLE_CODEC_VP9=true
      - ENABLE_CODEC_H264=true
    depends_on:
      - prosody
    networks:
      - jitsi-net

  jvb:
    image: jitsi/jvb:stable
    container_name: {JITSI_CONTAINERS['jvb']}
    restart: unless-stopped
    ports:
      - "{jvb_port}:{jvb_port}/udp"
    volumes:
      - ./jvb:/config:Z
    environment:
      - XMPP_AUTH_DOMAIN=auth.{domain}
      - XMPP_INTERNAL_MUC_DOMAIN=internal-muc.{domain}
      - XMPP_SERVER={JITSI_CONTAINERS['prosody']}
      - JVB_AUTH_USER=jvb
      - JVB_PORT={jvb_port}
      - JVB_STUN_SERVERS=meet-jit-si-turnrelay.jitsi.net:443
      - TZ={tz}
    depends_on:
      - prosody
    networks:
      - jitsi-net
{jibri_service}
networks:
  jitsi-net:
    driver: bridge
"""


def get_jvb_stats() -> dict:
    """Get JVB (Jitsi Videobridge) statistics via colibri."""
    rt = detect_runtime()
    if not rt:
        return {}

    try:
        result = subprocess.run(
            [rt, "exec", JITSI_CONTAINERS["jvb"], "curl", "-s", "http://localhost:8080/colibri/stats"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            return json.loads(result.stdout)
    except Exception:
        pass
    return {}


# ============================================================================
# Public Endpoints
# ============================================================================

@router.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "ok", "module": "jitsi"}


@router.get("/status")
async def status(user=Depends(require_jwt)):
    """Get Jitsi Meet comprehensive status."""
    cfg = get_config()
    rt = detect_runtime()
    containers = get_all_container_status()
    running = is_jitsi_running()

    # Get JVB stats
    jvb_stats = get_jvb_stats() if running else {}

    # Disk usage
    disk_usage = ""
    if DATA_DIR.exists():
        try:
            result = subprocess.run(
                ["du", "-sh", str(DATA_DIR)],
                capture_output=True, text=True, timeout=10
            )
            disk_usage = result.stdout.split()[0] if result.stdout else ""
        except Exception:
            pass

    # Count recordings
    recording_count = 0
    if RECORDINGS_DIR.exists():
        recording_count = len(list(RECORDINGS_DIR.glob("*.mp4")))

    return {
        "enabled": cfg.get("enabled", False),
        "domain": cfg.get("domain", "meet.secubox.local"),
        "public_url": cfg.get("public_url", "https://meet.secubox.local"),
        "http_port": cfg.get("http_port", 8443),
        "https_port": cfg.get("https_port", 443),
        "jvb_port": cfg.get("jvb_port", 10000),
        "docker_available": rt is not None,
        "runtime": rt or "none",
        "running": running,
        "containers": containers,
        "auth_enabled": cfg.get("auth_enabled", False),
        "auth_type": cfg.get("auth_type", "internal"),
        "jibri_enabled": cfg.get("jibri_enabled", False),
        "active_conferences": jvb_stats.get("conferences", 0),
        "active_participants": jvb_stats.get("participants", 0),
        "largest_conference": jvb_stats.get("largest_conference", 0),
        "total_conferences_created": jvb_stats.get("total_conferences_created", 0),
        "disk_usage": disk_usage,
        "recording_count": recording_count,
    }


# ============================================================================
# Configuration
# ============================================================================

@router.get("/config")
async def get_jitsi_config(user=Depends(require_jwt)):
    """Get Jitsi configuration."""
    cfg = get_config()
    # Remove sensitive fields
    safe_cfg = {k: v for k, v in cfg.items() if k not in ["jwt_secret"]}
    if cfg.get("jwt_secret"):
        safe_cfg["jwt_secret"] = "***configured***"
    return safe_cfg


@router.post("/config")
async def set_jitsi_config(config: JitsiConfig, user=Depends(require_jwt)):
    """Update Jitsi configuration."""
    cfg = get_config()
    cfg.update(config.dict(exclude_unset=True))
    save_config(cfg)
    log.info(f"Config updated by {user.get('sub', 'unknown')}")
    return {"success": True, "message": "Configuration saved. Restart to apply."}


# ============================================================================
# Room Management
# ============================================================================

@router.get("/rooms")
async def list_rooms(user=Depends(require_jwt)):
    """List active rooms/conferences."""
    if not is_jitsi_running():
        return {"rooms": [], "error": "Jitsi not running"}

    stats = get_jvb_stats()
    return {
        "total_active": stats.get("conferences", 0),
        "total_participants": stats.get("participants", 0),
        "largest_conference": stats.get("largest_conference", 0),
        # Note: Jitsi doesn't expose individual room names via colibri stats
        # Room details require SRTP internal API access
    }


@router.get("/room/{name}")
async def get_room(name: str, user=Depends(require_jwt)):
    """Get room details."""
    if not is_jitsi_running():
        raise HTTPException(400, "Jitsi not running")

    cfg = get_config()
    domain = cfg.get("domain", "meet.secubox.local")

    return {
        "name": name,
        "url": f"https://{domain}/{name}",
        "status": "Room status not available via API",
        "message": "Join the room to see participants"
    }


@router.post("/room/{name}/close")
async def close_room(name: str, user=Depends(require_jwt)):
    """Request to close a room (requires Prosody mod)."""
    if not is_jitsi_running():
        raise HTTPException(400, "Jitsi not running")

    # This requires custom Prosody module for room control
    log.warning(f"Room close requested for {name} by {user.get('sub', 'unknown')}")
    return {
        "success": False,
        "message": "Room close requires Prosody admin module. Rooms auto-close when empty."
    }


# ============================================================================
# Statistics
# ============================================================================

@router.get("/stats")
async def get_stats(user=Depends(require_jwt)):
    """Get detailed JVB statistics."""
    if not is_jitsi_running():
        raise HTTPException(400, "Jitsi not running")

    stats = get_jvb_stats()
    if not stats:
        return {"error": "Stats not available"}

    return {
        "conferences": stats.get("conferences", 0),
        "participants": stats.get("participants", 0),
        "largest_conference": stats.get("largest_conference", 0),
        "total_conferences_created": stats.get("total_conferences_created", 0),
        "total_participants": stats.get("total_participants", 0),
        "version": stats.get("version"),
        "stress_level": stats.get("stress_level"),
        "packet_rate_download": stats.get("packet_rate_download", 0),
        "packet_rate_upload": stats.get("packet_rate_upload", 0),
        "bit_rate_download": stats.get("bit_rate_download", 0),
        "bit_rate_upload": stats.get("bit_rate_upload", 0),
        "loss_rate_download": stats.get("loss_rate_download", 0),
        "loss_rate_upload": stats.get("loss_rate_upload", 0),
    }


# ============================================================================
# Recording Management
# ============================================================================

@router.get("/recordings")
async def list_recordings(user=Depends(require_jwt)):
    """List available recordings."""
    if not RECORDINGS_DIR.exists():
        return {"recordings": []}

    recordings = []
    for f in RECORDINGS_DIR.glob("*.mp4"):
        stat = f.stat()
        recordings.append({
            "id": f.stem,
            "filename": f.name,
            "size": stat.st_size,
            "size_human": f"{stat.st_size / 1024 / 1024:.1f} MB",
            "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
            "path": str(f),
        })

    recordings.sort(key=lambda x: x["created"], reverse=True)
    return {"recordings": recordings}


@router.delete("/recording/{recording_id}")
async def delete_recording(recording_id: str, user=Depends(require_jwt)):
    """Delete a recording."""
    recording_path = RECORDINGS_DIR / f"{recording_id}.mp4"

    if not recording_path.exists():
        raise HTTPException(404, "Recording not found")

    try:
        recording_path.unlink()
        log.info(f"Recording {recording_id} deleted by {user.get('sub', 'unknown')}")
        return {"success": True}
    except Exception as e:
        raise HTTPException(500, f"Failed to delete: {e}")


# ============================================================================
# Authentication
# ============================================================================

@router.get("/auth/config")
async def get_auth_config(user=Depends(require_jwt)):
    """Get authentication configuration."""
    cfg = get_config()
    return {
        "auth_enabled": cfg.get("auth_enabled", False),
        "auth_type": cfg.get("auth_type", "internal"),
        "jwt_app_id": cfg.get("jwt_app_id", "secubox"),
        "jwt_configured": bool(cfg.get("jwt_secret")),
        "ldap_url": cfg.get("ldap_url", ""),
        "ldap_base": cfg.get("ldap_base", ""),
    }


@router.post("/auth/config")
async def set_auth_config(auth: AuthConfig, user=Depends(require_jwt)):
    """Update authentication configuration."""
    cfg = get_config()

    cfg["auth_type"] = auth.auth_type
    if auth.jwt_secret:
        cfg["jwt_secret"] = auth.jwt_secret
    cfg["jwt_app_id"] = auth.jwt_app_id
    if auth.ldap_url:
        cfg["ldap_url"] = auth.ldap_url
    if auth.ldap_base:
        cfg["ldap_base"] = auth.ldap_base

    cfg["auth_enabled"] = True
    save_config(cfg)

    log.info(f"Auth config updated by {user.get('sub', 'unknown')}")
    return {"success": True, "message": "Auth config saved. Restart to apply."}


# ============================================================================
# Prosody Status
# ============================================================================

@router.get("/prosody/status")
async def prosody_status(user=Depends(require_jwt)):
    """Get Prosody XMPP server status."""
    container = get_container_status(JITSI_CONTAINERS["prosody"])

    if container["status"] != "running":
        return {"running": False, "status": container["status"]}

    rt = detect_runtime()
    users = []

    try:
        # Get registered users
        result = subprocess.run(
            [rt, "exec", JITSI_CONTAINERS["prosody"], "prosodyctl", "mod_listusers"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0 and result.stdout.strip():
            users = result.stdout.strip().split("\n")
    except Exception:
        pass

    return {
        "running": True,
        "uptime": container["uptime"],
        "registered_users": len(users),
        "users": users[:20],  # Limit to first 20
    }


# ============================================================================
# Jibri (Recording Service)
# ============================================================================

@router.get("/jibri/status")
async def jibri_status(user=Depends(require_jwt)):
    """Get Jibri recording service status."""
    cfg = get_config()
    container = get_container_status(JITSI_CONTAINERS["jibri"])

    return {
        "enabled": cfg.get("jibri_enabled", False),
        "running": container["status"] == "running",
        "status": container["status"],
        "uptime": container["uptime"],
    }


@router.post("/jibri/enable")
async def enable_jibri(user=Depends(require_jwt)):
    """Enable Jibri recording service."""
    cfg = get_config()
    cfg["jibri_enabled"] = True
    cfg["enable_recording"] = True
    save_config(cfg)

    # Regenerate docker-compose
    compose_content = generate_compose_file(cfg)
    compose_file = DATA_DIR / "docker-compose.yml"
    compose_file.write_text(compose_content)

    log.info(f"Jibri enabled by {user.get('sub', 'unknown')}")
    return {"success": True, "message": "Jibri enabled. Restart Jitsi to apply."}


@router.post("/jibri/disable")
async def disable_jibri(user=Depends(require_jwt)):
    """Disable Jibri recording service."""
    cfg = get_config()
    cfg["jibri_enabled"] = False
    save_config(cfg)

    # Stop Jibri container
    rt = detect_runtime()
    if rt:
        subprocess.run([rt, "stop", JITSI_CONTAINERS["jibri"]], capture_output=True, timeout=30)
        subprocess.run([rt, "rm", "-f", JITSI_CONTAINERS["jibri"]], capture_output=True, timeout=10)

    # Regenerate docker-compose without Jibri
    compose_content = generate_compose_file(cfg)
    compose_file = DATA_DIR / "docker-compose.yml"
    compose_file.write_text(compose_content)

    log.info(f"Jibri disabled by {user.get('sub', 'unknown')}")
    return {"success": True, "message": "Jibri disabled"}


# ============================================================================
# Container Management
# ============================================================================

@router.get("/container/status")
async def container_status(user=Depends(require_jwt)):
    """Get detailed container status."""
    rt = detect_runtime()
    containers = get_all_container_status()

    return {
        "runtime": rt or "none",
        "containers": containers,
        "all_running": is_jitsi_running(),
    }


@router.post("/container/install")
async def install_jitsi(user=Depends(require_jwt)):
    """Install Jitsi Meet Docker stack."""
    rt = detect_runtime()
    if not rt:
        raise HTTPException(500, "No container runtime (docker/podman) found")

    cfg = get_config()

    # Create directories
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    RECORDINGS_DIR.mkdir(parents=True, exist_ok=True)
    for subdir in ["web", "prosody/config", "prosody/prosody-plugins-custom", "jicofo", "jvb", "jibri", "transcripts"]:
        (DATA_DIR / subdir).mkdir(parents=True, exist_ok=True)

    # Generate docker-compose
    compose_content = generate_compose_file(cfg)
    compose_file = DATA_DIR / "docker-compose.yml"
    compose_file.write_text(compose_content)

    # Generate .env file
    env_content = f"""# Jitsi Meet environment
TZ={cfg.get('timezone', 'Europe/Paris')}
PUBLIC_URL={cfg.get('public_url', 'https://meet.secubox.local')}
"""
    (DATA_DIR / ".env").write_text(env_content)

    log.info(f"Installing Jitsi by {user.get('sub', 'unknown')}")

    # Pull images
    try:
        result = run_compose(["pull"], timeout=600)
        if result.returncode != 0:
            return {"success": False, "error": result.stderr, "output": result.stdout}

        return {"success": True, "message": "Jitsi installed. Use Start to launch."}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.post("/container/start")
async def start_jitsi(user=Depends(require_jwt)):
    """Start Jitsi containers."""
    if is_jitsi_running():
        return {"success": False, "error": "Already running"}

    log.info(f"Starting Jitsi by {user.get('sub', 'unknown')}")

    try:
        result = run_compose(["up", "-d"], timeout=120)
        await asyncio.sleep(5)

        if is_jitsi_running():
            return {"success": True}
        else:
            return {"success": False, "error": result.stderr or "Failed to start"}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.post("/container/stop")
async def stop_jitsi(user=Depends(require_jwt)):
    """Stop Jitsi containers."""
    log.info(f"Stopping Jitsi by {user.get('sub', 'unknown')}")

    try:
        result = run_compose(["down"], timeout=60)
        return {"success": result.returncode == 0, "output": result.stdout}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.post("/container/restart")
async def restart_jitsi(user=Depends(require_jwt)):
    """Restart Jitsi containers."""
    log.info(f"Restarting Jitsi by {user.get('sub', 'unknown')}")

    try:
        result = run_compose(["restart"], timeout=120)
        await asyncio.sleep(5)
        return {"success": result.returncode == 0}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.post("/container/uninstall")
async def uninstall_jitsi(user=Depends(require_jwt)):
    """Uninstall Jitsi (keeps data)."""
    log.info(f"Uninstalling Jitsi by {user.get('sub', 'unknown')}")

    try:
        run_compose(["down", "-v"], timeout=60)

        rt = detect_runtime()
        if rt:
            for name in JITSI_CONTAINERS.values():
                subprocess.run([rt, "rm", "-f", name], capture_output=True, timeout=10)

        return {"success": True, "message": "Containers removed, data preserved in /srv/jitsi"}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ============================================================================
# Logs
# ============================================================================

@router.get("/logs")
async def get_logs(
    service: str = Query("web", enum=["web", "prosody", "jicofo", "jvb", "jibri"]),
    lines: int = Query(100, ge=10, le=1000),
    user=Depends(require_jwt)
):
    """Get container logs."""
    rt = detect_runtime()
    if not rt:
        return {"logs": "No container runtime"}

    container = JITSI_CONTAINERS.get(service)
    if not container:
        return {"logs": "Unknown service"}

    try:
        result = subprocess.run(
            [rt, "logs", "--tail", str(lines), container],
            capture_output=True, text=True, timeout=10
        )
        logs = result.stdout + result.stderr
        return {"logs": logs, "service": service}
    except Exception:
        return {"logs": "Failed to get logs"}


app.include_router(router)
