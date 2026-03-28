"""secubox-jellyfin — FastAPI application for media server management.

Ported from OpenWRT luci-app-jellyfin RPCD backend.
Provides Jellyfin Docker container management.
"""
import asyncio
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any

from fastapi import FastAPI, APIRouter, Depends, HTTPException
from pydantic import BaseModel

from secubox_core.auth import router as auth_router, require_jwt
from secubox_core.logger import get_logger

app = FastAPI(title="secubox-jellyfin", version="1.0.0", root_path="/api/v1/jellyfin")
app.include_router(auth_router, prefix="/auth")
router = APIRouter()
log = get_logger("jellyfin")

# Configuration
CONFIG_FILE = Path("/etc/secubox/jellyfin.toml")
CONTAINER_NAME = "secbx-jellyfin"
DEFAULT_CONFIG = {
    "enabled": False,
    "image": "jellyfin/jellyfin:latest",
    "port": 8096,
    "data_path": "/srv/jellyfin",
    "timezone": "Europe/Paris",
    "hw_accel": False,
    "domain": "jellyfin.secubox.local",
    "haproxy": False,
    "wizard_complete": False,
}


# ============================================================================
# Models
# ============================================================================

class JellyfinConfig(BaseModel):
    enabled: bool = False
    image: str = "jellyfin/jellyfin:latest"
    port: int = 8096
    data_path: str = "/srv/jellyfin"
    timezone: str = "Europe/Paris"
    hw_accel: bool = False
    domain: str = "jellyfin.secubox.local"
    haproxy: bool = False


class MediaPath(BaseModel):
    name: str
    path: str
    type: str = "movies"  # movies, tvshows, music, photos


class RestoreRequest(BaseModel):
    path: str


# ============================================================================
# Helpers
# ============================================================================

def get_config() -> dict:
    """Load jellyfin configuration."""
    if CONFIG_FILE.exists():
        try:
            import tomllib
            return tomllib.loads(CONFIG_FILE.read_text())
        except Exception:
            pass
    return DEFAULT_CONFIG.copy()


def save_config(config: dict):
    """Save jellyfin configuration."""
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    lines = ["# Jellyfin configuration"]
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
    """Detect container runtime."""
    if shutil.which("podman"):
        return "podman"
    if shutil.which("docker"):
        return "docker"
    return None


def get_container_status() -> dict:
    """Get Jellyfin container status."""
    rt = detect_runtime()
    if not rt:
        return {"status": "no_runtime", "uptime": ""}

    try:
        # Check if running
        result = subprocess.run(
            [rt, "ps", "--filter", f"name={CONTAINER_NAME}", "--format", "{{.Status}}"],
            capture_output=True, text=True, timeout=5
        )
        if result.stdout.strip():
            return {"status": "running", "uptime": result.stdout.strip()}

        # Check if exists but stopped
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
    """Check if Jellyfin container is running."""
    return get_container_status()["status"] == "running"


def get_media_paths() -> List[dict]:
    """Get configured media paths."""
    media_file = Path("/etc/secubox/jellyfin-media.json")
    if media_file.exists():
        try:
            import json
            return json.loads(media_file.read_text())
        except Exception:
            pass
    return []


def save_media_paths(paths: List[dict]):
    """Save media paths configuration."""
    media_file = Path("/etc/secubox/jellyfin-media.json")
    media_file.parent.mkdir(parents=True, exist_ok=True)
    import json
    media_file.write_text(json.dumps(paths, indent=2))


# ============================================================================
# Public Endpoints
# ============================================================================

@router.get("/health")
async def health():
    """Health check."""
    return {"status": "ok", "module": "jellyfin"}


@router.get("/status")
async def status():
    """Get Jellyfin service status."""
    cfg = get_config()
    rt = detect_runtime()
    container = get_container_status()
    media_paths = get_media_paths()

    # Disk usage
    disk_usage = ""
    data_path = Path(cfg.get("data_path", "/srv/jellyfin"))
    if data_path.exists():
        try:
            result = subprocess.run(
                ["du", "-sh", str(data_path)],
                capture_output=True, text=True, timeout=10
            )
            disk_usage = result.stdout.split()[0] if result.stdout else ""
        except Exception:
            pass

    return {
        "enabled": cfg.get("enabled", False),
        "image": cfg.get("image", "jellyfin/jellyfin:latest"),
        "port": cfg.get("port", 8096),
        "data_path": cfg.get("data_path", "/srv/jellyfin"),
        "timezone": cfg.get("timezone", "Europe/Paris"),
        "hw_accel": cfg.get("hw_accel", False),
        "domain": cfg.get("domain", "jellyfin.secubox.local"),
        "haproxy": cfg.get("haproxy", False),
        "docker_available": rt is not None,
        "runtime": rt or "none",
        "container_status": container["status"],
        "container_uptime": container["uptime"],
        "disk_usage": disk_usage,
        "media_paths": media_paths,
        "wizard_complete": cfg.get("wizard_complete", False),
    }


# ============================================================================
# Protected Endpoints
# ============================================================================

@router.get("/config")
async def get_jellyfin_config(user=Depends(require_jwt)):
    """Get Jellyfin configuration."""
    return get_config()


@router.post("/config")
async def set_jellyfin_config(config: JellyfinConfig, user=Depends(require_jwt)):
    """Update Jellyfin configuration."""
    cfg = get_config()
    cfg.update(config.dict())
    save_config(cfg)
    log.info(f"Config updated by {user.get('sub', 'unknown')}")
    return {"success": True}


@router.get("/wizard")
async def get_wizard_status(user=Depends(require_jwt)):
    """Get setup wizard status."""
    cfg = get_config()
    container = get_container_status()
    media_paths = get_media_paths()

    installed = container["status"] != "not_installed"
    running = container["status"] == "running"
    wizard_complete = cfg.get("wizard_complete", False)

    return {
        "installed": installed,
        "running": running,
        "media_count": len(media_paths),
        "wizard_complete": wizard_complete,
        "show_wizard": installed and not wizard_complete,
    }


@router.post("/wizard/complete")
async def set_wizard_complete(user=Depends(require_jwt)):
    """Mark setup wizard as complete."""
    cfg = get_config()
    cfg["wizard_complete"] = True
    save_config(cfg)
    return {"success": True}


# ============================================================================
# Media Path Management
# ============================================================================

@router.get("/media")
async def list_media_paths(user=Depends(require_jwt)):
    """List configured media paths."""
    return {"paths": get_media_paths()}


@router.post("/media")
async def add_media_path(media: MediaPath, user=Depends(require_jwt)):
    """Add a media path."""
    paths = get_media_paths()

    # Check for duplicate
    for p in paths:
        if p["path"] == media.path:
            return {"success": False, "error": "Path already exists"}

    paths.append({
        "id": f"media_{len(paths)+1}",
        "name": media.name,
        "path": media.path,
        "type": media.type,
    })
    save_media_paths(paths)

    log.info(f"Media path added: {media.path} by {user.get('sub', 'unknown')}")
    return {"success": True}


@router.delete("/media/{media_id}")
async def remove_media_path(media_id: str, user=Depends(require_jwt)):
    """Remove a media path."""
    paths = get_media_paths()
    new_paths = [p for p in paths if p.get("id") != media_id]

    if len(new_paths) == len(paths):
        return {"success": False, "error": "Path not found"}

    save_media_paths(new_paths)
    log.info(f"Media path removed: {media_id} by {user.get('sub', 'unknown')}")
    return {"success": True}


# ============================================================================
# Service Control
# ============================================================================

@router.post("/install")
async def install_jellyfin(user=Depends(require_jwt)):
    """Install Jellyfin container."""
    rt = detect_runtime()
    if not rt:
        return {"success": False, "error": "No container runtime (docker/podman) found"}

    cfg = get_config()
    data_path = Path(cfg.get("data_path", "/srv/jellyfin"))

    # Create directories
    (data_path / "config").mkdir(parents=True, exist_ok=True)
    (data_path / "cache").mkdir(parents=True, exist_ok=True)

    # Pull image
    image = cfg.get("image", "jellyfin/jellyfin:latest")
    log.info(f"Installing Jellyfin ({image}) by {user.get('sub', 'unknown')}")

    try:
        result = subprocess.run(
            [rt, "pull", image],
            capture_output=True, text=True, timeout=300
        )
        if result.returncode != 0:
            return {"success": False, "error": result.stderr.strip(), "output": result.stdout}

        return {"success": True, "output": "Image pulled successfully"}
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Pull timeout"}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.post("/start")
async def start_jellyfin(user=Depends(require_jwt)):
    """Start Jellyfin container."""
    if is_running():
        return {"success": False, "error": "Already running"}

    rt = detect_runtime()
    if not rt:
        return {"success": False, "error": "No container runtime"}

    cfg = get_config()
    data_path = Path(cfg.get("data_path", "/srv/jellyfin"))
    port = cfg.get("port", 8096)
    image = cfg.get("image", "jellyfin/jellyfin:latest")
    tz = cfg.get("timezone", "Europe/Paris")

    # Ensure directories exist
    (data_path / "config").mkdir(parents=True, exist_ok=True)
    (data_path / "cache").mkdir(parents=True, exist_ok=True)

    # Build run command
    cmd = [
        rt, "run", "-d",
        "--name", CONTAINER_NAME,
        "-v", f"{data_path}/config:/config",
        "-v", f"{data_path}/cache:/cache",
        "-e", f"TZ={tz}",
        "-p", f"127.0.0.1:{port}:8096",
        "--restart", "unless-stopped",
    ]

    # Add media paths
    for mp in get_media_paths():
        path = mp.get("path")
        name = mp.get("name", "media").replace(" ", "_").lower()
        if path and Path(path).exists():
            cmd.extend(["-v", f"{path}:/media/{name}:ro"])

    # Hardware acceleration
    if cfg.get("hw_accel"):
        # VAAPI for Intel/AMD
        if Path("/dev/dri").exists():
            cmd.extend(["--device", "/dev/dri:/dev/dri"])

    cmd.append(image)

    log.info(f"Starting Jellyfin by {user.get('sub', 'unknown')}")

    try:
        # Remove existing stopped container
        subprocess.run([rt, "rm", "-f", CONTAINER_NAME], capture_output=True, timeout=10)

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        await asyncio.sleep(3)

        if is_running():
            return {"success": True}
        else:
            return {"success": False, "error": result.stderr.strip() or "Failed to start"}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.post("/stop")
async def stop_jellyfin(user=Depends(require_jwt)):
    """Stop Jellyfin container."""
    rt = detect_runtime()
    if not rt:
        return {"success": False, "error": "No container runtime"}

    log.info(f"Stopping Jellyfin by {user.get('sub', 'unknown')}")

    try:
        subprocess.run([rt, "stop", CONTAINER_NAME], capture_output=True, timeout=30)
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.post("/restart")
async def restart_jellyfin(user=Depends(require_jwt)):
    """Restart Jellyfin container."""
    await stop_jellyfin(user)
    await asyncio.sleep(2)
    return await start_jellyfin(user)


@router.post("/uninstall")
async def uninstall_jellyfin(user=Depends(require_jwt)):
    """Uninstall Jellyfin container."""
    rt = detect_runtime()
    if not rt:
        return {"success": False, "error": "No container runtime"}

    log.info(f"Uninstalling Jellyfin by {user.get('sub', 'unknown')}")

    try:
        subprocess.run([rt, "stop", CONTAINER_NAME], capture_output=True, timeout=30)
        subprocess.run([rt, "rm", "-f", CONTAINER_NAME], capture_output=True, timeout=10)
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.post("/update")
async def update_jellyfin(user=Depends(require_jwt)):
    """Update Jellyfin to latest image."""
    cfg = get_config()
    rt = detect_runtime()
    if not rt:
        return {"success": False, "error": "No container runtime"}

    image = cfg.get("image", "jellyfin/jellyfin:latest")
    log.info(f"Updating Jellyfin ({image}) by {user.get('sub', 'unknown')}")

    try:
        # Pull new image
        result = subprocess.run(
            [rt, "pull", image],
            capture_output=True, text=True, timeout=300
        )
        if result.returncode != 0:
            return {"success": False, "error": result.stderr.strip()}

        # Restart if running
        if is_running():
            await restart_jellyfin(user)

        return {"success": True, "output": "Update complete"}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ============================================================================
# Backup/Restore
# ============================================================================

@router.post("/backup")
async def backup_jellyfin(user=Depends(require_jwt)):
    """Backup Jellyfin configuration."""
    cfg = get_config()
    data_path = Path(cfg.get("data_path", "/srv/jellyfin"))
    config_path = data_path / "config"

    if not config_path.exists():
        return {"success": False, "error": "No config to backup"}

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup_file = f"/tmp/jellyfin-backup-{timestamp}.tar.gz"

    log.info(f"Creating backup by {user.get('sub', 'unknown')}")

    try:
        result = subprocess.run(
            ["tar", "-czf", backup_file, "-C", str(data_path), "config"],
            capture_output=True, text=True, timeout=300
        )
        if result.returncode == 0:
            return {"success": True, "path": backup_file}
        else:
            return {"success": False, "error": result.stderr.strip()}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.post("/restore")
async def restore_jellyfin(req: RestoreRequest, user=Depends(require_jwt)):
    """Restore Jellyfin configuration from backup."""
    if not Path(req.path).exists():
        return {"success": False, "error": "Backup file not found"}

    cfg = get_config()
    data_path = Path(cfg.get("data_path", "/srv/jellyfin"))

    log.info(f"Restoring backup {req.path} by {user.get('sub', 'unknown')}")

    # Stop container first
    if is_running():
        await stop_jellyfin(user)
        await asyncio.sleep(2)

    try:
        result = subprocess.run(
            ["tar", "-xzf", req.path, "-C", str(data_path)],
            capture_output=True, text=True, timeout=300
        )
        if result.returncode == 0:
            return {"success": True}
        else:
            return {"success": False, "error": result.stderr.strip()}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.get("/logs")
async def get_logs(lines: int = 50, user=Depends(require_jwt)):
    """Get container logs."""
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
