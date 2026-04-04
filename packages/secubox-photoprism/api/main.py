"""secubox-photoprism — FastAPI application for PhotoPrism photo management.

Provides PhotoPrism Docker container management with library indexing,
face recognition, album management, and storage configuration.
"""
import asyncio
import shutil
import subprocess
import json
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any

from fastapi import FastAPI, APIRouter, Depends, HTTPException
from pydantic import BaseModel

from secubox_core.auth import router as auth_router, require_jwt
from secubox_core.logger import get_logger

app = FastAPI(title="secubox-photoprism", version="1.0.0", root_path="/api/v1/photoprism")
app.include_router(auth_router, prefix="/auth")
router = APIRouter()
log = get_logger("photoprism")

# Configuration
CONFIG_FILE = Path("/etc/secubox/photoprism.toml")
CONTAINER_NAME = "secbx-photoprism"
DEFAULT_CONFIG = {
    "enabled": False,
    "image": "photoprism/photoprism:latest",
    "port": 2342,
    "data_path": "/srv/photoprism",
    "originals_path": "/srv/photoprism/originals",
    "import_path": "/srv/photoprism/import",
    "timezone": "Europe/Paris",
    "domain": "photos.secubox.local",
    "haproxy": False,
    "face_recognition": True,
    "experimental": False,
    "readonly": False,
    "public": False,
    "admin_password": "",
}


# ============================================================================
# Models
# ============================================================================

class PhotoprismConfig(BaseModel):
    enabled: bool = False
    image: str = "photoprism/photoprism:latest"
    port: int = 2342
    data_path: str = "/srv/photoprism"
    originals_path: str = "/srv/photoprism/originals"
    import_path: str = "/srv/photoprism/import"
    timezone: str = "Europe/Paris"
    domain: str = "photos.secubox.local"
    haproxy: bool = False
    face_recognition: bool = True
    experimental: bool = False
    readonly: bool = False
    public: bool = False


class AlbumCreate(BaseModel):
    title: str
    description: str = ""


class UserCreate(BaseModel):
    username: str
    password: str
    role: str = "viewer"  # admin, viewer


class RestoreRequest(BaseModel):
    path: str


# ============================================================================
# Helpers
# ============================================================================

def get_config() -> dict:
    """Load photoprism configuration."""
    if CONFIG_FILE.exists():
        try:
            import tomllib
            return tomllib.loads(CONFIG_FILE.read_text())
        except Exception:
            pass
    return DEFAULT_CONFIG.copy()


def save_config(config: dict):
    """Save photoprism configuration."""
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    lines = ["# PhotoPrism configuration"]
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
    """Get PhotoPrism container status."""
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
    """Check if PhotoPrism container is running."""
    return get_container_status()["status"] == "running"


def get_library_stats() -> dict:
    """Get library statistics from PhotoPrism."""
    cfg = get_config()
    originals_path = Path(cfg.get("originals_path", "/srv/photoprism/originals"))
    import_path = Path(cfg.get("import_path", "/srv/photoprism/import"))

    stats = {
        "total_photos": 0,
        "total_videos": 0,
        "total_albums": 0,
        "storage_used": "0",
        "import_pending": 0,
    }

    # Count files in originals
    if originals_path.exists():
        try:
            photo_exts = {'.jpg', '.jpeg', '.png', '.gif', '.webp', '.heic', '.heif', '.raw', '.cr2', '.nef', '.arw'}
            video_exts = {'.mp4', '.mov', '.avi', '.mkv', '.webm', '.m4v'}

            for f in originals_path.rglob('*'):
                if f.is_file():
                    ext = f.suffix.lower()
                    if ext in photo_exts:
                        stats["total_photos"] += 1
                    elif ext in video_exts:
                        stats["total_videos"] += 1

            # Get storage size
            result = subprocess.run(
                ["du", "-sh", str(originals_path)],
                capture_output=True, text=True, timeout=30
            )
            if result.stdout:
                stats["storage_used"] = result.stdout.split()[0]
        except Exception:
            pass

    # Count pending imports
    if import_path.exists():
        try:
            stats["import_pending"] = sum(1 for f in import_path.rglob('*') if f.is_file())
        except Exception:
            pass

    # Count albums from sidecar files (simplified)
    albums_file = Path(cfg.get("data_path", "/srv/photoprism")) / "albums.json"
    if albums_file.exists():
        try:
            albums = json.loads(albums_file.read_text())
            stats["total_albums"] = len(albums)
        except Exception:
            pass

    return stats


def get_albums() -> List[dict]:
    """Get list of albums."""
    cfg = get_config()
    albums_file = Path(cfg.get("data_path", "/srv/photoprism")) / "albums.json"
    if albums_file.exists():
        try:
            return json.loads(albums_file.read_text())
        except Exception:
            pass
    return []


def save_albums(albums: List[dict]):
    """Save albums list."""
    cfg = get_config()
    albums_file = Path(cfg.get("data_path", "/srv/photoprism")) / "albums.json"
    albums_file.parent.mkdir(parents=True, exist_ok=True)
    albums_file.write_text(json.dumps(albums, indent=2))


def get_users() -> List[dict]:
    """Get list of users (simplified - stored locally)."""
    cfg = get_config()
    users_file = Path(cfg.get("data_path", "/srv/photoprism")) / "users.json"
    if users_file.exists():
        try:
            return json.loads(users_file.read_text())
        except Exception:
            pass
    return [{"username": "admin", "role": "admin", "created": "system"}]


def save_users(users: List[dict]):
    """Save users list."""
    cfg = get_config()
    users_file = Path(cfg.get("data_path", "/srv/photoprism")) / "users.json"
    users_file.parent.mkdir(parents=True, exist_ok=True)
    users_file.write_text(json.dumps(users, indent=2))


# ============================================================================
# Public Endpoints
# ============================================================================

@router.get("/health")
async def health():
    """Health check."""
    return {"status": "ok", "module": "photoprism"}


@router.get("/status")
async def status():
    """Get PhotoPrism service status."""
    cfg = get_config()
    rt = detect_runtime()
    container = get_container_status()
    lib_stats = get_library_stats()

    return {
        "enabled": cfg.get("enabled", False),
        "image": cfg.get("image", "photoprism/photoprism:latest"),
        "port": cfg.get("port", 2342),
        "data_path": cfg.get("data_path", "/srv/photoprism"),
        "originals_path": cfg.get("originals_path", "/srv/photoprism/originals"),
        "import_path": cfg.get("import_path", "/srv/photoprism/import"),
        "timezone": cfg.get("timezone", "Europe/Paris"),
        "domain": cfg.get("domain", "photos.secubox.local"),
        "haproxy": cfg.get("haproxy", False),
        "face_recognition": cfg.get("face_recognition", True),
        "experimental": cfg.get("experimental", False),
        "readonly": cfg.get("readonly", False),
        "public": cfg.get("public", False),
        "docker_available": rt is not None,
        "runtime": rt or "none",
        "container_status": container["status"],
        "container_uptime": container["uptime"],
        "library_stats": lib_stats,
    }


# ============================================================================
# Protected Endpoints - Configuration
# ============================================================================

@router.get("/config")
async def get_photoprism_config(user=Depends(require_jwt)):
    """Get PhotoPrism configuration."""
    cfg = get_config()
    # Remove sensitive data
    cfg.pop("admin_password", None)
    return cfg


@router.post("/config")
async def set_photoprism_config(config: PhotoprismConfig, user=Depends(require_jwt)):
    """Update PhotoPrism configuration."""
    cfg = get_config()
    cfg.update(config.dict())
    save_config(cfg)
    log.info(f"Config updated by {user.get('sub', 'unknown')}")
    return {"success": True}


# ============================================================================
# Library Management
# ============================================================================

@router.get("/library/stats")
async def get_library_statistics(user=Depends(require_jwt)):
    """Get library statistics."""
    return get_library_stats()


@router.post("/library/index")
async def start_indexing(user=Depends(require_jwt)):
    """Start library indexing."""
    if not is_running():
        return {"success": False, "error": "PhotoPrism is not running"}

    rt = detect_runtime()
    if not rt:
        return {"success": False, "error": "No container runtime"}

    log.info(f"Starting index by {user.get('sub', 'unknown')}")

    try:
        # Run photoprism index command in container
        result = subprocess.run(
            [rt, "exec", CONTAINER_NAME, "photoprism", "index"],
            capture_output=True, text=True, timeout=300
        )
        if result.returncode == 0:
            return {"success": True, "output": "Indexing started"}
        else:
            return {"success": False, "error": result.stderr.strip() or "Indexing failed"}
    except subprocess.TimeoutExpired:
        return {"success": True, "output": "Indexing in progress (background)"}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.post("/library/import")
async def import_photos(user=Depends(require_jwt)):
    """Import photos from import folder."""
    if not is_running():
        return {"success": False, "error": "PhotoPrism is not running"}

    rt = detect_runtime()
    if not rt:
        return {"success": False, "error": "No container runtime"}

    log.info(f"Starting import by {user.get('sub', 'unknown')}")

    try:
        # Run photoprism import command
        result = subprocess.run(
            [rt, "exec", CONTAINER_NAME, "photoprism", "import"],
            capture_output=True, text=True, timeout=300
        )
        if result.returncode == 0:
            return {"success": True, "output": "Import started"}
        else:
            return {"success": False, "error": result.stderr.strip() or "Import failed"}
    except subprocess.TimeoutExpired:
        return {"success": True, "output": "Import in progress (background)"}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ============================================================================
# Album Management
# ============================================================================

@router.get("/albums")
async def list_albums(user=Depends(require_jwt)):
    """List all albums."""
    return {"albums": get_albums()}


@router.post("/album/create")
async def create_album(album: AlbumCreate, user=Depends(require_jwt)):
    """Create a new album."""
    albums = get_albums()

    # Check for duplicate
    for a in albums:
        if a.get("title", "").lower() == album.title.lower():
            return {"success": False, "error": "Album already exists"}

    new_album = {
        "id": f"album_{len(albums)+1}_{int(datetime.now().timestamp())}",
        "title": album.title,
        "description": album.description,
        "created": datetime.now().isoformat(),
        "photo_count": 0,
    }
    albums.append(new_album)
    save_albums(albums)

    log.info(f"Album created: {album.title} by {user.get('sub', 'unknown')}")
    return {"success": True, "album": new_album}


@router.delete("/album/{album_id}")
async def delete_album(album_id: str, user=Depends(require_jwt)):
    """Delete an album."""
    albums = get_albums()
    new_albums = [a for a in albums if a.get("id") != album_id]

    if len(new_albums) == len(albums):
        return {"success": False, "error": "Album not found"}

    save_albums(new_albums)
    log.info(f"Album deleted: {album_id} by {user.get('sub', 'unknown')}")
    return {"success": True}


# ============================================================================
# Face Recognition
# ============================================================================

@router.get("/faces")
async def get_face_status(user=Depends(require_jwt)):
    """Get face recognition status."""
    cfg = get_config()
    return {
        "enabled": cfg.get("face_recognition", True),
        "status": "active" if cfg.get("face_recognition", True) and is_running() else "inactive",
    }


@router.post("/faces/enable")
async def enable_face_recognition(user=Depends(require_jwt)):
    """Enable face recognition."""
    cfg = get_config()
    cfg["face_recognition"] = True
    save_config(cfg)
    log.info(f"Face recognition enabled by {user.get('sub', 'unknown')}")
    return {"success": True, "message": "Restart PhotoPrism to apply"}


@router.post("/faces/disable")
async def disable_face_recognition(user=Depends(require_jwt)):
    """Disable face recognition."""
    cfg = get_config()
    cfg["face_recognition"] = False
    save_config(cfg)
    log.info(f"Face recognition disabled by {user.get('sub', 'unknown')}")
    return {"success": True, "message": "Restart PhotoPrism to apply"}


# ============================================================================
# Storage
# ============================================================================

@router.get("/storage")
async def get_storage_info(user=Depends(require_jwt)):
    """Get storage information."""
    cfg = get_config()
    data_path = Path(cfg.get("data_path", "/srv/photoprism"))
    originals_path = Path(cfg.get("originals_path", "/srv/photoprism/originals"))
    import_path = Path(cfg.get("import_path", "/srv/photoprism/import"))

    storage = {
        "data_path": str(data_path),
        "originals_path": str(originals_path),
        "import_path": str(import_path),
        "data_size": "0",
        "originals_size": "0",
        "import_size": "0",
        "disk_free": "0",
        "disk_total": "0",
        "disk_used_percent": 0,
    }

    try:
        # Get sizes
        for path_key, path in [("data", data_path), ("originals", originals_path), ("import", import_path)]:
            if path.exists():
                result = subprocess.run(
                    ["du", "-sh", str(path)],
                    capture_output=True, text=True, timeout=30
                )
                if result.stdout:
                    storage[f"{path_key}_size"] = result.stdout.split()[0]

        # Get disk space
        if data_path.exists():
            result = subprocess.run(
                ["df", "-h", str(data_path)],
                capture_output=True, text=True, timeout=10
            )
            if result.stdout:
                lines = result.stdout.strip().split('\n')
                if len(lines) > 1:
                    parts = lines[1].split()
                    if len(parts) >= 5:
                        storage["disk_total"] = parts[1]
                        storage["disk_free"] = parts[3]
                        storage["disk_used_percent"] = int(parts[4].rstrip('%'))
    except Exception:
        pass

    return storage


# ============================================================================
# User Management
# ============================================================================

@router.get("/users")
async def list_users(user=Depends(require_jwt)):
    """List users."""
    users = get_users()
    # Remove sensitive data
    return {"users": [{"username": u["username"], "role": u["role"]} for u in users]}


@router.post("/user")
async def create_user(new_user: UserCreate, user=Depends(require_jwt)):
    """Create a new user."""
    users = get_users()

    # Check for duplicate
    for u in users:
        if u["username"].lower() == new_user.username.lower():
            return {"success": False, "error": "User already exists"}

    users.append({
        "username": new_user.username,
        "password": new_user.password,  # In production, hash this
        "role": new_user.role,
        "created": datetime.now().isoformat(),
    })
    save_users(users)

    log.info(f"User created: {new_user.username} by {user.get('sub', 'unknown')}")
    return {"success": True}


@router.delete("/user/{username}")
async def delete_user(username: str, user=Depends(require_jwt)):
    """Delete a user."""
    if username.lower() == "admin":
        return {"success": False, "error": "Cannot delete admin user"}

    users = get_users()
    new_users = [u for u in users if u["username"].lower() != username.lower()]

    if len(new_users) == len(users):
        return {"success": False, "error": "User not found"}

    save_users(new_users)
    log.info(f"User deleted: {username} by {user.get('sub', 'unknown')}")
    return {"success": True}


# ============================================================================
# Container Management
# ============================================================================

@router.get("/container/status")
async def container_status(user=Depends(require_jwt)):
    """Get container status."""
    rt = detect_runtime()
    container = get_container_status()

    return {
        "runtime": rt or "none",
        "runtime_available": rt is not None,
        "container_name": CONTAINER_NAME,
        "status": container["status"],
        "uptime": container["uptime"],
    }


@router.post("/container/install")
async def install_photoprism(user=Depends(require_jwt)):
    """Install PhotoPrism container."""
    rt = detect_runtime()
    if not rt:
        return {"success": False, "error": "No container runtime (docker/podman) found"}

    cfg = get_config()
    data_path = Path(cfg.get("data_path", "/srv/photoprism"))
    originals_path = Path(cfg.get("originals_path", "/srv/photoprism/originals"))
    import_path = Path(cfg.get("import_path", "/srv/photoprism/import"))

    # Create directories
    data_path.mkdir(parents=True, exist_ok=True)
    originals_path.mkdir(parents=True, exist_ok=True)
    import_path.mkdir(parents=True, exist_ok=True)
    (data_path / "storage").mkdir(parents=True, exist_ok=True)

    # Pull image
    image = cfg.get("image", "photoprism/photoprism:latest")
    log.info(f"Installing PhotoPrism ({image}) by {user.get('sub', 'unknown')}")

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
async def start_photoprism(user=Depends(require_jwt)):
    """Start PhotoPrism container."""
    if is_running():
        return {"success": False, "error": "Already running"}

    rt = detect_runtime()
    if not rt:
        return {"success": False, "error": "No container runtime"}

    cfg = get_config()
    data_path = Path(cfg.get("data_path", "/srv/photoprism"))
    originals_path = Path(cfg.get("originals_path", "/srv/photoprism/originals"))
    import_path = Path(cfg.get("import_path", "/srv/photoprism/import"))
    port = cfg.get("port", 2342)
    image = cfg.get("image", "photoprism/photoprism:latest")
    tz = cfg.get("timezone", "Europe/Paris")

    # Ensure directories exist
    data_path.mkdir(parents=True, exist_ok=True)
    originals_path.mkdir(parents=True, exist_ok=True)
    import_path.mkdir(parents=True, exist_ok=True)
    (data_path / "storage").mkdir(parents=True, exist_ok=True)

    # Build environment variables
    env_vars = [
        f"PHOTOPRISM_SITE_URL=http://localhost:{port}/",
        f"PHOTOPRISM_ORIGINALS_PATH=/photoprism/originals",
        f"PHOTOPRISM_IMPORT_PATH=/photoprism/import",
        f"PHOTOPRISM_STORAGE_PATH=/photoprism/storage",
        "PHOTOPRISM_HTTP_PORT=2342",
        "PHOTOPRISM_DATABASE_DRIVER=sqlite",
        f"PHOTOPRISM_DETECT_NSFW={'true' if cfg.get('experimental', False) else 'false'}",
        f"PHOTOPRISM_EXPERIMENTAL={'true' if cfg.get('experimental', False) else 'false'}",
        f"PHOTOPRISM_READONLY={'true' if cfg.get('readonly', False) else 'false'}",
        f"PHOTOPRISM_PUBLIC={'true' if cfg.get('public', False) else 'false'}",
        f"PHOTOPRISM_DISABLE_FACES={'false' if cfg.get('face_recognition', True) else 'true'}",
        f"TZ={tz}",
    ]

    # Set admin password if configured
    admin_pass = cfg.get("admin_password", "")
    if admin_pass:
        env_vars.append(f"PHOTOPRISM_ADMIN_PASSWORD={admin_pass}")
    else:
        env_vars.append("PHOTOPRISM_AUTH_MODE=public")  # No auth if no password

    # Build run command
    cmd = [
        rt, "run", "-d",
        "--name", CONTAINER_NAME,
        "-v", f"{originals_path}:/photoprism/originals",
        "-v", f"{import_path}:/photoprism/import",
        "-v", f"{data_path}/storage:/photoprism/storage",
        "-p", f"127.0.0.1:{port}:2342",
        "--restart", "unless-stopped",
    ]

    # Add environment variables
    for env in env_vars:
        cmd.extend(["-e", env])

    cmd.append(image)

    log.info(f"Starting PhotoPrism by {user.get('sub', 'unknown')}")

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
async def stop_photoprism(user=Depends(require_jwt)):
    """Stop PhotoPrism container."""
    rt = detect_runtime()
    if not rt:
        return {"success": False, "error": "No container runtime"}

    log.info(f"Stopping PhotoPrism by {user.get('sub', 'unknown')}")

    try:
        subprocess.run([rt, "stop", CONTAINER_NAME], capture_output=True, timeout=30)
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.post("/container/restart")
async def restart_photoprism(user=Depends(require_jwt)):
    """Restart PhotoPrism container."""
    await stop_photoprism(user)
    await asyncio.sleep(2)
    return await start_photoprism(user)


@router.post("/container/uninstall")
async def uninstall_photoprism(user=Depends(require_jwt)):
    """Uninstall PhotoPrism container."""
    rt = detect_runtime()
    if not rt:
        return {"success": False, "error": "No container runtime"}

    log.info(f"Uninstalling PhotoPrism by {user.get('sub', 'unknown')}")

    try:
        subprocess.run([rt, "stop", CONTAINER_NAME], capture_output=True, timeout=30)
        subprocess.run([rt, "rm", "-f", CONTAINER_NAME], capture_output=True, timeout=10)
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.post("/container/update")
async def update_photoprism(user=Depends(require_jwt)):
    """Update PhotoPrism to latest image."""
    cfg = get_config()
    rt = detect_runtime()
    if not rt:
        return {"success": False, "error": "No container runtime"}

    image = cfg.get("image", "photoprism/photoprism:latest")
    log.info(f"Updating PhotoPrism ({image}) by {user.get('sub', 'unknown')}")

    try:
        # Pull new image
        result = subprocess.run(
            [rt, "pull", image],
            capture_output=True, text=True, timeout=600
        )
        if result.returncode != 0:
            return {"success": False, "error": result.stderr.strip()}

        # Restart if running
        if is_running():
            await restart_photoprism(user)

        return {"success": True, "output": "Update complete"}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ============================================================================
# Logs
# ============================================================================

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


# ============================================================================
# Backup/Restore
# ============================================================================

@router.post("/backup")
async def backup_photoprism(user=Depends(require_jwt)):
    """Backup PhotoPrism configuration and database."""
    cfg = get_config()
    data_path = Path(cfg.get("data_path", "/srv/photoprism"))
    storage_path = data_path / "storage"

    if not storage_path.exists():
        return {"success": False, "error": "No data to backup"}

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup_file = f"/tmp/photoprism-backup-{timestamp}.tar.gz"

    log.info(f"Creating backup by {user.get('sub', 'unknown')}")

    try:
        result = subprocess.run(
            ["tar", "-czf", backup_file, "-C", str(data_path), "storage"],
            capture_output=True, text=True, timeout=600
        )
        if result.returncode == 0:
            return {"success": True, "path": backup_file}
        else:
            return {"success": False, "error": result.stderr.strip()}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.post("/restore")
async def restore_photoprism(req: RestoreRequest, user=Depends(require_jwt)):
    """Restore PhotoPrism from backup."""
    if not Path(req.path).exists():
        return {"success": False, "error": "Backup file not found"}

    cfg = get_config()
    data_path = Path(cfg.get("data_path", "/srv/photoprism"))

    log.info(f"Restoring backup {req.path} by {user.get('sub', 'unknown')}")

    # Stop container first
    if is_running():
        await stop_photoprism(user)
        await asyncio.sleep(2)

    try:
        result = subprocess.run(
            ["tar", "-xzf", req.path, "-C", str(data_path)],
            capture_output=True, text=True, timeout=600
        )
        if result.returncode == 0:
            return {"success": True}
        else:
            return {"success": False, "error": result.stderr.strip()}
    except Exception as e:
        return {"success": False, "error": str(e)}


app.include_router(router)
