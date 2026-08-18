# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""secubox-photoprism — FastAPI application for PhotoPrism photo management.

Provides PhotoPrism Docker container management with library indexing,
face recognition, album management, and storage configuration.
"""
import asyncio
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

# ══════════════════════════════════════════════════════════════════
# Health Check Endpoint (public, no auth)
# ══════════════════════════════════════════════════════════════════

@app.get("/health")
async def health_check():
    """Public health check endpoint for sidebar status."""
    return {"status": "ok", "module": "deb"}

app.include_router(auth_router, prefix="/auth")
router = APIRouter()
log = get_logger("photoprism")

# Configuration
CONFIG_FILE = Path("/etc/secubox/photoprism.toml")
INSTALL_LIB = "/usr/share/secubox/lib/photoprism/install-lxc.sh"
PHOTOPRISMCTL = "/usr/sbin/photoprismctl"
# PhotoPrism runs as the `photoprism` podman container INSIDE the photoprism
# LXC (see lib/photoprism/install-lxc.sh), not on the host.
CONTAINER_NAME = "photoprism"
DEFAULT_CONFIG = {
    # LXC
    "name": "photoprism",
    "ip": "10.100.0.130",
    "path": "/data/lxc",
    # PhotoPrism (inside the LXC)
    "enabled": False,
    "image": "docker.io/photoprism/photoprism:latest",
    "port": 2342,
    "http_port": 2342,
    "data_path": "/data/photoprism",
    "originals_path": "/data/shared/photos",   # shared with Nextcloud "PhotoLibrary"
    "import_path": "/data/photoprism/import",
    "timezone": "Europe/Paris",
    "domain": "photoprism.gk2.secubox.in",
    "public_hostname": "photoprism.gk2.secubox.in",
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
    """Load + flatten photoprism.toml ([lxc]/[photoprism]/[exposure]) over defaults."""
    cfg = DEFAULT_CONFIG.copy()
    if CONFIG_FILE.exists():
        try:
            import tomllib
            raw = tomllib.loads(CONFIG_FILE.read_text())
            for section in ("lxc", "photoprism", "exposure"):
                for k, v in (raw.get(section) or {}).items():
                    cfg[k] = v
            for k, v in raw.items():        # tolerate flat keys too
                if not isinstance(v, dict):
                    cfg[k] = v
        except Exception:
            pass
    return cfg


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


def http_reachable() -> bool:
    """True if PhotoPrism answers on <ip>:<http_port> (inside its LXC)."""
    cfg = get_config()
    ip = cfg.get("ip", "10.100.0.130")
    port = cfg.get("http_port", cfg.get("port", 2342))
    try:
        r = subprocess.run(
            ["curl", "-fsS", "-o", "/dev/null", "--max-time", "3", f"http://{ip}:{port}/"],
            capture_output=True, timeout=5,
        )
        return r.returncode == 0
    except Exception:
        return False


def lxc_state() -> str:
    """LXC container state (best-effort; the dashboard user may lack access)."""
    cfg = get_config()
    try:
        r = subprocess.run(
            ["lxc-info", "-n", cfg.get("name", "photoprism"), "-P", cfg.get("path", "/data/lxc")],
            capture_output=True, text=True, timeout=5,
        )
        for line in r.stdout.splitlines():
            if line.strip().lower().startswith("state:"):
                return line.split(":", 1)[1].strip().lower()
    except Exception:
        pass
    return "unknown"


def get_container_status() -> dict:
    """PhotoPrism status — primary signal is HTTP reachability of the LXC
    instance (the dashboard runs unprivileged and can't always read lxc-info)."""
    if http_reachable():
        return {"status": "running", "uptime": ""}
    state = lxc_state()
    if state in ("stopped", "frozen"):
        return {"status": "stopped", "uptime": ""}
    return {"status": "not_installed", "uptime": ""}


def is_running() -> bool:
    """Check if PhotoPrism is reachable."""
    return http_reachable()


def _pm() -> list:
    """Command prefix to run podman inside the PhotoPrism LXC.

    NOTE: lxc-attach needs root; the dashboard runs as the unprivileged
    'secubox' user, so container-lifecycle verbs are best driven via
    photoprismctl from a root context. Read-only status uses http_reachable()."""
    cfg = get_config()
    return ["lxc-attach", "-n", cfg.get("name", "photoprism"),
            "-P", cfg.get("path", "/data/lxc"), "--", "podman"]


def _photoprismctl(verb: str, timeout: int = 60) -> dict:
    try:
        r = subprocess.run([PHOTOPRISMCTL, verb], capture_output=True, text=True, timeout=timeout)
        return {"success": r.returncode == 0, "stdout": r.stdout, "stderr": r.stderr}
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "timeout"}
    except Exception as e:
        return {"success": False, "error": str(e)}


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
    """Get PhotoPrism service status (native-LXC)."""
    cfg = get_config()
    container = get_container_status()
    lib_stats = get_library_stats()
    hostname = cfg.get("public_hostname", cfg.get("domain", "photoprism.gk2.secubox.in"))

    return {
        "deployment": "lxc-native",
        "enabled": cfg.get("enabled", False),
        "image": cfg.get("image", "docker.io/photoprism/photoprism:latest"),
        "port": cfg.get("port", 2342),
        "lxc_name": cfg.get("name", "photoprism"),
        "lxc_ip": cfg.get("ip", "10.100.0.130"),
        "lxc_state": lxc_state(),
        "http_reachable": http_reachable(),
        "data_path": cfg.get("data_path", "/data/photoprism"),
        "originals_path": cfg.get("originals_path", "/data/shared/photos"),
        "import_path": cfg.get("import_path", "/data/photoprism/import"),
        "timezone": cfg.get("timezone", "Europe/Paris"),
        "domain": hostname,
        "public_url": f"https://{hostname}/",
        "haproxy": cfg.get("haproxy", False),
        "face_recognition": cfg.get("face_recognition", True),
        "experimental": cfg.get("experimental", False),
        "readonly": cfg.get("readonly", False),
        "public": cfg.get("public", False),
        # webui back-compat keys (was Docker; now native-LXC):
        "runtime": "lxc-native",
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
def start_indexing(user=Depends(require_jwt)):
    """Start library indexing."""
    if not is_running():
        return {"success": False, "error": "PhotoPrism is not running"}

    log.info(f"Starting index by {user.get('sub', 'unknown')}")

    try:
        # Run photoprism index inside the LXC container.
        result = subprocess.run(
            _pm() + ["exec", CONTAINER_NAME, "photoprism", "index"],
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
def import_photos(user=Depends(require_jwt)):
    """Import photos from import folder."""
    if not is_running():
        return {"success": False, "error": "PhotoPrism is not running"}

    log.info(f"Starting import by {user.get('sub', 'unknown')}")

    try:
        # Run photoprism import inside the LXC container.
        result = subprocess.run(
            _pm() + ["exec", CONTAINER_NAME, "photoprism", "import"],
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
def get_storage_info(user=Depends(require_jwt)):
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
    """LXC + reachability status (kept under /container/* for webui back-compat)."""
    container = get_container_status()
    return {
        "runtime": "lxc-native",
        "runtime_available": True,
        "container_name": CONTAINER_NAME,
        "lxc_state": lxc_state(),
        "http_reachable": http_reachable(),
        "status": container["status"],
        "uptime": container["uptime"],
    }


@router.post("/container/install")
def install_photoprism(user=Depends(require_jwt)):
    """Provision the LXC + podman + PhotoPrism. Long-running → detached."""
    if not Path(INSTALL_LIB).exists():
        return {"success": False, "error": f"install script missing at {INSTALL_LIB}"}
    log.info(f"Launching native-LXC PhotoPrism install by {user.get('sub', 'unknown')}")
    try:
        subprocess.Popen(
            ["bash", INSTALL_LIB],
            stdout=open("/var/log/secubox/photoprism-install.log", "a"),
            stderr=subprocess.STDOUT, start_new_session=True,
        )
        return {"success": True,
                "message": "Install started (several minutes). Follow "
                           "/var/log/secubox/photoprism-install.log or 'photoprismctl logs'."}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.post("/container/start")
async def start_photoprism(user=Depends(require_jwt)):
    """Start PhotoPrism (LXC)."""
    log.info(f"Starting PhotoPrism LXC by {user.get('sub', 'unknown')}")
    r = _photoprismctl("start")
    return {"success": r.get("success", False), "output": r.get("stdout", r.get("error", ""))}


@router.post("/container/stop")
async def stop_photoprism(user=Depends(require_jwt)):
    """Stop PhotoPrism (LXC)."""
    log.info(f"Stopping PhotoPrism LXC by {user.get('sub', 'unknown')}")
    r = _photoprismctl("stop")
    return {"success": r.get("success", False), "output": r.get("stdout", r.get("error", ""))}


@router.post("/container/restart")
async def restart_photoprism(user=Depends(require_jwt)):
    """Restart PhotoPrism (LXC)."""
    log.info(f"Restarting PhotoPrism LXC by {user.get('sub', 'unknown')}")
    r = _photoprismctl("restart")
    return {"success": r.get("success", False), "output": r.get("stdout", r.get("error", ""))}


@router.post("/container/uninstall")
async def uninstall_photoprism(user=Depends(require_jwt)):
    """Stop the LXC (data on /data/photoprism + /data/shared/photos preserved)."""
    log.info(f"Stopping PhotoPrism LXC (data preserved) by {user.get('sub', 'unknown')}")
    r = _photoprismctl("stop")
    return {"success": r.get("success", False), "message": "LXC stopped, data preserved"}


@router.post("/container/update")
def update_photoprism(user=Depends(require_jwt)):
    """Pull the latest image inside the LXC + restart."""
    cfg = get_config()
    image = cfg.get("image", "docker.io/photoprism/photoprism:latest")
    log.info(f"Updating PhotoPrism image ({image}) by {user.get('sub', 'unknown')}")
    try:
        pull = subprocess.run(_pm() + ["pull", image], capture_output=True, text=True, timeout=600)
        if pull.returncode != 0:
            return {"success": False, "error": pull.stderr.strip() or "pull failed"}
        _photoprismctl("restart")
        return {"success": True, "output": "Update complete"}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ============================================================================
# Logs
# ============================================================================

@router.get("/logs")
def get_logs(lines: int = 50, user=Depends(require_jwt)):
    """Tail photoprism.service journal inside the LXC."""
    cfg = get_config()
    try:
        result = subprocess.run(
            ["lxc-attach", "-n", cfg.get("name", "photoprism"),
             "-P", cfg.get("path", "/data/lxc"), "--",
             "journalctl", "-u", "photoprism", "-n", str(lines), "--no-pager"],
            capture_output=True, text=True, timeout=15,
        )
        return {"logs": (result.stdout + result.stderr) or "No logs available"}
    except Exception:
        return {"logs": "No logs available"}


# ============================================================================
# Backup/Restore
# ============================================================================

@router.post("/backup")
def backup_photoprism(user=Depends(require_jwt)):
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
