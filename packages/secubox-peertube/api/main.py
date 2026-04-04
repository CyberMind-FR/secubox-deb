"""secubox-peertube -- FastAPI application for PeerTube video platform management.

Provides PeerTube Docker container management with video, channel, user,
federation, transcoding, plugin, and storage management.

SecuBox-Deb :: PeerTube
CyberMind -- https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate
"""
import asyncio
import json
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any

from fastapi import FastAPI, APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from secubox_core.auth import router as auth_router, require_jwt
from secubox_core.logger import get_logger

app = FastAPI(title="secubox-peertube", version="1.0.0", root_path="/api/v1/peertube")
app.include_router(auth_router, prefix="/auth")
router = APIRouter()
log = get_logger("peertube")

# Configuration
CONFIG_FILE = Path("/etc/secubox/peertube.toml")
CONTAINER_NAME = "secbx-peertube"
DEFAULT_CONFIG = {
    "enabled": False,
    "image": "chocobozzz/peertube:production-bookworm",
    "http_port": 9000,
    "data_path": "/srv/peertube",
    "timezone": "Europe/Paris",
    "domain": "peertube.secubox.local",
    "haproxy": False,
    "signup_enabled": False,
    "transcoding_enabled": True,
    "transcoding_threads": 2,
    "hls_enabled": True,
    "webtorrent_enabled": True,
    "federation_enabled": True,
    "auto_follow_back": False,
    "instance_name": "SecuBox PeerTube",
    "short_description": "Federated video platform on SecuBox",
}


# ============================================================================
# Models
# ============================================================================

class PeerTubeConfig(BaseModel):
    enabled: bool = False
    image: str = "chocobozzz/peertube:production-bookworm"
    http_port: int = 9000
    data_path: str = "/srv/peertube"
    timezone: str = "Europe/Paris"
    domain: str = "peertube.secubox.local"
    haproxy: bool = False
    signup_enabled: bool = False
    transcoding_enabled: bool = True
    transcoding_threads: int = 2
    hls_enabled: bool = True
    webtorrent_enabled: bool = True
    federation_enabled: bool = True
    auto_follow_back: bool = False


class InstanceSettings(BaseModel):
    name: str = "SecuBox PeerTube"
    short_description: str = "Video hosting on SecuBox"
    description: str = ""
    terms: str = ""
    signup_enabled: bool = False
    signup_requires_email: bool = True


class ChannelCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=50)
    display_name: str = Field(..., min_length=1, max_length=100)
    description: str = ""


class UserCreate(BaseModel):
    username: str = Field(..., min_length=1, max_length=50)
    email: str
    password: str = Field(..., min_length=8)
    role: int = 2  # 0=admin, 1=moderator, 2=user
    video_quota: int = -1  # -1 = unlimited


class FollowRequest(BaseModel):
    hosts: List[str]


class TranscodingSettings(BaseModel):
    enabled: bool = True
    threads: int = 2
    hls_enabled: bool = True
    webtorrent_enabled: bool = True
    resolutions: Dict[str, bool] = {
        "240p": True,
        "360p": True,
        "480p": True,
        "720p": True,
        "1080p": True,
        "1440p": False,
        "2160p": False,
    }


class PluginInstall(BaseModel):
    npm_name: str  # e.g., peertube-plugin-auth-ldap


# ============================================================================
# Helpers
# ============================================================================

def get_config() -> dict:
    """Load peertube configuration."""
    if CONFIG_FILE.exists():
        try:
            import tomllib
            return tomllib.loads(CONFIG_FILE.read_text())
        except Exception:
            pass
    return DEFAULT_CONFIG.copy()


def save_config(config: dict):
    """Save peertube configuration."""
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    lines = ["# PeerTube configuration"]
    for k, v in config.items():
        if isinstance(v, bool):
            lines.append(f"{k} = {str(v).lower()}")
        elif isinstance(v, int):
            lines.append(f"{k} = {v}")
        elif isinstance(v, dict):
            lines.append(f'{k} = {json.dumps(v)}')
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
    """Get PeerTube container status."""
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
    """Check if PeerTube container is running."""
    return get_container_status()["status"] == "running"


def run_in_container(cmd: List[str], timeout: int = 30) -> dict:
    """Run command inside PeerTube container."""
    rt = detect_runtime()
    if not rt:
        return {"success": False, "error": "No container runtime"}

    try:
        full_cmd = [rt, "exec", CONTAINER_NAME] + cmd
        result = subprocess.run(full_cmd, capture_output=True, text=True, timeout=timeout)
        return {
            "success": result.returncode == 0,
            "stdout": result.stdout,
            "stderr": result.stderr
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Command timeout"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def peertube_api(endpoint: str, method: str = "GET", data: dict = None) -> dict:
    """Call PeerTube internal API."""
    cfg = get_config()
    port = cfg.get("http_port", 9000)
    curl_cmd = ["curl", "-s", f"http://127.0.0.1:{port}/api/v1{endpoint}"]

    if method == "POST" and data:
        curl_cmd.extend(["-X", "POST", "-H", "Content-Type: application/json", "-d", json.dumps(data)])
    elif method == "DELETE":
        curl_cmd.extend(["-X", "DELETE"])

    result = run_in_container(curl_cmd)

    if result.get("success") and result.get("stdout"):
        try:
            return {"success": True, "data": json.loads(result["stdout"])}
        except json.JSONDecodeError:
            return {"success": True, "data": result["stdout"]}

    return {"success": False, "error": result.get("error", "API call failed")}


# ============================================================================
# Public Endpoints
# ============================================================================

@router.get("/health")
async def health():
    """Health check."""
    return {"status": "ok", "module": "peertube"}


@router.get("/status")
async def status():
    """Get PeerTube service status."""
    cfg = get_config()
    rt = detect_runtime()
    container = get_container_status()

    # Disk usage
    disk_usage = ""
    data_path = Path(cfg.get("data_path", "/srv/peertube"))
    if data_path.exists():
        try:
            result = subprocess.run(
                ["du", "-sh", str(data_path)],
                capture_output=True, text=True, timeout=30
            )
            disk_usage = result.stdout.split()[0] if result.stdout else ""
        except Exception:
            pass

    # Video count (if storage exists)
    video_count = 0
    videos_path = data_path / "storage" / "videos"
    if videos_path.exists():
        try:
            video_count = len(list(videos_path.glob("*")))
        except Exception:
            pass

    return {
        "enabled": cfg.get("enabled", False),
        "image": cfg.get("image", DEFAULT_CONFIG["image"]),
        "http_port": cfg.get("http_port", 9000),
        "data_path": cfg.get("data_path", "/srv/peertube"),
        "timezone": cfg.get("timezone", "Europe/Paris"),
        "domain": cfg.get("domain", "peertube.secubox.local"),
        "haproxy": cfg.get("haproxy", False),
        "signup_enabled": cfg.get("signup_enabled", False),
        "transcoding_enabled": cfg.get("transcoding_enabled", True),
        "federation_enabled": cfg.get("federation_enabled", True),
        "docker_available": rt is not None,
        "runtime": rt or "none",
        "container_status": container["status"],
        "container_uptime": container["uptime"],
        "disk_usage": disk_usage,
        "video_count": video_count,
        "instance_name": cfg.get("instance_name", "SecuBox PeerTube"),
    }


# ============================================================================
# Instance Management
# ============================================================================

@router.get("/instance")
async def get_instance(user=Depends(require_jwt)):
    """Get instance information."""
    cfg = get_config()
    return {
        "name": cfg.get("instance_name", "SecuBox PeerTube"),
        "short_description": cfg.get("short_description", "Video hosting on SecuBox"),
        "description": cfg.get("description", ""),
        "terms": cfg.get("terms", ""),
        "signup_enabled": cfg.get("signup_enabled", False),
        "signup_requires_email": cfg.get("signup_requires_email", True),
        "domain": cfg.get("domain", "peertube.secubox.local"),
    }


@router.post("/instance")
async def update_instance(settings: InstanceSettings, user=Depends(require_jwt)):
    """Update instance settings."""
    cfg = get_config()
    cfg["instance_name"] = settings.name
    cfg["short_description"] = settings.short_description
    cfg["description"] = settings.description
    cfg["terms"] = settings.terms
    cfg["signup_enabled"] = settings.signup_enabled
    cfg["signup_requires_email"] = settings.signup_requires_email
    save_config(cfg)
    log.info(f"Instance settings updated by {user.get('sub', 'unknown')}")
    return {"success": True}


# ============================================================================
# Video Management
# ============================================================================

@router.get("/videos")
async def list_videos(
    start: int = 0,
    count: int = 15,
    sort: str = "-publishedAt",
    user=Depends(require_jwt)
):
    """List videos on instance."""
    if not is_running():
        return {"videos": [], "total": 0, "error": "Container not running"}

    result = peertube_api(f"/videos?start={start}&count={count}&sort={sort}")

    if result.get("success") and isinstance(result.get("data"), dict):
        data = result["data"]
        return {"videos": data.get("data", []), "total": data.get("total", 0)}

    return {"videos": [], "total": 0}


@router.delete("/video/{video_id}")
async def delete_video(video_id: str, user=Depends(require_jwt)):
    """Delete a video."""
    if not is_running():
        return {"success": False, "error": "Container not running"}

    log.info(f"Deleting video {video_id} by {user.get('sub', 'unknown')}")
    result = peertube_api(f"/videos/{video_id}", method="DELETE")
    return {"success": result.get("success", False)}


# ============================================================================
# Channel Management
# ============================================================================

@router.get("/channels")
async def list_channels(user=Depends(require_jwt)):
    """List video channels."""
    if not is_running():
        return {"channels": [], "error": "Container not running"}

    result = peertube_api("/video-channels?count=100")

    if result.get("success") and isinstance(result.get("data"), dict):
        data = result["data"]
        return {"channels": data.get("data", []), "total": data.get("total", 0)}

    return {"channels": [], "total": 0}


@router.post("/channel")
async def create_channel(channel: ChannelCreate, user=Depends(require_jwt)):
    """Create a video channel."""
    if not is_running():
        return {"success": False, "error": "Container not running"}

    log.info(f"Creating channel {channel.name} by {user.get('sub', 'unknown')}")
    result = peertube_api("/video-channels", method="POST", data={
        "name": channel.name,
        "displayName": channel.display_name,
        "description": channel.description,
    })
    return {"success": result.get("success", False)}


@router.delete("/channel/{channel_name}")
async def delete_channel(channel_name: str, user=Depends(require_jwt)):
    """Delete a video channel."""
    if not is_running():
        return {"success": False, "error": "Container not running"}

    log.info(f"Deleting channel {channel_name} by {user.get('sub', 'unknown')}")
    result = peertube_api(f"/video-channels/{channel_name}", method="DELETE")
    return {"success": result.get("success", False)}


# ============================================================================
# User Management
# ============================================================================

@router.get("/users")
async def list_users(user=Depends(require_jwt)):
    """List users."""
    if not is_running():
        return {"users": [], "error": "Container not running"}

    result = peertube_api("/users?count=100")

    if result.get("success") and isinstance(result.get("data"), dict):
        data = result["data"]
        return {"users": data.get("data", []), "total": data.get("total", 0)}

    return {"users": [], "total": 0}


@router.post("/user")
async def create_user(new_user: UserCreate, user=Depends(require_jwt)):
    """Create a user."""
    if not is_running():
        return {"success": False, "error": "Container not running"}

    log.info(f"Creating user {new_user.username} by {user.get('sub', 'unknown')}")
    result = peertube_api("/users", method="POST", data={
        "username": new_user.username,
        "email": new_user.email,
        "password": new_user.password,
        "role": new_user.role,
        "videoQuota": new_user.video_quota,
    })
    return {"success": result.get("success", False), "username": new_user.username}


@router.delete("/user/{user_id}")
async def delete_user(user_id: int, user=Depends(require_jwt)):
    """Delete a user."""
    if not is_running():
        return {"success": False, "error": "Container not running"}

    log.info(f"Deleting user {user_id} by {user.get('sub', 'unknown')}")
    result = peertube_api(f"/users/{user_id}", method="DELETE")
    return {"success": result.get("success", False)}


# ============================================================================
# Federation (ActivityPub)
# ============================================================================

@router.get("/federation/followers")
async def get_followers(user=Depends(require_jwt)):
    """Get instance followers."""
    if not is_running():
        return {"followers": [], "error": "Container not running"}

    result = peertube_api("/server/followers?count=100")

    if result.get("success") and isinstance(result.get("data"), dict):
        data = result["data"]
        return {"followers": data.get("data", []), "total": data.get("total", 0)}

    return {"followers": [], "total": 0}


@router.get("/federation/following")
async def get_following(user=Depends(require_jwt)):
    """Get instances we are following."""
    if not is_running():
        return {"following": [], "error": "Container not running"}

    result = peertube_api("/server/following?count=100")

    if result.get("success") and isinstance(result.get("data"), dict):
        data = result["data"]
        return {"following": data.get("data", []), "total": data.get("total", 0)}

    return {"following": [], "total": 0}


@router.post("/federation/follow")
async def follow_instance(req: FollowRequest, user=Depends(require_jwt)):
    """Follow remote instances."""
    if not is_running():
        return {"success": False, "error": "Container not running"}

    log.info(f"Following instances {req.hosts} by {user.get('sub', 'unknown')}")
    result = peertube_api("/server/following", method="POST", data={"hosts": req.hosts})
    return {"success": result.get("success", False)}


@router.delete("/federation/following/{follow_id}")
async def unfollow_instance(follow_id: int, user=Depends(require_jwt)):
    """Unfollow a remote instance."""
    if not is_running():
        return {"success": False, "error": "Container not running"}

    log.info(f"Unfollowing {follow_id} by {user.get('sub', 'unknown')}")
    result = peertube_api(f"/server/following/{follow_id}", method="DELETE")
    return {"success": result.get("success", False)}


# ============================================================================
# Transcoding
# ============================================================================

@router.get("/transcoding/jobs")
async def get_transcoding_jobs(user=Depends(require_jwt)):
    """Get transcoding job queue."""
    if not is_running():
        return {"jobs": [], "error": "Container not running"}

    result = peertube_api("/jobs/video-transcoding?count=50")

    if result.get("success") and isinstance(result.get("data"), dict):
        data = result["data"]
        return {"jobs": data.get("data", []), "total": data.get("total", 0)}

    return {"jobs": [], "total": 0}


@router.get("/transcoding/settings")
async def get_transcoding_settings(user=Depends(require_jwt)):
    """Get transcoding settings."""
    cfg = get_config()
    return {
        "enabled": cfg.get("transcoding_enabled", True),
        "threads": cfg.get("transcoding_threads", 2),
        "hls_enabled": cfg.get("hls_enabled", True),
        "webtorrent_enabled": cfg.get("webtorrent_enabled", True),
        "resolutions": cfg.get("transcoding_resolutions", {
            "240p": True,
            "360p": True,
            "480p": True,
            "720p": True,
            "1080p": True,
            "1440p": False,
            "2160p": False,
        })
    }


@router.post("/transcoding/settings")
async def update_transcoding_settings(settings: TranscodingSettings, user=Depends(require_jwt)):
    """Update transcoding settings."""
    cfg = get_config()
    cfg["transcoding_enabled"] = settings.enabled
    cfg["transcoding_threads"] = settings.threads
    cfg["hls_enabled"] = settings.hls_enabled
    cfg["webtorrent_enabled"] = settings.webtorrent_enabled
    cfg["transcoding_resolutions"] = settings.resolutions
    save_config(cfg)

    log.info(f"Transcoding settings updated by {user.get('sub', 'unknown')}")
    return {"success": True, "message": "Restart PeerTube to apply changes"}


# ============================================================================
# Storage
# ============================================================================

@router.get("/storage/stats")
async def get_storage_stats(user=Depends(require_jwt)):
    """Get storage usage statistics."""
    cfg = get_config()
    data_path = Path(cfg.get("data_path", "/srv/peertube"))

    stats = {
        "total": "",
        "videos": "",
        "thumbnails": "",
        "torrents": "",
        "streaming_playlists": "",
    }

    if not data_path.exists():
        return {"stats": stats, "error": "Data path not found"}

    try:
        # Total size
        result = subprocess.run(
            ["du", "-sh", str(data_path)],
            capture_output=True, text=True, timeout=30
        )
        if result.stdout:
            stats["total"] = result.stdout.split()[0]

        # Subdirectory sizes
        storage_path = data_path / "storage"
        for subdir in ["videos", "thumbnails", "torrents", "streaming-playlists"]:
            sub_path = storage_path / subdir
            if sub_path.exists():
                result = subprocess.run(
                    ["du", "-sh", str(sub_path)],
                    capture_output=True, text=True, timeout=30
                )
                if result.stdout:
                    key = subdir.replace("-", "_")
                    stats[key] = result.stdout.split()[0]
    except Exception as e:
        return {"stats": stats, "error": str(e)}

    return {"stats": stats}


# ============================================================================
# Plugins
# ============================================================================

@router.get("/plugins")
async def list_plugins(user=Depends(require_jwt)):
    """List installed plugins."""
    if not is_running():
        return {"plugins": [], "error": "Container not running"}

    result = peertube_api("/plugins?count=100")

    if result.get("success") and isinstance(result.get("data"), dict):
        data = result["data"]
        return {"plugins": data.get("data", []), "total": data.get("total", 0)}

    return {"plugins": [], "total": 0}


@router.post("/plugin/install")
async def install_plugin(plugin: PluginInstall, user=Depends(require_jwt)):
    """Install a plugin."""
    if not is_running():
        return {"success": False, "error": "Container not running"}

    log.info(f"Installing plugin {plugin.npm_name} by {user.get('sub', 'unknown')}")
    result = peertube_api("/plugins/install", method="POST", data={"npmName": plugin.npm_name})
    return {"success": result.get("success", False)}


@router.delete("/plugin/{plugin_name}")
async def uninstall_plugin(plugin_name: str, user=Depends(require_jwt)):
    """Uninstall a plugin."""
    if not is_running():
        return {"success": False, "error": "Container not running"}

    log.info(f"Uninstalling plugin {plugin_name} by {user.get('sub', 'unknown')}")
    result = peertube_api(f"/plugins/uninstall", method="POST", data={"npmName": plugin_name})
    return {"success": result.get("success", False)}


# ============================================================================
# Container Management
# ============================================================================

@router.get("/container/status")
async def container_status():
    """Get container runtime status."""
    rt = detect_runtime()
    container = get_container_status()

    return {
        "runtime": rt or "none",
        "docker_available": rt is not None,
        "status": container["status"],
        "uptime": container["uptime"],
    }


@router.post("/container/install")
async def install_peertube(user=Depends(require_jwt)):
    """Install PeerTube container."""
    rt = detect_runtime()
    if not rt:
        return {"success": False, "error": "No container runtime (docker/podman) found"}

    cfg = get_config()
    data_path = Path(cfg.get("data_path", "/srv/peertube"))

    # Create directories
    for subdir in ["data", "config", "storage"]:
        (data_path / subdir).mkdir(parents=True, exist_ok=True)

    # Pull image
    image = cfg.get("image", DEFAULT_CONFIG["image"])
    log.info(f"Installing PeerTube ({image}) by {user.get('sub', 'unknown')}")

    try:
        result = subprocess.run(
            [rt, "pull", image],
            capture_output=True, text=True, timeout=600
        )
        if result.returncode != 0:
            return {"success": False, "error": result.stderr.strip(), "output": result.stdout}

        return {"success": True, "output": "Image pulled successfully"}
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Pull timeout (>10 minutes)"}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.post("/container/start")
async def start_peertube(user=Depends(require_jwt)):
    """Start PeerTube container."""
    if is_running():
        return {"success": False, "error": "Already running"}

    rt = detect_runtime()
    if not rt:
        return {"success": False, "error": "No container runtime"}

    cfg = get_config()
    data_path = Path(cfg.get("data_path", "/srv/peertube"))
    port = cfg.get("http_port", 9000)
    image = cfg.get("image", DEFAULT_CONFIG["image"])
    tz = cfg.get("timezone", "Europe/Paris")
    domain = cfg.get("domain", "peertube.secubox.local")

    # Ensure directories exist
    for subdir in ["data", "config", "storage"]:
        (data_path / subdir).mkdir(parents=True, exist_ok=True)

    # Build run command - PeerTube with embedded PostgreSQL and Redis
    cmd = [
        rt, "run", "-d",
        "--name", CONTAINER_NAME,
        "-v", f"{data_path}/data:/data",
        "-v", f"{data_path}/config:/config",
        "-v", f"{data_path}/storage:/var/www/peertube/storage",
        "-e", f"TZ={tz}",
        "-e", f"PEERTUBE_WEBSERVER_HOSTNAME={domain}",
        "-e", "PEERTUBE_WEBSERVER_PORT=443",
        "-e", "PEERTUBE_WEBSERVER_HTTPS=true",
        "-e", "PEERTUBE_DB_SSL=false",
        "-e", "PEERTUBE_TRUST_PROXY=loopback,uniquelocal",
        "-e", "PT_INITIAL_ROOT_PASSWORD=secubox",
        "-p", f"127.0.0.1:{port}:9000",
        "--restart", "unless-stopped",
    ]

    cmd.append(image)

    log.info(f"Starting PeerTube by {user.get('sub', 'unknown')}")

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
async def stop_peertube(user=Depends(require_jwt)):
    """Stop PeerTube container."""
    rt = detect_runtime()
    if not rt:
        return {"success": False, "error": "No container runtime"}

    log.info(f"Stopping PeerTube by {user.get('sub', 'unknown')}")

    try:
        subprocess.run([rt, "stop", CONTAINER_NAME], capture_output=True, timeout=30)
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.post("/container/restart")
async def restart_peertube(user=Depends(require_jwt)):
    """Restart PeerTube container."""
    await stop_peertube(user)
    await asyncio.sleep(3)
    return await start_peertube(user)


@router.post("/container/uninstall")
async def uninstall_peertube(user=Depends(require_jwt)):
    """Uninstall PeerTube container (data preserved)."""
    rt = detect_runtime()
    if not rt:
        return {"success": False, "error": "No container runtime"}

    log.info(f"Uninstalling PeerTube by {user.get('sub', 'unknown')}")

    try:
        subprocess.run([rt, "stop", CONTAINER_NAME], capture_output=True, timeout=30)
        subprocess.run([rt, "rm", "-f", CONTAINER_NAME], capture_output=True, timeout=10)
        return {"success": True, "message": "Container removed, data preserved"}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ============================================================================
# Logs
# ============================================================================

@router.get("/logs")
async def get_logs(lines: int = 100, user=Depends(require_jwt)):
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
# Configuration
# ============================================================================

@router.get("/config")
async def get_peertube_config(user=Depends(require_jwt)):
    """Get PeerTube configuration."""
    return get_config()


@router.post("/config")
async def set_peertube_config(config: PeerTubeConfig, user=Depends(require_jwt)):
    """Update PeerTube configuration."""
    cfg = get_config()
    cfg.update(config.dict())
    save_config(cfg)
    log.info(f"Config updated by {user.get('sub', 'unknown')}")
    return {"success": True}


app.include_router(router)
