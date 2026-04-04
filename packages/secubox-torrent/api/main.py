"""secubox-torrent — FastAPI application for BitTorrent client management.

Provides Transmission/qBittorrent Docker container management with
torrent lifecycle, RSS feeds, and speed limiting.

SecuBox-Deb :: secubox-torrent
CyberMind — https://cybermind.fr
Author: Gerald Kerma <devel@cybermind.fr>
License: Proprietary / ANSSI CSPN candidate
"""
import asyncio
import json
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any

from fastapi import FastAPI, APIRouter, Depends, HTTPException, UploadFile, File, Form
from pydantic import BaseModel

from secubox_core.auth import router as auth_router, require_jwt
from secubox_core.logger import get_logger

app = FastAPI(title="secubox-torrent", version="1.0.0", root_path="/api/v1/torrent")
app.include_router(auth_router, prefix="/auth")
router = APIRouter()
log = get_logger("torrent")

# Configuration
CONFIG_FILE = Path("/etc/secubox/torrent.toml")
CONTAINER_NAME = "secbx-torrent"
CACHE_DIR = Path("/var/cache/secubox/torrent")
RSS_FILE = Path("/etc/secubox/torrent-rss.json")
CATEGORIES_FILE = Path("/etc/secubox/torrent-categories.json")

DEFAULT_CONFIG = {
    "enabled": False,
    "client": "transmission",  # transmission or qbittorrent
    "image": "linuxserver/transmission:latest",
    "port": 9091,
    "peer_port": 51413,
    "data_path": "/srv/torrent",
    "download_dir": "/srv/torrent/downloads",
    "watch_dir": "/srv/torrent/watch",
    "timezone": "Europe/Paris",
    "domain": "torrent.secubox.local",
    "haproxy": False,
    "auth_enabled": True,
    "username": "admin",
    "password_hash": "",
    # Speed limits (KB/s, 0 = unlimited)
    "download_limit": 0,
    "upload_limit": 0,
    "alt_download_limit": 1000,
    "alt_upload_limit": 500,
    "alt_speed_enabled": False,
    # Schedule (24h format)
    "schedule_enabled": False,
    "schedule_start": "08:00",
    "schedule_end": "23:00",
    # Seeding
    "seed_ratio_limit": 2.0,
    "seed_ratio_enabled": True,
}


# ============================================================================
# Models
# ============================================================================

class TorrentConfig(BaseModel):
    enabled: bool = False
    client: str = "transmission"
    image: str = "linuxserver/transmission:latest"
    port: int = 9091
    peer_port: int = 51413
    data_path: str = "/srv/torrent"
    download_dir: str = "/srv/torrent/downloads"
    watch_dir: str = "/srv/torrent/watch"
    timezone: str = "Europe/Paris"
    domain: str = "torrent.secubox.local"
    haproxy: bool = False
    download_limit: int = 0
    upload_limit: int = 0
    alt_download_limit: int = 1000
    alt_upload_limit: int = 500
    alt_speed_enabled: bool = False
    schedule_enabled: bool = False
    schedule_start: str = "08:00"
    schedule_end: str = "23:00"
    seed_ratio_limit: float = 2.0
    seed_ratio_enabled: bool = True


class AddTorrentRequest(BaseModel):
    magnet: Optional[str] = None
    url: Optional[str] = None
    paused: bool = False
    download_dir: Optional[str] = None
    category: Optional[str] = None


class RSSFeed(BaseModel):
    name: str
    url: str
    category: Optional[str] = None
    auto_download: bool = False
    filter_pattern: Optional[str] = None


class Category(BaseModel):
    name: str
    save_path: Optional[str] = None


# ============================================================================
# Helpers
# ============================================================================

def get_config() -> dict:
    """Load torrent configuration."""
    if CONFIG_FILE.exists():
        try:
            import tomllib
            return tomllib.loads(CONFIG_FILE.read_text())
        except Exception:
            pass
    return DEFAULT_CONFIG.copy()


def save_config(config: dict):
    """Save torrent configuration."""
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    lines = ["# Torrent client configuration"]
    for k, v in config.items():
        if isinstance(v, bool):
            lines.append(f"{k} = {str(v).lower()}")
        elif isinstance(v, (int, float)):
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
    """Get torrent container status."""
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
    """Check if container is running."""
    return get_container_status()["status"] == "running"


def get_rss_feeds() -> List[dict]:
    """Get RSS feed subscriptions."""
    if RSS_FILE.exists():
        try:
            return json.loads(RSS_FILE.read_text())
        except Exception:
            pass
    return []


def save_rss_feeds(feeds: List[dict]):
    """Save RSS feeds."""
    RSS_FILE.parent.mkdir(parents=True, exist_ok=True)
    RSS_FILE.write_text(json.dumps(feeds, indent=2))


def get_categories() -> List[dict]:
    """Get torrent categories."""
    if CATEGORIES_FILE.exists():
        try:
            return json.loads(CATEGORIES_FILE.read_text())
        except Exception:
            pass
    # Default categories
    return [
        {"id": "movies", "name": "Movies", "save_path": "/downloads/movies"},
        {"id": "tv", "name": "TV Shows", "save_path": "/downloads/tv"},
        {"id": "music", "name": "Music", "save_path": "/downloads/music"},
        {"id": "software", "name": "Software", "save_path": "/downloads/software"},
    ]


def save_categories(categories: List[dict]):
    """Save categories."""
    CATEGORIES_FILE.parent.mkdir(parents=True, exist_ok=True)
    CATEGORIES_FILE.write_text(json.dumps(categories, indent=2))


def get_transmission_rpc_url() -> str:
    """Get Transmission RPC URL."""
    cfg = get_config()
    return f"http://127.0.0.1:{cfg.get('port', 9091)}/transmission/rpc"


def transmission_rpc(method: str, arguments: dict = None) -> dict:
    """Call Transmission RPC API."""
    import urllib.request
    import urllib.error

    cfg = get_config()
    url = get_transmission_rpc_url()
    session_id = ""

    payload = {"method": method}
    if arguments:
        payload["arguments"] = arguments

    headers = {
        "Content-Type": "application/json",
        "X-Transmission-Session-Id": session_id,
    }

    try:
        # First request to get session ID
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode(),
            headers=headers,
            method="POST"
        )
        urllib.request.urlopen(req, timeout=5)
    except urllib.error.HTTPError as e:
        if e.code == 409:
            # Get session ID from response
            session_id = e.headers.get("X-Transmission-Session-Id", "")
            headers["X-Transmission-Session-Id"] = session_id
        else:
            raise

    # Retry with session ID
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers=headers,
        method="POST"
    )
    response = urllib.request.urlopen(req, timeout=10)
    return json.loads(response.read().decode())


# ============================================================================
# Cache for stats
# ============================================================================

_stats_cache: dict = {}


async def refresh_stats_cache():
    """Background task to refresh statistics cache."""
    global _stats_cache
    while True:
        try:
            if is_running():
                # Get session stats from Transmission
                try:
                    result = transmission_rpc("session-stats")
                    if result.get("result") == "success":
                        args = result.get("arguments", {})
                        _stats_cache = {
                            "download_speed": args.get("downloadSpeed", 0),
                            "upload_speed": args.get("uploadSpeed", 0),
                            "active_torrents": args.get("activeTorrentCount", 0),
                            "paused_torrents": args.get("pausedTorrentCount", 0),
                            "total_downloaded": args.get("cumulative-stats", {}).get("downloadedBytes", 0),
                            "total_uploaded": args.get("cumulative-stats", {}).get("uploadedBytes", 0),
                            "updated": datetime.now().isoformat(),
                        }
                except Exception as e:
                    log.debug(f"Stats cache refresh failed: {e}")
            else:
                _stats_cache = {}

            # Cache to file
            CACHE_DIR.mkdir(parents=True, exist_ok=True)
            (CACHE_DIR / "stats.json").write_text(json.dumps(_stats_cache))
        except Exception as e:
            log.error(f"Stats cache error: {e}")

        await asyncio.sleep(10)


@app.on_event("startup")
async def startup():
    asyncio.create_task(refresh_stats_cache())


# ============================================================================
# Public Endpoints
# ============================================================================

@router.get("/health")
async def health():
    """Health check."""
    return {"status": "ok", "module": "torrent"}


@router.get("/status")
async def status():
    """Get torrent service status."""
    cfg = get_config()
    rt = detect_runtime()
    container = get_container_status()
    rss_feeds = get_rss_feeds()
    categories = get_categories()

    # Disk usage
    disk_usage = ""
    data_path = Path(cfg.get("data_path", "/srv/torrent"))
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
        "client": cfg.get("client", "transmission"),
        "image": cfg.get("image", "linuxserver/transmission:latest"),
        "port": cfg.get("port", 9091),
        "peer_port": cfg.get("peer_port", 51413),
        "data_path": cfg.get("data_path", "/srv/torrent"),
        "download_dir": cfg.get("download_dir", "/srv/torrent/downloads"),
        "timezone": cfg.get("timezone", "Europe/Paris"),
        "domain": cfg.get("domain", "torrent.secubox.local"),
        "haproxy": cfg.get("haproxy", False),
        "docker_available": rt is not None,
        "runtime": rt or "none",
        "container_status": container["status"],
        "container_uptime": container["uptime"],
        "disk_usage": disk_usage,
        "rss_count": len(rss_feeds),
        "category_count": len(categories),
        "download_limit": cfg.get("download_limit", 0),
        "upload_limit": cfg.get("upload_limit", 0),
        "alt_speed_enabled": cfg.get("alt_speed_enabled", False),
    }


# ============================================================================
# Protected Endpoints — Configuration
# ============================================================================

@router.get("/config")
async def get_torrent_config(user=Depends(require_jwt)):
    """Get torrent configuration."""
    return get_config()


@router.post("/config")
async def set_torrent_config(config: TorrentConfig, user=Depends(require_jwt)):
    """Update torrent configuration."""
    cfg = get_config()
    cfg.update(config.dict())
    save_config(cfg)
    log.info(f"Config updated by {user.get('sub', 'unknown')}")
    return {"success": True}


# ============================================================================
# Protected Endpoints — Torrents
# ============================================================================

@router.get("/torrents")
async def list_torrents(user=Depends(require_jwt)):
    """List all torrents."""
    if not is_running():
        return {"torrents": [], "error": "Service not running"}

    try:
        result = transmission_rpc("torrent-get", {
            "fields": [
                "id", "name", "status", "percentDone", "totalSize",
                "downloadedEver", "uploadedEver", "rateDownload", "rateUpload",
                "eta", "addedDate", "doneDate", "error", "errorString",
                "trackerStats", "labels", "downloadDir", "isFinished",
                "peersConnected", "seedRatioLimit", "uploadRatio"
            ]
        })

        if result.get("result") != "success":
            return {"torrents": [], "error": result.get("result")}

        torrents = []
        for t in result.get("arguments", {}).get("torrents", []):
            status_map = {
                0: "stopped",
                1: "queued_verify",
                2: "verifying",
                3: "queued_download",
                4: "downloading",
                5: "queued_seed",
                6: "seeding",
            }
            torrents.append({
                "id": t["id"],
                "name": t["name"],
                "status": status_map.get(t["status"], "unknown"),
                "progress": round(t["percentDone"] * 100, 1),
                "size": t["totalSize"],
                "downloaded": t["downloadedEver"],
                "uploaded": t["uploadedEver"],
                "download_speed": t["rateDownload"],
                "upload_speed": t["rateUpload"],
                "eta": t["eta"] if t["eta"] >= 0 else None,
                "added": datetime.fromtimestamp(t["addedDate"]).isoformat() if t["addedDate"] else None,
                "completed": datetime.fromtimestamp(t["doneDate"]).isoformat() if t["doneDate"] else None,
                "error": t["errorString"] if t["error"] else None,
                "peers": t["peersConnected"],
                "ratio": round(t["uploadRatio"], 2),
                "category": t.get("labels", [""])[0] if t.get("labels") else "",
                "download_dir": t["downloadDir"],
            })

        return {"torrents": torrents}

    except Exception as e:
        log.error(f"Failed to list torrents: {e}")
        return {"torrents": [], "error": str(e)}


@router.post("/torrent/add")
async def add_torrent(
    request: AddTorrentRequest = None,
    torrent_file: UploadFile = File(None),
    magnet: str = Form(None),
    user=Depends(require_jwt)
):
    """Add a torrent from magnet link, URL, or file."""
    if not is_running():
        raise HTTPException(503, "Service not running")

    try:
        args = {"paused": False}

        # Handle different input types
        if torrent_file:
            # Upload torrent file
            import base64
            content = await torrent_file.read()
            args["metainfo"] = base64.b64encode(content).decode()
        elif magnet:
            args["filename"] = magnet
        elif request:
            if request.magnet:
                args["filename"] = request.magnet
            elif request.url:
                args["filename"] = request.url
            args["paused"] = request.paused
            if request.download_dir:
                args["download-dir"] = request.download_dir
        else:
            raise HTTPException(400, "No torrent source provided")

        result = transmission_rpc("torrent-add", args)

        if result.get("result") == "success":
            torrent_info = result.get("arguments", {})
            added = torrent_info.get("torrent-added") or torrent_info.get("torrent-duplicate")
            log.info(f"Torrent added by {user.get('sub', 'unknown')}: {added.get('name', 'unknown')}")
            return {
                "success": True,
                "torrent": {
                    "id": added.get("id"),
                    "name": added.get("name"),
                    "hash": added.get("hashString"),
                }
            }
        else:
            return {"success": False, "error": result.get("result")}

    except HTTPException:
        raise
    except Exception as e:
        log.error(f"Add torrent failed: {e}")
        return {"success": False, "error": str(e)}


@router.delete("/torrent/{torrent_id}")
async def remove_torrent(torrent_id: int, delete_data: bool = False, user=Depends(require_jwt)):
    """Remove a torrent."""
    if not is_running():
        raise HTTPException(503, "Service not running")

    try:
        result = transmission_rpc("torrent-remove", {
            "ids": [torrent_id],
            "delete-local-data": delete_data,
        })

        if result.get("result") == "success":
            log.info(f"Torrent {torrent_id} removed by {user.get('sub', 'unknown')} (delete_data={delete_data})")
            return {"success": True}
        else:
            return {"success": False, "error": result.get("result")}

    except Exception as e:
        log.error(f"Remove torrent failed: {e}")
        return {"success": False, "error": str(e)}


@router.post("/torrent/{torrent_id}/pause")
async def pause_torrent(torrent_id: int, user=Depends(require_jwt)):
    """Pause a torrent."""
    if not is_running():
        raise HTTPException(503, "Service not running")

    try:
        result = transmission_rpc("torrent-stop", {"ids": [torrent_id]})
        if result.get("result") == "success":
            log.info(f"Torrent {torrent_id} paused by {user.get('sub', 'unknown')}")
            return {"success": True}
        return {"success": False, "error": result.get("result")}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.post("/torrent/{torrent_id}/resume")
async def resume_torrent(torrent_id: int, user=Depends(require_jwt)):
    """Resume a torrent."""
    if not is_running():
        raise HTTPException(503, "Service not running")

    try:
        result = transmission_rpc("torrent-start", {"ids": [torrent_id]})
        if result.get("result") == "success":
            log.info(f"Torrent {torrent_id} resumed by {user.get('sub', 'unknown')}")
            return {"success": True}
        return {"success": False, "error": result.get("result")}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.get("/torrent/{torrent_id}/files")
async def get_torrent_files(torrent_id: int, user=Depends(require_jwt)):
    """Get files in a torrent."""
    if not is_running():
        raise HTTPException(503, "Service not running")

    try:
        result = transmission_rpc("torrent-get", {
            "ids": [torrent_id],
            "fields": ["files", "fileStats"]
        })

        if result.get("result") != "success":
            return {"files": [], "error": result.get("result")}

        torrents = result.get("arguments", {}).get("torrents", [])
        if not torrents:
            return {"files": [], "error": "Torrent not found"}

        t = torrents[0]
        files = []
        for i, f in enumerate(t.get("files", [])):
            stats = t.get("fileStats", [])[i] if i < len(t.get("fileStats", [])) else {}
            files.append({
                "name": f["name"],
                "size": f["length"],
                "downloaded": f["bytesCompleted"],
                "progress": round(f["bytesCompleted"] / f["length"] * 100, 1) if f["length"] > 0 else 0,
                "wanted": stats.get("wanted", True),
                "priority": stats.get("priority", 0),
            })

        return {"files": files}

    except Exception as e:
        return {"files": [], "error": str(e)}


# ============================================================================
# Statistics
# ============================================================================

@router.get("/stats")
async def get_stats(user=Depends(require_jwt)):
    """Get download/upload statistics."""
    if _stats_cache:
        return _stats_cache

    # Try loading from cache file
    cache_file = CACHE_DIR / "stats.json"
    if cache_file.exists():
        try:
            return json.loads(cache_file.read_text())
        except Exception:
            pass

    return {
        "download_speed": 0,
        "upload_speed": 0,
        "active_torrents": 0,
        "paused_torrents": 0,
        "total_downloaded": 0,
        "total_uploaded": 0,
    }


# ============================================================================
# RSS Feeds
# ============================================================================

@router.get("/rss/feeds")
async def list_rss_feeds(user=Depends(require_jwt)):
    """List RSS feed subscriptions."""
    return {"feeds": get_rss_feeds()}


@router.post("/rss/add")
async def add_rss_feed(feed: RSSFeed, user=Depends(require_jwt)):
    """Add an RSS feed subscription."""
    feeds = get_rss_feeds()

    # Check for duplicate
    for f in feeds:
        if f.get("url") == feed.url:
            return {"success": False, "error": "Feed URL already exists"}

    feeds.append({
        "id": f"rss_{len(feeds)+1}_{int(datetime.now().timestamp())}",
        "name": feed.name,
        "url": feed.url,
        "category": feed.category,
        "auto_download": feed.auto_download,
        "filter_pattern": feed.filter_pattern,
        "added": datetime.now().isoformat(),
    })
    save_rss_feeds(feeds)

    log.info(f"RSS feed added: {feed.name} by {user.get('sub', 'unknown')}")
    return {"success": True}


@router.delete("/rss/{feed_id}")
async def remove_rss_feed(feed_id: str, user=Depends(require_jwt)):
    """Remove an RSS feed."""
    feeds = get_rss_feeds()
    new_feeds = [f for f in feeds if f.get("id") != feed_id]

    if len(new_feeds) == len(feeds):
        return {"success": False, "error": "Feed not found"}

    save_rss_feeds(new_feeds)
    log.info(f"RSS feed removed: {feed_id} by {user.get('sub', 'unknown')}")
    return {"success": True}


# ============================================================================
# Categories
# ============================================================================

@router.get("/categories")
async def list_categories(user=Depends(require_jwt)):
    """List torrent categories."""
    return {"categories": get_categories()}


@router.post("/categories")
async def add_category(category: Category, user=Depends(require_jwt)):
    """Add a category."""
    categories = get_categories()

    for c in categories:
        if c.get("name").lower() == category.name.lower():
            return {"success": False, "error": "Category already exists"}

    categories.append({
        "id": category.name.lower().replace(" ", "_"),
        "name": category.name,
        "save_path": category.save_path or f"/downloads/{category.name.lower()}",
    })
    save_categories(categories)

    log.info(f"Category added: {category.name} by {user.get('sub', 'unknown')}")
    return {"success": True}


@router.delete("/categories/{category_id}")
async def remove_category(category_id: str, user=Depends(require_jwt)):
    """Remove a category."""
    categories = get_categories()
    new_cats = [c for c in categories if c.get("id") != category_id]

    if len(new_cats) == len(categories):
        return {"success": False, "error": "Category not found"}

    save_categories(new_cats)
    log.info(f"Category removed: {category_id} by {user.get('sub', 'unknown')}")
    return {"success": True}


# ============================================================================
# Container Management
# ============================================================================

@router.get("/container/status")
async def container_status(user=Depends(require_jwt)):
    """Get container status."""
    return get_container_status()


@router.post("/container/install")
async def install_container(user=Depends(require_jwt)):
    """Install torrent container."""
    rt = detect_runtime()
    if not rt:
        return {"success": False, "error": "No container runtime (docker/podman) found"}

    cfg = get_config()
    data_path = Path(cfg.get("data_path", "/srv/torrent"))

    # Create directories
    (data_path / "config").mkdir(parents=True, exist_ok=True)
    (data_path / "downloads").mkdir(parents=True, exist_ok=True)
    (data_path / "watch").mkdir(parents=True, exist_ok=True)

    image = cfg.get("image", "linuxserver/transmission:latest")
    log.info(f"Installing torrent client ({image}) by {user.get('sub', 'unknown')}")

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


@router.post("/container/start")
async def start_container(user=Depends(require_jwt)):
    """Start torrent container."""
    if is_running():
        return {"success": False, "error": "Already running"}

    rt = detect_runtime()
    if not rt:
        return {"success": False, "error": "No container runtime"}

    cfg = get_config()
    data_path = Path(cfg.get("data_path", "/srv/torrent"))
    port = cfg.get("port", 9091)
    peer_port = cfg.get("peer_port", 51413)
    image = cfg.get("image", "linuxserver/transmission:latest")
    tz = cfg.get("timezone", "Europe/Paris")

    # Ensure directories exist
    (data_path / "config").mkdir(parents=True, exist_ok=True)
    (data_path / "downloads").mkdir(parents=True, exist_ok=True)
    (data_path / "watch").mkdir(parents=True, exist_ok=True)

    cmd = [
        rt, "run", "-d",
        "--name", CONTAINER_NAME,
        "-v", f"{data_path}/config:/config",
        "-v", f"{data_path}/downloads:/downloads",
        "-v", f"{data_path}/watch:/watch",
        "-e", f"TZ={tz}",
        "-e", "PUID=1000",
        "-e", "PGID=1000",
        "-p", f"127.0.0.1:{port}:9091",
        "-p", f"{peer_port}:51413",
        "-p", f"{peer_port}:51413/udp",
        "--restart", "unless-stopped",
    ]

    cmd.append(image)

    log.info(f"Starting torrent client by {user.get('sub', 'unknown')}")

    try:
        subprocess.run([rt, "rm", "-f", CONTAINER_NAME], capture_output=True, timeout=10)
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        await asyncio.sleep(3)

        if is_running():
            return {"success": True}
        else:
            return {"success": False, "error": result.stderr.strip() or "Failed to start"}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.post("/container/stop")
async def stop_container(user=Depends(require_jwt)):
    """Stop torrent container."""
    rt = detect_runtime()
    if not rt:
        return {"success": False, "error": "No container runtime"}

    log.info(f"Stopping torrent client by {user.get('sub', 'unknown')}")

    try:
        subprocess.run([rt, "stop", CONTAINER_NAME], capture_output=True, timeout=30)
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.post("/container/restart")
async def restart_container(user=Depends(require_jwt)):
    """Restart torrent container."""
    await stop_container(user)
    await asyncio.sleep(2)
    return await start_container(user)


@router.post("/container/uninstall")
async def uninstall_container(user=Depends(require_jwt)):
    """Uninstall torrent container."""
    rt = detect_runtime()
    if not rt:
        return {"success": False, "error": "No container runtime"}

    log.info(f"Uninstalling torrent client by {user.get('sub', 'unknown')}")

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


app.include_router(router)
