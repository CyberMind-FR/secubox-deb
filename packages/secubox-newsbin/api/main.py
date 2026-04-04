"""secubox-newsbin -- FastAPI application for Usenet downloader management.

Provides SABnzbd Docker container management for Usenet/NZB downloads.
"""
import asyncio
import shutil
import subprocess
import json
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any

from fastapi import FastAPI, APIRouter, Depends, HTTPException, UploadFile, File, Form
from pydantic import BaseModel

from secubox_core.auth import router as auth_router, require_jwt
from secubox_core.logger import get_logger

app = FastAPI(title="secubox-newsbin", version="1.0.0", root_path="/api/v1/newsbin")
app.include_router(auth_router, prefix="/auth")
router = APIRouter()
log = get_logger("newsbin")

# Configuration
CONFIG_FILE = Path("/etc/secubox/newsbin.toml")
CONTAINER_NAME = "secbx-sabnzbd"
DEFAULT_CONFIG = {
    "enabled": False,
    "image": "lscr.io/linuxserver/sabnzbd:latest",
    "port": 8090,
    "data_path": "/srv/newsbin",
    "downloads_path": "/srv/downloads/usenet",
    "timezone": "Europe/Paris",
    "domain": "newsbin.secubox.local",
    "haproxy": False,
}


# ============================================================================
# Models
# ============================================================================

class NewsbinConfig(BaseModel):
    enabled: bool = False
    image: str = "lscr.io/linuxserver/sabnzbd:latest"
    port: int = 8090
    data_path: str = "/srv/newsbin"
    downloads_path: str = "/srv/downloads/usenet"
    timezone: str = "Europe/Paris"
    domain: str = "newsbin.secubox.local"
    haproxy: bool = False


class ServerConfig(BaseModel):
    name: str
    host: str
    port: int = 563
    ssl: bool = True
    username: str = ""
    password: str = ""
    connections: int = 10
    priority: int = 0
    enabled: bool = True


class CategoryConfig(BaseModel):
    name: str
    directory: str = ""
    priority: int = 0
    script: str = ""


class AddNzbRequest(BaseModel):
    url: Optional[str] = None
    category: str = "default"
    priority: int = 0
    name: Optional[str] = None


class RestoreRequest(BaseModel):
    path: str


# ============================================================================
# Helpers
# ============================================================================

def get_config() -> dict:
    """Load newsbin configuration."""
    if CONFIG_FILE.exists():
        try:
            import tomllib
            return tomllib.loads(CONFIG_FILE.read_text())
        except Exception:
            pass
    return DEFAULT_CONFIG.copy()


def save_config(config: dict):
    """Save newsbin configuration."""
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    lines = ["# Newsbin (SABnzbd) configuration"]
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
    """Get SABnzbd container status."""
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
    """Check if SABnzbd container is running."""
    return get_container_status()["status"] == "running"


def sabnzbd_api(endpoint: str, params: dict = None) -> dict:
    """Call SABnzbd API."""
    cfg = get_config()
    port = cfg.get("port", 8090)
    api_key = get_api_key()

    if not api_key:
        return {"error": "No API key configured"}

    url = f"http://127.0.0.1:{port}/sabnzbd/api"
    query_params = {"apikey": api_key, "output": "json"}
    if params:
        query_params.update(params)

    import urllib.request
    import urllib.parse

    full_url = f"{url}?{urllib.parse.urlencode(query_params)}"

    try:
        with urllib.request.urlopen(full_url, timeout=10) as resp:
            return json.loads(resp.read().decode())
    except Exception as e:
        return {"error": str(e)}


def get_api_key() -> Optional[str]:
    """Get SABnzbd API key from config file."""
    cfg = get_config()
    data_path = Path(cfg.get("data_path", "/srv/newsbin"))
    ini_file = data_path / "config" / "sabnzbd.ini"

    if ini_file.exists():
        try:
            content = ini_file.read_text()
            for line in content.split("\n"):
                if line.strip().startswith("api_key"):
                    parts = line.split("=")
                    if len(parts) >= 2:
                        return parts[1].strip()
        except Exception:
            pass
    return None


def get_servers_config() -> List[dict]:
    """Get configured Usenet servers."""
    servers_file = Path("/etc/secubox/newsbin-servers.json")
    if servers_file.exists():
        try:
            return json.loads(servers_file.read_text())
        except Exception:
            pass
    return []


def save_servers_config(servers: List[dict]):
    """Save Usenet servers configuration."""
    servers_file = Path("/etc/secubox/newsbin-servers.json")
    servers_file.parent.mkdir(parents=True, exist_ok=True)
    servers_file.write_text(json.dumps(servers, indent=2))


def get_categories_config() -> List[dict]:
    """Get configured categories."""
    cats_file = Path("/etc/secubox/newsbin-categories.json")
    if cats_file.exists():
        try:
            return json.loads(cats_file.read_text())
        except Exception:
            pass
    return [{"name": "default", "directory": "", "priority": 0, "script": ""}]


def save_categories_config(categories: List[dict]):
    """Save categories configuration."""
    cats_file = Path("/etc/secubox/newsbin-categories.json")
    cats_file.parent.mkdir(parents=True, exist_ok=True)
    cats_file.write_text(json.dumps(categories, indent=2))


# ============================================================================
# Public Endpoints
# ============================================================================

@router.get("/health")
async def health():
    """Health check."""
    return {"status": "ok", "module": "newsbin"}


@router.get("/status")
async def status():
    """Get Newsbin service status."""
    cfg = get_config()
    rt = detect_runtime()
    container = get_container_status()
    api_key = get_api_key()

    # Disk usage
    disk_usage = ""
    data_path = Path(cfg.get("data_path", "/srv/newsbin"))
    if data_path.exists():
        try:
            result = subprocess.run(
                ["du", "-sh", str(data_path)],
                capture_output=True, text=True, timeout=10
            )
            disk_usage = result.stdout.split()[0] if result.stdout else ""
        except Exception:
            pass

    # Queue stats (if running)
    queue_info = {}
    if container["status"] == "running" and api_key:
        resp = sabnzbd_api("queue", {"mode": "queue"})
        if "queue" in resp:
            q = resp["queue"]
            queue_info = {
                "speed": q.get("speed", "0"),
                "size_left": q.get("sizeleft", "0"),
                "slots": len(q.get("slots", [])),
                "paused": q.get("paused", False),
            }

    return {
        "enabled": cfg.get("enabled", False),
        "image": cfg.get("image", "lscr.io/linuxserver/sabnzbd:latest"),
        "port": cfg.get("port", 8090),
        "data_path": cfg.get("data_path", "/srv/newsbin"),
        "downloads_path": cfg.get("downloads_path", "/srv/downloads/usenet"),
        "timezone": cfg.get("timezone", "Europe/Paris"),
        "domain": cfg.get("domain", "newsbin.secubox.local"),
        "haproxy": cfg.get("haproxy", False),
        "docker_available": rt is not None,
        "runtime": rt or "none",
        "container_status": container["status"],
        "container_uptime": container["uptime"],
        "disk_usage": disk_usage,
        "api_key_configured": api_key is not None,
        "queue": queue_info,
    }


# ============================================================================
# Protected Endpoints
# ============================================================================

@router.get("/config")
async def get_newsbin_config(user=Depends(require_jwt)):
    """Get Newsbin configuration."""
    return get_config()


@router.post("/config")
async def set_newsbin_config(config: NewsbinConfig, user=Depends(require_jwt)):
    """Update Newsbin configuration."""
    cfg = get_config()
    cfg.update(config.dict())
    save_config(cfg)
    log.info(f"Config updated by {user.get('sub', 'unknown')}")
    return {"success": True}


# ============================================================================
# Queue Management
# ============================================================================

@router.get("/queue")
async def get_queue(user=Depends(require_jwt)):
    """Get download queue."""
    if not is_running():
        return {"queue": [], "error": "Not running"}

    resp = sabnzbd_api("queue", {"mode": "queue"})
    if "queue" in resp:
        q = resp["queue"]
        return {
            "speed": q.get("speed", "0"),
            "speed_limit": q.get("speedlimit", ""),
            "size_left": q.get("sizeleft", "0"),
            "time_left": q.get("timeleft", "0:00:00"),
            "paused": q.get("paused", False),
            "slots": q.get("slots", []),
            "total": q.get("noofslots", 0),
        }
    return {"queue": [], "error": resp.get("error", "API error")}


@router.post("/nzb/add")
async def add_nzb(req: AddNzbRequest, user=Depends(require_jwt)):
    """Add NZB from URL."""
    if not is_running():
        raise HTTPException(status_code=400, detail="Not running")

    if not req.url:
        raise HTTPException(status_code=400, detail="URL required")

    params = {
        "mode": "addurl",
        "name": req.url,
        "cat": req.category,
        "priority": req.priority,
    }
    if req.name:
        params["nzbname"] = req.name

    resp = sabnzbd_api("addurl", params)
    log.info(f"NZB added by {user.get('sub', 'unknown')}: {req.url}")
    return {"success": resp.get("status", False), "nzo_ids": resp.get("nzo_ids", [])}


@router.post("/nzb/upload")
async def upload_nzb(
    file: UploadFile = File(...),
    category: str = Form("default"),
    priority: int = Form(0),
    user=Depends(require_jwt)
):
    """Upload NZB file."""
    if not is_running():
        raise HTTPException(status_code=400, detail="Not running")

    cfg = get_config()
    port = cfg.get("port", 8090)
    api_key = get_api_key()

    if not api_key:
        raise HTTPException(status_code=400, detail="No API key configured")

    # Save temporarily and use curl to upload
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".nzb", delete=False) as tmp:
        content = await file.read()
        tmp.write(content)
        tmp_path = tmp.name

    try:
        result = subprocess.run([
            "curl", "-s", "-X", "POST",
            f"http://127.0.0.1:{port}/sabnzbd/api",
            "-F", f"apikey={api_key}",
            "-F", "mode=addfile",
            "-F", f"cat={category}",
            "-F", f"priority={priority}",
            "-F", f"nzbfile=@{tmp_path}",
            "-F", "output=json"
        ], capture_output=True, text=True, timeout=30)

        resp = json.loads(result.stdout)
        log.info(f"NZB file uploaded by {user.get('sub', 'unknown')}: {file.filename}")
        return {"success": resp.get("status", False), "nzo_ids": resp.get("nzo_ids", [])}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        Path(tmp_path).unlink(missing_ok=True)


@router.delete("/queue/{nzo_id}")
async def remove_from_queue(nzo_id: str, user=Depends(require_jwt)):
    """Remove item from queue."""
    if not is_running():
        raise HTTPException(status_code=400, detail="Not running")

    resp = sabnzbd_api("queue", {"mode": "queue", "name": "delete", "value": nzo_id})
    log.info(f"Queue item {nzo_id} removed by {user.get('sub', 'unknown')}")
    return {"success": True}


@router.post("/queue/{nzo_id}/pause")
async def pause_item(nzo_id: str, user=Depends(require_jwt)):
    """Pause queue item."""
    if not is_running():
        raise HTTPException(status_code=400, detail="Not running")

    resp = sabnzbd_api("queue", {"mode": "queue", "name": "pause", "value": nzo_id})
    return {"success": True}


@router.post("/queue/{nzo_id}/resume")
async def resume_item(nzo_id: str, user=Depends(require_jwt)):
    """Resume queue item."""
    if not is_running():
        raise HTTPException(status_code=400, detail="Not running")

    resp = sabnzbd_api("queue", {"mode": "queue", "name": "resume", "value": nzo_id})
    return {"success": True}


@router.post("/queue/pause")
async def pause_queue(user=Depends(require_jwt)):
    """Pause entire queue."""
    if not is_running():
        raise HTTPException(status_code=400, detail="Not running")

    resp = sabnzbd_api("pause", {"mode": "pause"})
    return {"success": True}


@router.post("/queue/resume")
async def resume_queue(user=Depends(require_jwt)):
    """Resume entire queue."""
    if not is_running():
        raise HTTPException(status_code=400, detail="Not running")

    resp = sabnzbd_api("resume", {"mode": "resume"})
    return {"success": True}


# ============================================================================
# History
# ============================================================================

@router.get("/history")
async def get_history(limit: int = 50, user=Depends(require_jwt)):
    """Get download history."""
    if not is_running():
        return {"history": [], "error": "Not running"}

    resp = sabnzbd_api("history", {"mode": "history", "limit": limit})
    if "history" in resp:
        h = resp["history"]
        return {
            "total": h.get("noofslots", 0),
            "slots": h.get("slots", []),
        }
    return {"history": [], "error": resp.get("error", "API error")}


@router.delete("/history/{nzo_id}")
async def delete_history_item(nzo_id: str, user=Depends(require_jwt)):
    """Delete history item."""
    if not is_running():
        raise HTTPException(status_code=400, detail="Not running")

    resp = sabnzbd_api("history", {"mode": "history", "name": "delete", "value": nzo_id})
    return {"success": True}


@router.post("/history/clear")
async def clear_history(user=Depends(require_jwt)):
    """Clear download history."""
    if not is_running():
        raise HTTPException(status_code=400, detail="Not running")

    resp = sabnzbd_api("history", {"mode": "history", "name": "delete", "value": "all"})
    log.info(f"History cleared by {user.get('sub', 'unknown')}")
    return {"success": True}


# ============================================================================
# Categories
# ============================================================================

@router.get("/categories")
async def list_categories(user=Depends(require_jwt)):
    """List download categories."""
    return {"categories": get_categories_config()}


@router.post("/category")
async def add_category(cat: CategoryConfig, user=Depends(require_jwt)):
    """Add or update category."""
    cats = get_categories_config()

    # Update existing or add new
    found = False
    for c in cats:
        if c["name"] == cat.name:
            c.update(cat.dict())
            found = True
            break

    if not found:
        cats.append(cat.dict())

    save_categories_config(cats)
    log.info(f"Category {cat.name} saved by {user.get('sub', 'unknown')}")
    return {"success": True}


@router.delete("/category/{name}")
async def delete_category(name: str, user=Depends(require_jwt)):
    """Delete category."""
    if name == "default":
        raise HTTPException(status_code=400, detail="Cannot delete default category")

    cats = get_categories_config()
    cats = [c for c in cats if c["name"] != name]
    save_categories_config(cats)
    log.info(f"Category {name} deleted by {user.get('sub', 'unknown')}")
    return {"success": True}


# ============================================================================
# Usenet Servers
# ============================================================================

@router.get("/servers")
async def list_servers(user=Depends(require_jwt)):
    """List configured Usenet servers."""
    return {"servers": get_servers_config()}


@router.post("/server")
async def add_server(server: ServerConfig, user=Depends(require_jwt)):
    """Add or update Usenet server."""
    servers = get_servers_config()

    # Update existing or add new
    found = False
    for s in servers:
        if s["name"] == server.name:
            s.update(server.dict())
            found = True
            break

    if not found:
        servers.append(server.dict())

    save_servers_config(servers)
    log.info(f"Server {server.name} saved by {user.get('sub', 'unknown')}")
    return {"success": True}


@router.delete("/server/{name}")
async def delete_server(name: str, user=Depends(require_jwt)):
    """Delete Usenet server."""
    servers = get_servers_config()
    servers = [s for s in servers if s["name"] != name]
    save_servers_config(servers)
    log.info(f"Server {name} deleted by {user.get('sub', 'unknown')}")
    return {"success": True}


# ============================================================================
# Statistics
# ============================================================================

@router.get("/stats")
async def get_stats(user=Depends(require_jwt)):
    """Get download statistics."""
    if not is_running():
        return {"stats": {}, "error": "Not running"}

    resp = sabnzbd_api("stats", {"mode": "server_stats"})

    # Also get queue for current stats
    queue_resp = sabnzbd_api("queue", {"mode": "queue"})

    stats = {
        "servers": resp.get("servers", {}),
        "total": resp.get("total", 0),
        "day": resp.get("day", 0),
        "week": resp.get("week", 0),
        "month": resp.get("month", 0),
    }

    if "queue" in queue_resp:
        q = queue_resp["queue"]
        stats["current"] = {
            "speed": q.get("speed", "0"),
            "paused": q.get("paused", False),
            "queue_size": q.get("noofslots", 0),
            "eta": q.get("timeleft", "0:00:00"),
        }

    return {"stats": stats}


# ============================================================================
# Container Management
# ============================================================================

@router.get("/container/status")
async def get_container_status_endpoint(user=Depends(require_jwt)):
    """Get container status details."""
    rt = detect_runtime()
    status = get_container_status()

    return {
        "runtime": rt or "none",
        "container_name": CONTAINER_NAME,
        "status": status["status"],
        "uptime": status["uptime"],
    }


@router.post("/container/install")
async def install_container(user=Depends(require_jwt)):
    """Install SABnzbd container."""
    rt = detect_runtime()
    if not rt:
        return {"success": False, "error": "No container runtime (docker/podman) found"}

    cfg = get_config()
    data_path = Path(cfg.get("data_path", "/srv/newsbin"))
    downloads_path = Path(cfg.get("downloads_path", "/srv/downloads/usenet"))

    # Create directories
    (data_path / "config").mkdir(parents=True, exist_ok=True)
    downloads_path.mkdir(parents=True, exist_ok=True)
    (downloads_path / "complete").mkdir(parents=True, exist_ok=True)
    (downloads_path / "incomplete").mkdir(parents=True, exist_ok=True)

    # Pull image
    image = cfg.get("image", "lscr.io/linuxserver/sabnzbd:latest")
    log.info(f"Installing SABnzbd ({image}) by {user.get('sub', 'unknown')}")

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
    """Start SABnzbd container."""
    if is_running():
        return {"success": False, "error": "Already running"}

    rt = detect_runtime()
    if not rt:
        return {"success": False, "error": "No container runtime"}

    cfg = get_config()
    data_path = Path(cfg.get("data_path", "/srv/newsbin"))
    downloads_path = Path(cfg.get("downloads_path", "/srv/downloads/usenet"))
    port = cfg.get("port", 8090)
    image = cfg.get("image", "lscr.io/linuxserver/sabnzbd:latest")
    tz = cfg.get("timezone", "Europe/Paris")

    # Ensure directories exist
    (data_path / "config").mkdir(parents=True, exist_ok=True)
    downloads_path.mkdir(parents=True, exist_ok=True)

    # Build run command
    cmd = [
        rt, "run", "-d",
        "--name", CONTAINER_NAME,
        "-v", f"{data_path}/config:/config",
        "-v", f"{downloads_path}:/downloads",
        "-e", f"TZ={tz}",
        "-e", "PUID=1000",
        "-e", "PGID=1000",
        "-p", f"127.0.0.1:{port}:8080",
        "--restart", "unless-stopped",
        image
    ]

    log.info(f"Starting SABnzbd by {user.get('sub', 'unknown')}")

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


@router.post("/container/stop")
async def stop_container(user=Depends(require_jwt)):
    """Stop SABnzbd container."""
    rt = detect_runtime()
    if not rt:
        return {"success": False, "error": "No container runtime"}

    log.info(f"Stopping SABnzbd by {user.get('sub', 'unknown')}")

    try:
        subprocess.run([rt, "stop", CONTAINER_NAME], capture_output=True, timeout=30)
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.post("/container/restart")
async def restart_container(user=Depends(require_jwt)):
    """Restart SABnzbd container."""
    await stop_container(user)
    await asyncio.sleep(2)
    return await start_container(user)


@router.delete("/container")
async def uninstall_container(user=Depends(require_jwt)):
    """Uninstall SABnzbd container."""
    rt = detect_runtime()
    if not rt:
        return {"success": False, "error": "No container runtime"}

    log.info(f"Uninstalling SABnzbd by {user.get('sub', 'unknown')}")

    try:
        subprocess.run([rt, "stop", CONTAINER_NAME], capture_output=True, timeout=30)
        subprocess.run([rt, "rm", "-f", CONTAINER_NAME], capture_output=True, timeout=10)
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.post("/container/update")
async def update_container(user=Depends(require_jwt)):
    """Update SABnzbd to latest image."""
    cfg = get_config()
    rt = detect_runtime()
    if not rt:
        return {"success": False, "error": "No container runtime"}

    image = cfg.get("image", "lscr.io/linuxserver/sabnzbd:latest")
    log.info(f"Updating SABnzbd ({image}) by {user.get('sub', 'unknown')}")

    try:
        result = subprocess.run(
            [rt, "pull", image],
            capture_output=True, text=True, timeout=300
        )
        if result.returncode != 0:
            return {"success": False, "error": result.stderr.strip()}

        if is_running():
            await restart_container(user)

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
async def create_backup(user=Depends(require_jwt)):
    """Backup SABnzbd configuration."""
    cfg = get_config()
    data_path = Path(cfg.get("data_path", "/srv/newsbin"))
    config_path = data_path / "config"

    if not config_path.exists():
        return {"success": False, "error": "No config to backup"}

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup_file = f"/tmp/newsbin-backup-{timestamp}.tar.gz"

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
async def restore_backup(req: RestoreRequest, user=Depends(require_jwt)):
    """Restore SABnzbd configuration from backup."""
    if not Path(req.path).exists():
        return {"success": False, "error": "Backup file not found"}

    cfg = get_config()
    data_path = Path(cfg.get("data_path", "/srv/newsbin"))

    log.info(f"Restoring backup {req.path} by {user.get('sub', 'unknown')}")

    # Stop container first
    if is_running():
        await stop_container(user)
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


app.include_router(router)
