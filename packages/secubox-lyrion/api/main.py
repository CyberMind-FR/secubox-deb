"""secubox-lyrion — FastAPI application for Lyrion Music Server (LMS).

Ported from OpenWRT luci-app-lyrion RPCD backend.
Provides Lyrion container management and Squeezebox JSON-RPC API proxy.
"""
import asyncio
import shutil
import subprocess
from pathlib import Path
from typing import List, Optional, Dict, Any

from fastapi import FastAPI, APIRouter, Depends, HTTPException
from pydantic import BaseModel
import httpx

from secubox_core.auth import router as auth_router, require_jwt
from secubox_core.logger import get_logger

app = FastAPI(title="secubox-lyrion", version="1.0.0", root_path="/api/v1/lyrion")
app.include_router(auth_router, prefix="/auth")
router = APIRouter()
log = get_logger("lyrion")

# Configuration
CONFIG_FILE = Path("/etc/secubox/lyrion.toml")
DEFAULT_CONFIG = {
    "web_port": 9000,
    "cli_port": 9090,
    "data_path": "/srv/lyrion",
    "media_path": "/srv/media",
    "memory_limit": "512m",
}


# ============================================================================
# Models
# ============================================================================

class LyrionConfig(BaseModel):
    web_port: int = 9000
    cli_port: int = 9090
    data_path: str = "/srv/lyrion"
    media_path: str = "/srv/media"
    memory_limit: str = "512m"


class RescanRequest(BaseModel):
    mode: str = "full"  # full, playlists, external


class PlayerCommand(BaseModel):
    player_id: str
    command: str  # play, pause, stop, next, prev, volume
    value: Optional[str] = None


# ============================================================================
# Helpers
# ============================================================================

def get_config() -> dict:
    """Load lyrion configuration."""
    if CONFIG_FILE.exists():
        try:
            import tomllib
            return tomllib.loads(CONFIG_FILE.read_text())
        except Exception:
            pass
    return DEFAULT_CONFIG.copy()


def detect_runtime() -> Optional[str]:
    """Detect container runtime (podman or docker)."""
    if shutil.which("podman"):
        return "podman"
    if shutil.which("docker"):
        return "docker"
    return None


def is_running() -> bool:
    """Check if Lyrion container is running."""
    rt = detect_runtime()
    if not rt:
        return False
    try:
        result = subprocess.run(
            [rt, "ps", "--format", "{{.Names}}"],
            capture_output=True, text=True, timeout=5
        )
        return "lyrion" in result.stdout.split() or "secbx-lyrion" in result.stdout.split()
    except Exception:
        return False


def get_container_name() -> str:
    """Get actual container name."""
    rt = detect_runtime()
    if not rt:
        return "lyrion"
    try:
        result = subprocess.run(
            [rt, "ps", "--format", "{{.Names}}"],
            capture_output=True, text=True, timeout=5
        )
        for name in result.stdout.split():
            if "lyrion" in name:
                return name
    except Exception:
        pass
    return "lyrion"


def get_lyrion_url() -> str:
    """Get Lyrion web UI URL."""
    cfg = get_config()
    port = cfg.get("web_port", 9000)
    return f"http://127.0.0.1:{port}"


async def lyrion_jsonrpc(method: str, params: list = None) -> dict:
    """Make JSON-RPC request to Lyrion (Squeezebox Server API)."""
    url = f"{get_lyrion_url()}/jsonrpc.js"
    payload = {
        "id": 1,
        "method": "slim.request",
        "params": ["", params or [method]]
    }
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(url, json=payload)
        resp.raise_for_status()
        data = resp.json()
        return data.get("result", {})


async def get_library_stats() -> dict:
    """Get library statistics via JSON-RPC."""
    stats = {"songs": 0, "albums": 0, "artists": 0, "genres": 0, "playlists": 0}

    try:
        # Get total counts
        result = await lyrion_jsonrpc("info", ["total", "songs", "?"])
        stats["songs"] = result.get("_songs", 0)

        result = await lyrion_jsonrpc("info", ["total", "albums", "?"])
        stats["albums"] = result.get("_albums", 0)

        result = await lyrion_jsonrpc("info", ["total", "artists", "?"])
        stats["artists"] = result.get("_artists", 0)

        result = await lyrion_jsonrpc("info", ["total", "genres", "?"])
        stats["genres"] = result.get("_genres", 0)
    except Exception as e:
        log.debug(f"Could not get library stats: {e}")

    return stats


# ============================================================================
# Public Endpoints (no auth required)
# ============================================================================

@router.get("/health")
async def health():
    """Health check."""
    return {"status": "ok", "module": "lyrion"}


@router.get("/status")
async def status():
    """Get Lyrion service status."""
    cfg = get_config()
    rt = detect_runtime()
    running = is_running()

    uptime = 0
    version = "unknown"
    library = {"songs": 0, "albums": 0, "artists": 0}
    web_accessible = False

    if running:
        container = get_container_name()

        # Get uptime
        if rt:
            try:
                result = subprocess.run(
                    [rt, "ps", "--filter", f"name={container}", "--format", "{{.Status}}"],
                    capture_output=True, text=True, timeout=5
                )
                status_str = result.stdout.strip().split('\n')[0] if result.stdout else ""
                if "minute" in status_str:
                    uptime = int(''.join(filter(str.isdigit, status_str.split()[1]))) * 60
                elif "hour" in status_str:
                    uptime = int(''.join(filter(str.isdigit, status_str.split()[1]))) * 3600
                elif "second" in status_str:
                    uptime = int(''.join(filter(str.isdigit, status_str.split()[1])))
            except Exception:
                pass

        # Check web accessibility and get library stats
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"{get_lyrion_url()}/")
                web_accessible = resp.status_code == 200

            if web_accessible:
                library = await get_library_stats()

                # Try to get version
                try:
                    result = await lyrion_jsonrpc("version", ["?"])
                    version = result.get("_version", "unknown")
                except Exception:
                    pass
        except Exception:
            pass

    return {
        "running": running,
        "uptime": uptime,
        "version": version,
        "web_port": cfg.get("web_port", 9000),
        "cli_port": cfg.get("cli_port", 9090),
        "data_path": cfg.get("data_path", "/srv/lyrion"),
        "media_path": cfg.get("media_path", "/srv/media"),
        "runtime": rt or "none",
        "web_accessible": web_accessible,
        "library": library,
    }


# ============================================================================
# Protected Endpoints (JWT required)
# ============================================================================

@router.get("/config")
async def get_lyrion_config(user=Depends(require_jwt)):
    """Get Lyrion configuration."""
    return get_config()


@router.post("/config")
async def set_lyrion_config(config: LyrionConfig, user=Depends(require_jwt)):
    """Update Lyrion configuration."""
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)

    content = f"""# Lyrion Music Server configuration
web_port = {config.web_port}
cli_port = {config.cli_port}
data_path = "{config.data_path}"
media_path = "{config.media_path}"
memory_limit = "{config.memory_limit}"
"""
    CONFIG_FILE.write_text(content)
    log.info(f"Config updated by {user.get('sub', 'unknown')}")
    return {"success": True}


@router.get("/library")
async def get_library(user=Depends(require_jwt)):
    """Get library statistics."""
    if not is_running():
        return {"error": "Lyrion not running", "stats": {}}

    try:
        stats = await get_library_stats()
        return {"stats": stats}
    except Exception as e:
        log.error(f"Failed to get library stats: {e}")
        return {"error": str(e), "stats": {}}


@router.get("/library/recent")
async def get_recent_albums(limit: int = 10, user=Depends(require_jwt)):
    """Get recently added albums."""
    if not is_running():
        return {"albums": [], "error": "Lyrion not running"}

    try:
        result = await lyrion_jsonrpc("albums", [
            "0", str(limit), "sort:new", "tags:alyj"
        ])
        albums = result.get("albums_loop", [])
        return {"albums": albums}
    except Exception as e:
        log.error(f"Failed to get recent albums: {e}")
        return {"albums": [], "error": str(e)}


@router.get("/players")
async def get_players(user=Depends(require_jwt)):
    """Get connected players/devices."""
    if not is_running():
        return {"players": [], "error": "Lyrion not running"}

    try:
        result = await lyrion_jsonrpc("players", ["0", "100"])
        players = []
        for p in result.get("players_loop", []):
            players.append({
                "id": p.get("playerid", ""),
                "name": p.get("name", ""),
                "model": p.get("model", ""),
                "ip": p.get("ip", ""),
                "connected": p.get("connected", 0) == 1,
                "power": p.get("power", 0) == 1,
            })
        return {"players": players, "count": len(players)}
    except Exception as e:
        log.error(f"Failed to get players: {e}")
        return {"players": [], "error": str(e)}


@router.get("/now_playing/{player_id}")
async def get_now_playing(player_id: str, user=Depends(require_jwt)):
    """Get now playing info for a player."""
    if not is_running():
        raise HTTPException(503, "Lyrion not running")

    try:
        result = await lyrion_jsonrpc(player_id, [
            "status", "-", "1", "tags:alyjtiqKJ"
        ])

        playlist = result.get("playlist_loop", [{}])
        current = playlist[0] if playlist else {}

        return {
            "player_id": player_id,
            "mode": result.get("mode", "stop"),
            "volume": result.get("mixer volume", 0),
            "time": result.get("time", 0),
            "duration": result.get("duration", 0),
            "track": {
                "title": current.get("title", ""),
                "artist": current.get("artist", ""),
                "album": current.get("album", ""),
                "artwork_url": current.get("artwork_url", ""),
            }
        }
    except Exception as e:
        log.error(f"Failed to get now playing: {e}")
        raise HTTPException(500, str(e))


@router.post("/player/command")
async def player_command(cmd: PlayerCommand, user=Depends(require_jwt)):
    """Send command to a player."""
    if not is_running():
        raise HTTPException(503, "Lyrion not running")

    commands_map = {
        "play": ["play"],
        "pause": ["pause", "1"],
        "stop": ["stop"],
        "next": ["playlist", "index", "+1"],
        "prev": ["playlist", "index", "-1"],
        "volume": ["mixer", "volume", cmd.value or "50"],
        "power_on": ["power", "1"],
        "power_off": ["power", "0"],
    }

    if cmd.command not in commands_map:
        raise HTTPException(400, f"Unknown command: {cmd.command}")

    try:
        await lyrion_jsonrpc(cmd.player_id, commands_map[cmd.command])
        log.info(f"Player command {cmd.command} sent to {cmd.player_id} by {user.get('sub', 'unknown')}")
        return {"success": True}
    except Exception as e:
        log.error(f"Player command failed: {e}")
        return {"success": False, "error": str(e)}


@router.post("/rescan")
async def rescan_library(req: RescanRequest = None, user=Depends(require_jwt)):
    """Trigger library rescan."""
    if not is_running():
        raise HTTPException(503, "Lyrion not running")

    mode = req.mode if req else "full"
    scan_cmd = {
        "full": ["rescan"],
        "playlists": ["rescan", "playlists"],
        "external": ["rescan", "external"],
    }.get(mode, ["rescan"])

    try:
        await lyrion_jsonrpc("rescan", scan_cmd)
        log.info(f"Library rescan ({mode}) triggered by {user.get('sub', 'unknown')}")
        return {"success": True, "mode": mode}
    except Exception as e:
        log.error(f"Rescan failed: {e}")
        return {"success": False, "error": str(e)}


@router.get("/scan_status")
async def scan_status(user=Depends(require_jwt)):
    """Get library scan status."""
    if not is_running():
        return {"scanning": False}

    try:
        result = await lyrion_jsonrpc("rescanprogress", [])
        return {
            "scanning": result.get("rescan", 0) == 1,
            "progress": result.get("progressname", ""),
            "steps": result.get("steps", ""),
        }
    except Exception:
        return {"scanning": False}


@router.get("/system")
async def system_info(user=Depends(require_jwt)):
    """Get system resource info."""
    cfg = get_config()
    rt = detect_runtime()

    mem_total = mem_used = mem_pct = 0
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    mem_total = int(line.split()[1])
                elif line.startswith("MemAvailable:"):
                    mem_free = int(line.split()[1])
                    mem_used = mem_total - mem_free
                    mem_pct = (mem_used * 100) // mem_total if mem_total else 0
    except Exception:
        pass

    disk_total = disk_used = disk_pct = 0
    data_path = cfg.get("data_path", "/srv/lyrion")
    try:
        import os
        st = os.statvfs(data_path if Path(data_path).exists() else "/")
        disk_total = (st.f_blocks * st.f_frsize) // 1024
        disk_used = ((st.f_blocks - st.f_bfree) * st.f_frsize) // 1024
        disk_pct = (disk_used * 100) // disk_total if disk_total else 0
    except Exception:
        pass

    media_size = 0
    media_path = cfg.get("media_path", "/srv/media")
    try:
        if Path(media_path).exists():
            result = subprocess.run(
                ["du", "-sk", media_path],
                capture_output=True, text=True, timeout=30
            )
            media_size = int(result.stdout.split()[0]) if result.stdout else 0
    except Exception:
        pass

    container_mem = "0"
    container_cpu = "0%"
    if is_running() and rt:
        container = get_container_name()
        try:
            result = subprocess.run(
                [rt, "stats", "--no-stream", "--format", "{{.MemUsage}} {{.CPUPerc}}", container],
                capture_output=True, text=True, timeout=5
            )
            parts = result.stdout.strip().split()
            if len(parts) >= 2:
                container_mem = parts[0]
                container_cpu = parts[-1]
        except Exception:
            pass

    return {
        "memory": {
            "total_kb": mem_total,
            "used_kb": mem_used,
            "percent": mem_pct,
        },
        "disk": {
            "total_kb": disk_total,
            "used_kb": disk_used,
            "percent": disk_pct,
            "path": data_path,
        },
        "media": {
            "size_kb": media_size,
            "path": media_path,
        },
        "container": {
            "memory": container_mem,
            "cpu": container_cpu,
        },
    }


@router.get("/logs")
async def get_logs(lines: int = 50, user=Depends(require_jwt)):
    """Get recent container logs."""
    rt = detect_runtime()
    if not rt:
        return {"logs": []}

    container = get_container_name()
    try:
        result = subprocess.run(
            [rt, "logs", "--tail", str(lines), container],
            capture_output=True, text=True, timeout=10
        )
        logs = result.stdout.strip().split('\n') if result.stdout else []
        if result.stderr:
            logs.extend(result.stderr.strip().split('\n'))
        return {"logs": logs[-lines:]}
    except Exception:
        return {"logs": []}


# ============================================================================
# Service Control
# ============================================================================

@router.post("/install")
async def install_service(user=Depends(require_jwt)):
    """Pull and prepare Lyrion container image."""
    rt = detect_runtime()
    if not rt:
        return {"success": False, "error": "No container runtime (docker/podman) found"}

    log.info(f"Installing Lyrion by {user.get('sub', 'unknown')}")

    try:
        result = subprocess.run(
            [rt, "pull", "lmscommunity/logitechmediaserver:stable"],
            capture_output=True, text=True, timeout=600
        )
        if result.returncode == 0:
            return {"success": True}
        else:
            return {"success": False, "error": result.stderr.strip()}
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Pull timeout"}


@router.post("/start")
async def start_service(user=Depends(require_jwt)):
    """Start Lyrion container."""
    if is_running():
        return {"success": False, "error": "Already running"}

    rt = detect_runtime()
    if not rt:
        return {"success": False, "error": "No container runtime (docker/podman) found"}

    cfg = get_config()
    data_path = Path(cfg.get("data_path", "/srv/lyrion"))
    media_path = Path(cfg.get("media_path", "/srv/media"))

    data_path.mkdir(parents=True, exist_ok=True)
    media_path.mkdir(parents=True, exist_ok=True)

    # Create subdirectories for LMS
    (data_path / "config").mkdir(exist_ok=True)
    (data_path / "playlist").mkdir(exist_ok=True)

    cmd = [
        rt, "run", "-d",
        "--name", "lyrion",
        "-v", f"{data_path}/config:/config",
        "-v", f"{data_path}/playlist:/playlist",
        "-v", f"{media_path}:/music:ro",
        "-p", f"127.0.0.1:{cfg.get('web_port', 9000)}:9000",
        "-p", f"127.0.0.1:{cfg.get('cli_port', 9090)}:9090",
        "-p", f"127.0.0.1:3483:3483",
        "-p", f"127.0.0.1:3483:3483/udp",
        "--memory", cfg.get("memory_limit", "512m"),
        "--restart", "unless-stopped",
        "-e", "PUID=1000",
        "-e", "PGID=1000",
        "lmscommunity/logitechmediaserver:stable",
    ]

    log.info(f"Starting Lyrion by {user.get('sub', 'unknown')}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        await asyncio.sleep(5)  # LMS takes a bit to start

        if is_running():
            return {"success": True}
        else:
            return {"success": False, "error": result.stderr.strip() or "Failed to start"}
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Start timeout"}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.post("/stop")
async def stop_service(user=Depends(require_jwt)):
    """Stop Lyrion container."""
    rt = detect_runtime()
    if not rt:
        return {"success": False, "error": "No container runtime"}

    container = get_container_name()
    log.info(f"Stopping Lyrion by {user.get('sub', 'unknown')}")

    try:
        subprocess.run([rt, "stop", container], capture_output=True, timeout=30)
        subprocess.run([rt, "rm", "-f", container], capture_output=True, timeout=10)

        if not is_running():
            return {"success": True}
        else:
            return {"success": False, "error": "Failed to stop"}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.post("/restart")
async def restart_service(user=Depends(require_jwt)):
    """Restart Lyrion container."""
    await stop_service(user)
    await asyncio.sleep(1)
    return await start_service(user)


# ============================================================================
# Backup & Restore
# ============================================================================

@router.get("/backup")
async def list_backups(user=Depends(require_jwt)):
    """List available backups."""
    backup_dir = Path("/var/backups/secubox/lyrion")
    if not backup_dir.exists():
        return {"backups": []}

    backups = []
    for f in sorted(backup_dir.glob("*.tar.gz"), reverse=True):
        backups.append({
            "name": f.name,
            "size": f.stat().st_size,
            "created": f.stat().st_mtime,
        })
    return {"backups": backups[:10]}


@router.post("/backup")
async def create_backup(user=Depends(require_jwt)):
    """Create configuration backup."""
    cfg = get_config()
    data_path = Path(cfg.get("data_path", "/srv/lyrion"))
    backup_dir = Path("/var/backups/secubox/lyrion")
    backup_dir.mkdir(parents=True, exist_ok=True)

    import time
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    backup_file = backup_dir / f"lyrion-{timestamp}.tar.gz"

    # Only backup config, not the entire library cache
    config_dir = data_path / "config"
    if not config_dir.exists():
        return {"success": False, "error": "No config directory found"}

    log.info(f"Creating backup by {user.get('sub', 'unknown')}")

    try:
        result = subprocess.run(
            ["tar", "czf", str(backup_file), "-C", str(data_path), "config", "playlist"],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode == 0:
            return {"success": True, "file": backup_file.name, "size": backup_file.stat().st_size}
        else:
            return {"success": False, "error": result.stderr.strip()}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.post("/restore/{backup_name}")
async def restore_backup(backup_name: str, user=Depends(require_jwt)):
    """Restore from backup."""
    backup_file = Path(f"/var/backups/secubox/lyrion/{backup_name}")
    if not backup_file.exists():
        raise HTTPException(404, "Backup not found")

    cfg = get_config()
    data_path = Path(cfg.get("data_path", "/srv/lyrion"))

    was_running = is_running()
    if was_running:
        await stop_service(user)
        await asyncio.sleep(2)

    log.info(f"Restoring backup {backup_name} by {user.get('sub', 'unknown')}")

    try:
        result = subprocess.run(
            ["tar", "xzf", str(backup_file), "-C", str(data_path)],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode != 0:
            return {"success": False, "error": result.stderr.strip()}

        if was_running:
            await asyncio.sleep(1)
            await start_service(user)

        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}


app.include_router(router)
