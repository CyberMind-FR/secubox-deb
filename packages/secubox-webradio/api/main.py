"""secubox-webradio -- FastAPI application for Internet Radio Streaming.

Ported from OpenWRT concepts. Provides internet radio station management,
Icecast/Liquidsoap streaming, recording functionality, and schedule programming.
"""
import asyncio
import shutil
import subprocess
import json
import time
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any

from fastapi import FastAPI, APIRouter, Depends, HTTPException
from pydantic import BaseModel

from secubox_core.auth import router as auth_router, require_jwt
from secubox_core.logger import get_logger

app = FastAPI(title="secubox-webradio", version="1.0.0", root_path="/api/v1/webradio")
app.include_router(auth_router, prefix="/auth")
router = APIRouter()
log = get_logger("webradio")

# Configuration
CONFIG_FILE = Path("/etc/secubox/webradio.toml")
STATIONS_FILE = Path("/var/lib/secubox/webradio/stations.json")
SCHEDULE_FILE = Path("/var/lib/secubox/webradio/schedule.json")
RECORDINGS_DIR = Path("/var/lib/secubox/webradio/recordings")

DEFAULT_CONFIG = {
    "icecast_port": 8000,
    "liquidsoap_port": 8001,
    "data_path": "/var/lib/secubox/webradio",
    "output_formats": ["mp3", "ogg", "aac"],
    "max_recording_hours": 4,
    "memory_limit": "256m",
}


# ============================================================================
# Models
# ============================================================================

class WebRadioConfig(BaseModel):
    icecast_port: int = 8000
    liquidsoap_port: int = 8001
    data_path: str = "/var/lib/secubox/webradio"
    output_formats: List[str] = ["mp3", "ogg", "aac"]
    max_recording_hours: int = 4
    memory_limit: str = "256m"


class Station(BaseModel):
    id: Optional[str] = None
    name: str
    url: str
    genre: str = "Various"
    country: str = ""
    favicon: str = ""
    bitrate: int = 128
    codec: str = "mp3"


class ScheduleEntry(BaseModel):
    id: Optional[str] = None
    station_id: str
    day_of_week: int  # 0=Monday, 6=Sunday
    start_time: str  # HH:MM
    end_time: str    # HH:MM
    action: str = "play"  # play, record
    enabled: bool = True


# ============================================================================
# Helpers
# ============================================================================

def get_config() -> dict:
    """Load webradio configuration."""
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


def load_stations() -> List[dict]:
    """Load saved radio stations."""
    if STATIONS_FILE.exists():
        try:
            return json.loads(STATIONS_FILE.read_text())
        except Exception:
            pass
    return []


def save_stations(stations: List[dict]):
    """Save radio stations."""
    STATIONS_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATIONS_FILE.write_text(json.dumps(stations, indent=2))


def load_schedule() -> List[dict]:
    """Load schedule entries."""
    if SCHEDULE_FILE.exists():
        try:
            return json.loads(SCHEDULE_FILE.read_text())
        except Exception:
            pass
    return []


def save_schedule(schedule: List[dict]):
    """Save schedule entries."""
    SCHEDULE_FILE.parent.mkdir(parents=True, exist_ok=True)
    SCHEDULE_FILE.write_text(json.dumps(schedule, indent=2))


def generate_id() -> str:
    """Generate unique ID."""
    import hashlib
    return hashlib.sha256(str(time.time()).encode()).hexdigest()[:12]


def is_container_running(name: str) -> bool:
    """Check if a container is running."""
    rt = detect_runtime()
    if not rt:
        return False
    try:
        result = subprocess.run(
            [rt, "ps", "--format", "{{.Names}}"],
            capture_output=True, text=True, timeout=5
        )
        return name in result.stdout.split()
    except Exception:
        return False


def is_streaming() -> bool:
    """Check if streaming server is running."""
    return is_container_running("secbx-icecast") or is_container_running("icecast")


def get_container_name(base: str) -> str:
    """Get actual container name."""
    rt = detect_runtime()
    if not rt:
        return base
    try:
        result = subprocess.run(
            [rt, "ps", "--format", "{{.Names}}"],
            capture_output=True, text=True, timeout=5
        )
        for name in result.stdout.split():
            if base in name:
                return name
    except Exception:
        pass
    return base


# ============================================================================
# Public Endpoints (no auth required)
# ============================================================================

@router.get("/health")
async def health():
    """Health check."""
    return {"status": "ok", "module": "webradio"}


@router.get("/status")
async def status():
    """Get webradio service status."""
    cfg = get_config()
    rt = detect_runtime()
    streaming = is_streaming()

    stations = load_stations()
    recordings_count = 0
    if RECORDINGS_DIR.exists():
        recordings_count = len(list(RECORDINGS_DIR.glob("*.mp3"))) + \
                          len(list(RECORDINGS_DIR.glob("*.ogg"))) + \
                          len(list(RECORDINGS_DIR.glob("*.aac")))

    container_uptime = 0
    if streaming and rt:
        container = get_container_name("icecast")
        try:
            result = subprocess.run(
                [rt, "ps", "--filter", f"name={container}", "--format", "{{.Status}}"],
                capture_output=True, text=True, timeout=5
            )
            status_str = result.stdout.strip().split('\n')[0] if result.stdout else ""
            if "minute" in status_str:
                container_uptime = int(''.join(filter(str.isdigit, status_str.split()[1]))) * 60
            elif "hour" in status_str:
                container_uptime = int(''.join(filter(str.isdigit, status_str.split()[1]))) * 3600
        except Exception:
            pass

    return {
        "streaming": streaming,
        "uptime": container_uptime,
        "icecast_port": cfg.get("icecast_port", 8000),
        "liquidsoap_port": cfg.get("liquidsoap_port", 8001),
        "runtime": rt or "none",
        "stations_count": len(stations),
        "recordings_count": recordings_count,
        "output_formats": cfg.get("output_formats", ["mp3", "ogg", "aac"]),
    }


# ============================================================================
# Station Management
# ============================================================================

@router.get("/stations")
async def get_stations(user=Depends(require_jwt)):
    """Get all saved stations."""
    stations = load_stations()
    return {"stations": stations, "count": len(stations)}


@router.post("/station/add")
async def add_station(station: Station, user=Depends(require_jwt)):
    """Add a station to favorites."""
    stations = load_stations()

    # Check for duplicate URL
    for s in stations:
        if s.get("url") == station.url:
            return {"success": False, "error": "Station URL already exists"}

    station_dict = station.dict()
    station_dict["id"] = generate_id()
    station_dict["added_at"] = datetime.now().isoformat()

    stations.append(station_dict)
    save_stations(stations)

    log.info(f"Station added: {station.name} by {user.get('sub', 'unknown')}")
    return {"success": True, "station": station_dict}


@router.delete("/station/{station_id}")
async def remove_station(station_id: str, user=Depends(require_jwt)):
    """Remove a station from favorites."""
    stations = load_stations()
    original_count = len(stations)
    stations = [s for s in stations if s.get("id") != station_id]

    if len(stations) == original_count:
        raise HTTPException(404, "Station not found")

    save_stations(stations)
    log.info(f"Station removed: {station_id} by {user.get('sub', 'unknown')}")
    return {"success": True}


@router.get("/station/{station_id}")
async def get_station(station_id: str, user=Depends(require_jwt)):
    """Get station details."""
    stations = load_stations()
    for s in stations:
        if s.get("id") == station_id:
            return {"station": s}
    raise HTTPException(404, "Station not found")


@router.get("/station/{station_id}/play")
async def get_stream_url(station_id: str, user=Depends(require_jwt)):
    """Get stream URL for a station."""
    stations = load_stations()
    for s in stations:
        if s.get("id") == station_id:
            return {
                "stream_url": s.get("url"),
                "name": s.get("name"),
                "codec": s.get("codec", "mp3"),
                "bitrate": s.get("bitrate", 128)
            }
    raise HTTPException(404, "Station not found")


# ============================================================================
# Streaming Server Control
# ============================================================================

@router.post("/stream/start")
async def start_streaming(user=Depends(require_jwt)):
    """Start the streaming server (Icecast)."""
    if is_streaming():
        return {"success": False, "error": "Already running"}

    rt = detect_runtime()
    if not rt:
        return {"success": False, "error": "No container runtime (docker/podman) found"}

    cfg = get_config()
    data_path = Path(cfg.get("data_path", "/var/lib/secubox/webradio"))
    icecast_port = cfg.get("icecast_port", 8000)

    # Create directories
    (data_path / "icecast").mkdir(parents=True, exist_ok=True)
    (data_path / "logs").mkdir(parents=True, exist_ok=True)

    cmd = [
        rt, "run", "-d",
        "--name", "secbx-icecast",
        "-v", f"{data_path}/icecast:/etc/icecast2:rw",
        "-v", f"{data_path}/logs:/var/log/icecast2:rw",
        "-p", f"127.0.0.1:{icecast_port}:8000",
        "--memory", cfg.get("memory_limit", "256m"),
        "--restart", "unless-stopped",
        "moul/icecast",
    ]

    log.info(f"Starting Icecast by {user.get('sub', 'unknown')}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        await asyncio.sleep(3)

        if is_streaming():
            return {"success": True}
        else:
            return {"success": False, "error": result.stderr.strip() or "Failed to start"}
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Start timeout"}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.post("/stream/stop")
async def stop_streaming(user=Depends(require_jwt)):
    """Stop the streaming server."""
    rt = detect_runtime()
    if not rt:
        return {"success": False, "error": "No container runtime"}

    container = get_container_name("icecast")
    log.info(f"Stopping Icecast by {user.get('sub', 'unknown')}")

    try:
        subprocess.run([rt, "stop", container], capture_output=True, timeout=30)
        subprocess.run([rt, "rm", "-f", container], capture_output=True, timeout=10)

        if not is_streaming():
            return {"success": True}
        else:
            return {"success": False, "error": "Failed to stop"}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.get("/stream/status")
async def streaming_status(user=Depends(require_jwt)):
    """Get detailed streaming status."""
    cfg = get_config()
    streaming = is_streaming()

    listeners = 0
    sources = 0
    mounts = []

    if streaming:
        # Try to get Icecast stats
        try:
            import httpx
            icecast_port = cfg.get("icecast_port", 8000)
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"http://127.0.0.1:{icecast_port}/status-json.xsl")
                if resp.status_code == 200:
                    data = resp.json()
                    icestats = data.get("icestats", {})
                    sources = len(icestats.get("source", [])) if isinstance(icestats.get("source"), list) else (1 if icestats.get("source") else 0)

                    source_list = icestats.get("source", [])
                    if not isinstance(source_list, list):
                        source_list = [source_list] if source_list else []

                    for src in source_list:
                        if src:
                            listeners += src.get("listeners", 0)
                            mounts.append({
                                "mount": src.get("listenurl", ""),
                                "title": src.get("title", ""),
                                "listeners": src.get("listeners", 0),
                                "bitrate": src.get("audio_bitrate", 0),
                            })
        except Exception as e:
            log.debug(f"Could not get Icecast stats: {e}")

    return {
        "streaming": streaming,
        "listeners": listeners,
        "sources": sources,
        "mounts": mounts,
        "icecast_port": cfg.get("icecast_port", 8000),
    }


# ============================================================================
# Recording
# ============================================================================

@router.get("/recordings")
async def list_recordings(user=Depends(require_jwt)):
    """List all recordings."""
    recordings = []

    if RECORDINGS_DIR.exists():
        for ext in ["mp3", "ogg", "aac"]:
            for f in RECORDINGS_DIR.glob(f"*.{ext}"):
                stat = f.stat()
                recordings.append({
                    "name": f.name,
                    "path": str(f),
                    "size": stat.st_size,
                    "created": stat.st_mtime,
                    "format": ext.upper(),
                })

    # Sort by creation time, newest first
    recordings.sort(key=lambda x: x["created"], reverse=True)

    return {"recordings": recordings, "count": len(recordings)}


@router.post("/record/start")
async def start_recording(station_id: str, format: str = "mp3", user=Depends(require_jwt)):
    """Start recording a station."""
    stations = load_stations()
    station = None
    for s in stations:
        if s.get("id") == station_id:
            station = s
            break

    if not station:
        raise HTTPException(404, "Station not found")

    cfg = get_config()
    max_hours = cfg.get("max_recording_hours", 4)

    RECORDINGS_DIR.mkdir(parents=True, exist_ok=True)

    # Generate filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_name = "".join(c for c in station["name"] if c.isalnum() or c in " -_").strip()[:30]
    filename = f"{safe_name}_{timestamp}.{format}"
    output_path = RECORDINGS_DIR / filename

    # Select audio codec
    codec_map = {
        "mp3": "libmp3lame",
        "ogg": "libvorbis",
        "aac": "aac"
    }
    codec = codec_map.get(format, "libmp3lame")

    # Start ffmpeg recording
    cmd = [
        "ffmpeg", "-y",
        "-i", station["url"],
        "-t", str(max_hours * 3600),  # Max duration
        "-acodec", codec,
        "-b:a", f"{station.get('bitrate', 128)}k",
        str(output_path)
    ]

    try:
        # Start in background
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True
        )

        # Store PID for later stop
        pid_file = RECORDINGS_DIR / f".recording_{station_id}.pid"
        pid_file.write_text(str(process.pid))

        log.info(f"Recording started: {filename} by {user.get('sub', 'unknown')}")
        return {
            "success": True,
            "filename": filename,
            "station": station["name"],
            "pid": process.pid
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.post("/record/stop")
async def stop_recording(station_id: str = None, user=Depends(require_jwt)):
    """Stop a recording."""
    import signal
    import os

    if station_id:
        pid_file = RECORDINGS_DIR / f".recording_{station_id}.pid"
        if pid_file.exists():
            try:
                pid = int(pid_file.read_text().strip())
                os.kill(pid, signal.SIGTERM)
                pid_file.unlink()
                log.info(f"Recording stopped for {station_id} by {user.get('sub', 'unknown')}")
                return {"success": True}
            except ProcessLookupError:
                pid_file.unlink()
                return {"success": True, "message": "Process already stopped"}
            except Exception as e:
                return {"success": False, "error": str(e)}

    # Stop all recordings
    stopped = 0
    for pid_file in RECORDINGS_DIR.glob(".recording_*.pid"):
        try:
            pid = int(pid_file.read_text().strip())
            os.kill(pid, signal.SIGTERM)
            pid_file.unlink()
            stopped += 1
        except Exception:
            pid_file.unlink()

    log.info(f"Stopped {stopped} recordings by {user.get('sub', 'unknown')}")
    return {"success": True, "stopped": stopped}


@router.delete("/recording/{filename}")
async def delete_recording(filename: str, user=Depends(require_jwt)):
    """Delete a recording."""
    # Sanitize filename to prevent directory traversal
    safe_filename = Path(filename).name
    recording_path = RECORDINGS_DIR / safe_filename

    if not recording_path.exists():
        raise HTTPException(404, "Recording not found")

    try:
        recording_path.unlink()
        log.info(f"Recording deleted: {filename} by {user.get('sub', 'unknown')}")
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ============================================================================
# Schedule
# ============================================================================

@router.get("/schedule")
async def get_schedule(user=Depends(require_jwt)):
    """Get schedule entries."""
    schedule = load_schedule()
    return {"schedule": schedule, "count": len(schedule)}


@router.post("/schedule")
async def update_schedule(entry: ScheduleEntry, user=Depends(require_jwt)):
    """Add or update a schedule entry."""
    schedule = load_schedule()

    entry_dict = entry.dict()

    if entry.id:
        # Update existing
        found = False
        for i, s in enumerate(schedule):
            if s.get("id") == entry.id:
                entry_dict["updated_at"] = datetime.now().isoformat()
                schedule[i] = entry_dict
                found = True
                break
        if not found:
            raise HTTPException(404, "Schedule entry not found")
    else:
        # Add new
        entry_dict["id"] = generate_id()
        entry_dict["created_at"] = datetime.now().isoformat()
        schedule.append(entry_dict)

    save_schedule(schedule)
    log.info(f"Schedule updated by {user.get('sub', 'unknown')}")
    return {"success": True, "entry": entry_dict}


@router.delete("/schedule/{entry_id}")
async def delete_schedule_entry(entry_id: str, user=Depends(require_jwt)):
    """Delete a schedule entry."""
    schedule = load_schedule()
    original_count = len(schedule)
    schedule = [s for s in schedule if s.get("id") != entry_id]

    if len(schedule) == original_count:
        raise HTTPException(404, "Schedule entry not found")

    save_schedule(schedule)
    log.info(f"Schedule entry deleted: {entry_id} by {user.get('sub', 'unknown')}")
    return {"success": True}


# ============================================================================
# Container Management
# ============================================================================

@router.get("/container/status")
async def container_status(user=Depends(require_jwt)):
    """Get container status."""
    rt = detect_runtime()
    if not rt:
        return {"runtime": None, "containers": []}

    containers = []
    for name in ["icecast", "liquidsoap"]:
        running = is_container_running(f"secbx-{name}") or is_container_running(name)
        containers.append({
            "name": name,
            "running": running,
        })

    return {"runtime": rt, "containers": containers}


@router.post("/container/install")
async def install_containers(user=Depends(require_jwt)):
    """Pull required container images."""
    rt = detect_runtime()
    if not rt:
        return {"success": False, "error": "No container runtime (docker/podman) found"}

    log.info(f"Installing containers by {user.get('sub', 'unknown')}")

    images = ["moul/icecast"]
    errors = []

    for image in images:
        try:
            result = subprocess.run(
                [rt, "pull", image],
                capture_output=True, text=True, timeout=600
            )
            if result.returncode != 0:
                errors.append(f"{image}: {result.stderr.strip()}")
        except subprocess.TimeoutExpired:
            errors.append(f"{image}: Pull timeout")
        except Exception as e:
            errors.append(f"{image}: {str(e)}")

    if errors:
        return {"success": False, "errors": errors}
    return {"success": True}


@router.post("/container/start")
async def start_containers(user=Depends(require_jwt)):
    """Start all containers."""
    return await start_streaming(user)


@router.post("/container/stop")
async def stop_containers(user=Depends(require_jwt)):
    """Stop all containers."""
    return await stop_streaming(user)


@router.post("/container/restart")
async def restart_containers(user=Depends(require_jwt)):
    """Restart all containers."""
    await stop_streaming(user)
    await asyncio.sleep(2)
    return await start_streaming(user)


# ============================================================================
# Configuration
# ============================================================================

@router.get("/config")
async def get_webradio_config(user=Depends(require_jwt)):
    """Get webradio configuration."""
    return get_config()


@router.post("/config")
async def set_webradio_config(config: WebRadioConfig, user=Depends(require_jwt)):
    """Update webradio configuration."""
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)

    formats_str = ", ".join(f'"{f}"' for f in config.output_formats)
    content = f"""# WebRadio configuration
icecast_port = {config.icecast_port}
liquidsoap_port = {config.liquidsoap_port}
data_path = "{config.data_path}"
output_formats = [{formats_str}]
max_recording_hours = {config.max_recording_hours}
memory_limit = "{config.memory_limit}"
"""
    CONFIG_FILE.write_text(content)
    log.info(f"Config updated by {user.get('sub', 'unknown')}")
    return {"success": True}


# ============================================================================
# Logs
# ============================================================================

@router.get("/logs")
async def get_logs(lines: int = 50, user=Depends(require_jwt)):
    """Get container logs."""
    rt = detect_runtime()
    if not rt:
        return {"logs": []}

    container = get_container_name("icecast")
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


app.include_router(router)
