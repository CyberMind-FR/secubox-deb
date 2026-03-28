#!/usr/bin/env python3
"""SecuBox WebRadio API - Internet Radio Streaming with Icecast"""

from fastapi import FastAPI, HTTPException, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional, List
import subprocess
import os
import json
import xml.etree.ElementTree as ET
from pathlib import Path

app = FastAPI(title="SecuBox WebRadio API", version="1.0.0")

ICECAST_CONFIG = Path("/etc/icecast2/icecast.xml")
ICECAST_LOG_DIR = Path("/var/log/icecast2")
MEDIA_DIR = Path("/var/lib/secubox/webradio/media")
PLAYLISTS_DIR = Path("/var/lib/secubox/webradio/playlists")


class MountConfig(BaseModel):
    name: str
    password: Optional[str] = None
    genre: Optional[str] = "Various"
    description: Optional[str] = ""
    public: Optional[bool] = True


def run_cmd(cmd: list, timeout: int = 30) -> dict:
    """Run command and return result"""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {
            "success": result.returncode == 0,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "code": result.returncode
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Command timed out"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def parse_icecast_status():
    """Parse Icecast status from admin XML"""
    try:
        result = subprocess.run(
            ["curl", "-s", "http://localhost:8000/admin/stats",
             "-u", "admin:hackme"],  # Default credentials
            capture_output=True, text=True, timeout=5
        )
        if result.returncode != 0:
            return None

        root = ET.fromstring(result.stdout)
        sources = []
        for source in root.findall('.//source'):
            sources.append({
                "mount": source.get("mount"),
                "listeners": int(source.findtext("listeners", "0")),
                "title": source.findtext("title", ""),
                "genre": source.findtext("genre", ""),
                "bitrate": source.findtext("bitrate", ""),
                "type": source.findtext("server_type", "")
            })

        return {
            "listeners": int(root.findtext(".//listeners", "0")),
            "sources": sources,
            "server_start": root.findtext(".//server_start", "")
        }
    except Exception:
        return None


@app.get("/health")
async def health():
    """Health check endpoint"""
    return {"status": "ok", "service": "webradio"}


@app.get("/status")
async def status():
    """Get Icecast status"""
    # Check if icecast is running
    result = run_cmd(["systemctl", "is-active", "icecast2"])
    running = result.get("stdout", "").strip() == "active"

    # Check if icecast is installed
    installed = ICECAST_CONFIG.exists()

    # Get stream stats
    stats = None
    if running:
        stats = parse_icecast_status()

    # Count media files
    media_count = 0
    if MEDIA_DIR.exists():
        media_count = len(list(MEDIA_DIR.glob("**/*.mp3"))) + \
                      len(list(MEDIA_DIR.glob("**/*.ogg"))) + \
                      len(list(MEDIA_DIR.glob("**/*.flac")))

    return {
        "installed": installed,
        "running": running,
        "listeners": stats.get("listeners", 0) if stats else 0,
        "active_mounts": len(stats.get("sources", [])) if stats else 0,
        "media_files": media_count,
        "stream_url": "http://localhost:8000/stream" if running else None
    }


@app.post("/install")
async def install():
    """Install Icecast2"""
    result = run_cmd(["apt-get", "install", "-y", "icecast2", "ices2", "liquidsoap"], timeout=300)
    if not result["success"]:
        raise HTTPException(status_code=500, detail=f"Install failed: {result.get('stderr')}")

    # Create directories
    MEDIA_DIR.mkdir(parents=True, exist_ok=True)
    PLAYLISTS_DIR.mkdir(parents=True, exist_ok=True)

    # Enable and start icecast
    run_cmd(["systemctl", "enable", "icecast2"])
    run_cmd(["systemctl", "start", "icecast2"])

    return {"success": True, "message": "Icecast2 installed and started"}


@app.post("/start")
async def start():
    """Start Icecast"""
    result = run_cmd(["systemctl", "start", "icecast2"])
    if not result["success"]:
        raise HTTPException(status_code=500, detail=result.get("stderr", "Start failed"))
    return {"success": True}


@app.post("/stop")
async def stop():
    """Stop Icecast"""
    result = run_cmd(["systemctl", "stop", "icecast2"])
    if not result["success"]:
        raise HTTPException(status_code=500, detail=result.get("stderr", "Stop failed"))
    return {"success": True}


@app.post("/restart")
async def restart():
    """Restart Icecast"""
    result = run_cmd(["systemctl", "restart", "icecast2"])
    if not result["success"]:
        raise HTTPException(status_code=500, detail=result.get("stderr", "Restart failed"))
    return {"success": True}


@app.get("/mounts")
async def list_mounts():
    """List active mount points"""
    stats = parse_icecast_status()
    if not stats:
        return {"mounts": []}
    return {"mounts": stats.get("sources", [])}


@app.get("/config")
async def get_config():
    """Get current Icecast configuration"""
    if not ICECAST_CONFIG.exists():
        raise HTTPException(status_code=404, detail="Icecast not configured")

    try:
        tree = ET.parse(ICECAST_CONFIG)
        root = tree.getroot()

        return {
            "hostname": root.findtext(".//hostname", "localhost"),
            "port": int(root.findtext(".//listen-socket/port", "8000")),
            "source_password": root.findtext(".//authentication/source-password", ""),
            "admin_user": root.findtext(".//authentication/admin-user", "admin"),
            "max_clients": int(root.findtext(".//limits/clients", "100")),
            "max_sources": int(root.findtext(".//limits/sources", "4"))
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/config")
async def update_config(
    hostname: Optional[str] = None,
    source_password: Optional[str] = None,
    admin_password: Optional[str] = None,
    max_clients: Optional[int] = None
):
    """Update Icecast configuration"""
    if not ICECAST_CONFIG.exists():
        raise HTTPException(status_code=404, detail="Icecast not configured")

    try:
        tree = ET.parse(ICECAST_CONFIG)
        root = tree.getroot()

        if hostname:
            elem = root.find(".//hostname")
            if elem is not None:
                elem.text = hostname

        if source_password:
            elem = root.find(".//authentication/source-password")
            if elem is not None:
                elem.text = source_password

        if admin_password:
            elem = root.find(".//authentication/admin-password")
            if elem is not None:
                elem.text = admin_password

        if max_clients:
            elem = root.find(".//limits/clients")
            if elem is not None:
                elem.text = str(max_clients)

        tree.write(ICECAST_CONFIG)
        return {"success": True, "message": "Config updated. Restart Icecast to apply."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/playlists")
async def list_playlists():
    """List available playlists"""
    playlists = []
    if PLAYLISTS_DIR.exists():
        for f in PLAYLISTS_DIR.glob("*.m3u"):
            with open(f) as fp:
                lines = [l for l in fp.readlines() if not l.startswith("#") and l.strip()]
            playlists.append({
                "name": f.stem,
                "file": f.name,
                "tracks": len(lines)
            })
    return {"playlists": playlists}


@app.post("/playlists")
async def create_playlist(name: str, tracks: List[str]):
    """Create a new playlist"""
    PLAYLISTS_DIR.mkdir(parents=True, exist_ok=True)
    playlist_path = PLAYLISTS_DIR / f"{name}.m3u"

    content = "#EXTM3U\n"
    for track in tracks:
        content += f"{track}\n"

    with open(playlist_path, "w") as f:
        f.write(content)

    return {"success": True, "file": str(playlist_path)}


@app.get("/media")
async def list_media():
    """List available media files"""
    files = []
    if MEDIA_DIR.exists():
        for ext in ["mp3", "ogg", "flac", "wav"]:
            for f in MEDIA_DIR.glob(f"**/*.{ext}"):
                files.append({
                    "name": f.name,
                    "path": str(f.relative_to(MEDIA_DIR)),
                    "size": f.stat().st_size,
                    "type": ext
                })
    return {"files": sorted(files, key=lambda x: x["name"])}


@app.get("/logs")
async def get_logs(lines: int = 100):
    """Get Icecast logs"""
    log_file = ICECAST_LOG_DIR / "error.log"
    if not log_file.exists():
        return {"logs": []}

    result = run_cmd(["tail", "-n", str(lines), str(log_file)])
    if result["success"]:
        return {"logs": result["stdout"].split("\n")}
    return {"logs": []}


@app.get("/listeners")
async def get_listeners():
    """Get current listener statistics"""
    stats = parse_icecast_status()
    if not stats:
        return {"total": 0, "per_mount": []}

    per_mount = []
    for source in stats.get("sources", []):
        per_mount.append({
            "mount": source.get("mount"),
            "listeners": source.get("listeners", 0)
        })

    return {
        "total": stats.get("listeners", 0),
        "per_mount": per_mount
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
