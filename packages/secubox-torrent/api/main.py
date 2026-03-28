#!/usr/bin/env python3
"""SecuBox Torrent API - BitTorrent Client with Transmission"""

from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional, List
import subprocess
import os
import json
import base64
from pathlib import Path

app = FastAPI(title="SecuBox Torrent API", version="1.0.0")

TRANSMISSION_CONFIG = Path("/etc/transmission-daemon/settings.json")
DOWNLOAD_DIR = Path("/var/lib/secubox/torrent/downloads")
WATCH_DIR = Path("/var/lib/secubox/torrent/watch")
RPC_URL = "http://127.0.0.1:9091/transmission/rpc"


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


def transmission_rpc(method: str, arguments: dict = None) -> dict:
    """Call Transmission RPC API"""
    payload = {"method": method}
    if arguments:
        payload["arguments"] = arguments

    # Get session ID first
    result = run_cmd(["curl", "-s", "-I", RPC_URL])
    session_id = ""
    for line in result.get("stdout", "").split("\n"):
        if "X-Transmission-Session-Id" in line:
            session_id = line.split(":")[-1].strip()
            break

    # Make RPC call
    result = run_cmd([
        "curl", "-s", RPC_URL,
        "-H", f"X-Transmission-Session-Id: {session_id}",
        "-H", "Content-Type: application/json",
        "-d", json.dumps(payload)
    ])

    if result["success"]:
        try:
            return json.loads(result["stdout"])
        except:
            return {"result": "error", "error": "Invalid JSON response"}
    return {"result": "error", "error": result.get("stderr", "RPC failed")}


@app.get("/health")
async def health():
    """Health check endpoint"""
    return {"status": "ok", "service": "torrent"}


@app.get("/status")
async def status():
    """Get Transmission status"""
    # Check if transmission is running
    result = run_cmd(["systemctl", "is-active", "transmission-daemon"])
    running = result.get("stdout", "").strip() == "active"

    # Check if installed
    installed = TRANSMISSION_CONFIG.exists() or Path("/usr/bin/transmission-daemon").exists()

    stats = {}
    if running:
        rpc_result = transmission_rpc("session-stats")
        if rpc_result.get("result") == "success":
            args = rpc_result.get("arguments", {})
            stats = {
                "download_speed": args.get("downloadSpeed", 0),
                "upload_speed": args.get("uploadSpeed", 0),
                "active_torrents": args.get("activeTorrentCount", 0),
                "paused_torrents": args.get("pausedTorrentCount", 0),
                "total_downloaded": args.get("cumulative-stats", {}).get("downloadedBytes", 0),
                "total_uploaded": args.get("cumulative-stats", {}).get("uploadedBytes", 0)
            }

    # Get download dir size
    download_size = "0"
    if DOWNLOAD_DIR.exists():
        result = run_cmd(["du", "-sh", str(DOWNLOAD_DIR)])
        if result["success"]:
            download_size = result["stdout"].split()[0] if result["stdout"] else "0"

    return {
        "installed": installed,
        "running": running,
        "download_dir": str(DOWNLOAD_DIR),
        "download_size": download_size,
        **stats
    }


@app.post("/install")
async def install():
    """Install Transmission daemon"""
    result = run_cmd(["apt-get", "install", "-y", "transmission-daemon"], timeout=120)
    if not result["success"]:
        raise HTTPException(status_code=500, detail=f"Install failed: {result.get('stderr')}")

    # Create directories
    DOWNLOAD_DIR.mkdir(parents=True, exist_ok=True)
    WATCH_DIR.mkdir(parents=True, exist_ok=True)

    # Stop daemon to modify config
    run_cmd(["systemctl", "stop", "transmission-daemon"])

    # Update config
    if TRANSMISSION_CONFIG.exists():
        with open(TRANSMISSION_CONFIG) as f:
            config = json.load(f)
    else:
        config = {}

    config.update({
        "download-dir": str(DOWNLOAD_DIR),
        "watch-dir": str(WATCH_DIR),
        "watch-dir-enabled": True,
        "rpc-enabled": True,
        "rpc-bind-address": "127.0.0.1",
        "rpc-port": 9091,
        "rpc-whitelist-enabled": False,
        "rpc-authentication-required": False,
        "speed-limit-down-enabled": False,
        "speed-limit-up-enabled": False
    })

    TRANSMISSION_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    with open(TRANSMISSION_CONFIG, "w") as f:
        json.dump(config, f, indent=2)

    # Fix permissions
    run_cmd(["chown", "-R", "debian-transmission:debian-transmission", str(DOWNLOAD_DIR)])
    run_cmd(["chown", "-R", "debian-transmission:debian-transmission", str(WATCH_DIR)])

    # Start daemon
    run_cmd(["systemctl", "enable", "transmission-daemon"])
    run_cmd(["systemctl", "start", "transmission-daemon"])

    return {"success": True, "message": "Transmission installed and configured"}


@app.post("/start")
async def start():
    """Start Transmission"""
    result = run_cmd(["systemctl", "start", "transmission-daemon"])
    if not result["success"]:
        raise HTTPException(status_code=500, detail=result.get("stderr", "Start failed"))
    return {"success": True}


@app.post("/stop")
async def stop():
    """Stop Transmission"""
    result = run_cmd(["systemctl", "stop", "transmission-daemon"])
    if not result["success"]:
        raise HTTPException(status_code=500, detail=result.get("stderr", "Stop failed"))
    return {"success": True}


@app.post("/restart")
async def restart():
    """Restart Transmission"""
    result = run_cmd(["systemctl", "restart", "transmission-daemon"])
    if not result["success"]:
        raise HTTPException(status_code=500, detail=result.get("stderr", "Restart failed"))
    return {"success": True}


@app.get("/torrents")
async def list_torrents():
    """List all torrents"""
    result = transmission_rpc("torrent-get", {
        "fields": ["id", "name", "status", "percentDone", "rateDownload", "rateUpload",
                   "totalSize", "downloadedEver", "uploadedEver", "eta", "error", "errorString"]
    })

    if result.get("result") != "success":
        return {"torrents": []}

    torrents = []
    for t in result.get("arguments", {}).get("torrents", []):
        status_map = {0: "stopped", 1: "queued", 2: "verifying", 3: "queued",
                      4: "downloading", 5: "queued", 6: "seeding"}
        torrents.append({
            "id": t.get("id"),
            "name": t.get("name"),
            "status": status_map.get(t.get("status", 0), "unknown"),
            "progress": round(t.get("percentDone", 0) * 100, 1),
            "download_speed": t.get("rateDownload", 0),
            "upload_speed": t.get("rateUpload", 0),
            "size": t.get("totalSize", 0),
            "downloaded": t.get("downloadedEver", 0),
            "uploaded": t.get("uploadedEver", 0),
            "eta": t.get("eta", -1),
            "error": t.get("errorString", "")
        })

    return {"torrents": torrents}


@app.post("/torrents")
async def add_torrent(url: Optional[str] = None, magnet: Optional[str] = None):
    """Add a torrent by URL or magnet link"""
    if not url and not magnet:
        raise HTTPException(status_code=400, detail="Provide url or magnet parameter")

    link = magnet or url
    result = transmission_rpc("torrent-add", {"filename": link})

    if result.get("result") == "success":
        added = result.get("arguments", {}).get("torrent-added", {})
        return {"success": True, "id": added.get("id"), "name": added.get("name")}
    else:
        raise HTTPException(status_code=500, detail=result.get("arguments", {}).get("result", "Add failed"))


@app.post("/torrents/upload")
async def upload_torrent(file: UploadFile = File(...)):
    """Upload a .torrent file"""
    if not file.filename.endswith(".torrent"):
        raise HTTPException(status_code=400, detail="File must be a .torrent file")

    content = await file.read()
    metainfo = base64.b64encode(content).decode()

    result = transmission_rpc("torrent-add", {"metainfo": metainfo})

    if result.get("result") == "success":
        added = result.get("arguments", {}).get("torrent-added", {})
        return {"success": True, "id": added.get("id"), "name": added.get("name")}
    else:
        raise HTTPException(status_code=500, detail="Upload failed")


@app.post("/torrents/{torrent_id}/start")
async def start_torrent(torrent_id: int):
    """Start a torrent"""
    result = transmission_rpc("torrent-start", {"ids": [torrent_id]})
    return {"success": result.get("result") == "success"}


@app.post("/torrents/{torrent_id}/stop")
async def stop_torrent(torrent_id: int):
    """Stop a torrent"""
    result = transmission_rpc("torrent-stop", {"ids": [torrent_id]})
    return {"success": result.get("result") == "success"}


@app.delete("/torrents/{torrent_id}")
async def delete_torrent(torrent_id: int, delete_data: bool = False):
    """Delete a torrent"""
    result = transmission_rpc("torrent-remove", {
        "ids": [torrent_id],
        "delete-local-data": delete_data
    })
    return {"success": result.get("result") == "success"}


@app.get("/config")
async def get_config():
    """Get Transmission configuration"""
    if not TRANSMISSION_CONFIG.exists():
        raise HTTPException(status_code=404, detail="Not configured")

    with open(TRANSMISSION_CONFIG) as f:
        config = json.load(f)

    return {
        "download_dir": config.get("download-dir"),
        "speed_limit_down": config.get("speed-limit-down", 0),
        "speed_limit_down_enabled": config.get("speed-limit-down-enabled", False),
        "speed_limit_up": config.get("speed-limit-up", 0),
        "speed_limit_up_enabled": config.get("speed-limit-up-enabled", False),
        "peer_limit": config.get("peer-limit-global", 200),
        "encryption": config.get("encryption", 1)
    }


@app.post("/config")
async def update_config(
    speed_limit_down: Optional[int] = None,
    speed_limit_up: Optional[int] = None,
    peer_limit: Optional[int] = None
):
    """Update Transmission configuration"""
    # Stop daemon
    run_cmd(["systemctl", "stop", "transmission-daemon"])

    if TRANSMISSION_CONFIG.exists():
        with open(TRANSMISSION_CONFIG) as f:
            config = json.load(f)
    else:
        config = {}

    if speed_limit_down is not None:
        config["speed-limit-down"] = speed_limit_down
        config["speed-limit-down-enabled"] = speed_limit_down > 0

    if speed_limit_up is not None:
        config["speed-limit-up"] = speed_limit_up
        config["speed-limit-up-enabled"] = speed_limit_up > 0

    if peer_limit is not None:
        config["peer-limit-global"] = peer_limit

    with open(TRANSMISSION_CONFIG, "w") as f:
        json.dump(config, f, indent=2)

    # Start daemon
    run_cmd(["systemctl", "start", "transmission-daemon"])

    return {"success": True, "message": "Config updated"}


@app.get("/downloads")
async def list_downloads():
    """List completed downloads"""
    files = []
    if DOWNLOAD_DIR.exists():
        for f in DOWNLOAD_DIR.iterdir():
            if f.is_file():
                files.append({
                    "name": f.name,
                    "size": f.stat().st_size,
                    "modified": f.stat().st_mtime
                })
            elif f.is_dir():
                # Get folder size
                total = sum(p.stat().st_size for p in f.rglob("*") if p.is_file())
                files.append({
                    "name": f.name,
                    "size": total,
                    "modified": f.stat().st_mtime,
                    "is_dir": True
                })

    return {"downloads": sorted(files, key=lambda x: x["modified"], reverse=True)}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
