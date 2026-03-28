#!/usr/bin/env python3
"""SecuBox VoIP API - Asterisk PBX Management"""

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional, List
import subprocess
import os
import json
from pathlib import Path

app = FastAPI(title="SecuBox VoIP API", version="1.0.0")

ASTERISK_CONFIG = Path("/etc/asterisk")
SIP_CONF = ASTERISK_CONFIG / "sip.conf"
EXTENSIONS_CONF = ASTERISK_CONFIG / "extensions.conf"
VOICEMAIL_CONF = ASTERISK_CONFIG / "voicemail.conf"
DATA_DIR = Path("/var/lib/secubox/voip")


class Extension(BaseModel):
    number: str
    name: str
    secret: str
    context: Optional[str] = "internal"
    voicemail: Optional[bool] = False


class Trunk(BaseModel):
    name: str
    host: str
    username: str
    secret: str
    context: Optional[str] = "from-trunk"


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


def asterisk_cmd(cmd: str) -> dict:
    """Run Asterisk CLI command"""
    return run_cmd(["asterisk", "-rx", cmd])


@app.get("/health")
async def health():
    """Health check endpoint"""
    return {"status": "ok", "service": "voip"}


@app.get("/status")
async def status():
    """Get Asterisk status"""
    # Check if asterisk is running
    result = run_cmd(["systemctl", "is-active", "asterisk"])
    running = result.get("stdout", "").strip() == "active"

    # Check if installed
    installed = Path("/usr/sbin/asterisk").exists()

    stats = {}
    if running:
        # Get core status
        result = asterisk_cmd("core show channels count")
        if result["success"]:
            lines = result["stdout"].strip().split("\n")
            for line in lines:
                if "active channel" in line:
                    stats["active_channels"] = int(line.split()[0])
                elif "active call" in line:
                    stats["active_calls"] = int(line.split()[0])

        # Get SIP peers count
        result = asterisk_cmd("sip show peers")
        if result["success"]:
            lines = result["stdout"].strip().split("\n")
            stats["sip_peers"] = max(0, len(lines) - 2)  # Exclude header lines

    return {
        "installed": installed,
        "running": running,
        "active_channels": stats.get("active_channels", 0),
        "active_calls": stats.get("active_calls", 0),
        "sip_peers": stats.get("sip_peers", 0),
        "sip_port": 5060
    }


@app.post("/install")
async def install():
    """Install Asterisk"""
    result = run_cmd(["apt-get", "install", "-y", "asterisk"], timeout=300)
    if not result["success"]:
        raise HTTPException(status_code=500, detail=f"Install failed: {result.get('stderr')}")

    # Create data directory
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    # Enable and start
    run_cmd(["systemctl", "enable", "asterisk"])
    run_cmd(["systemctl", "start", "asterisk"])

    return {"success": True, "message": "Asterisk installed"}


@app.post("/start")
async def start():
    """Start Asterisk"""
    result = run_cmd(["systemctl", "start", "asterisk"])
    if not result["success"]:
        raise HTTPException(status_code=500, detail=result.get("stderr", "Start failed"))
    return {"success": True}


@app.post("/stop")
async def stop():
    """Stop Asterisk"""
    result = run_cmd(["systemctl", "stop", "asterisk"])
    if not result["success"]:
        raise HTTPException(status_code=500, detail=result.get("stderr", "Stop failed"))
    return {"success": True}


@app.post("/restart")
async def restart():
    """Restart Asterisk"""
    result = run_cmd(["systemctl", "restart", "asterisk"])
    if not result["success"]:
        raise HTTPException(status_code=500, detail=result.get("stderr", "Restart failed"))
    return {"success": True}


@app.post("/reload")
async def reload():
    """Reload Asterisk configuration"""
    result = asterisk_cmd("core reload")
    if not result["success"]:
        raise HTTPException(status_code=500, detail="Reload failed")
    return {"success": True}


@app.get("/extensions")
async def list_extensions():
    """List SIP extensions"""
    if not SIP_CONF.exists():
        return {"extensions": []}

    extensions = []
    current = None

    with open(SIP_CONF) as f:
        for line in f:
            line = line.strip()
            if line.startswith("[") and line.endswith("]"):
                name = line[1:-1]
                if name not in ["general", "authentication"]:
                    if current:
                        extensions.append(current)
                    current = {"number": name, "name": "", "context": "internal"}
            elif current and "=" in line:
                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip()
                if key == "callerid":
                    current["name"] = value.split("<")[0].strip().strip('"')
                elif key == "context":
                    current["context"] = value
                elif key == "type":
                    current["type"] = value

        if current:
            extensions.append(current)

    return {"extensions": extensions}


@app.post("/extensions")
async def create_extension(ext: Extension):
    """Create a new SIP extension"""
    if not SIP_CONF.exists():
        raise HTTPException(status_code=404, detail="Asterisk not configured")

    # Read current config
    with open(SIP_CONF) as f:
        content = f.read()

    # Check if extension exists
    if f"[{ext.number}]" in content:
        raise HTTPException(status_code=400, detail=f"Extension {ext.number} already exists")

    # Add extension
    ext_config = f"""
[{ext.number}]
type=friend
context={ext.context}
host=dynamic
secret={ext.secret}
callerid="{ext.name}" <{ext.number}>
disallow=all
allow=ulaw
allow=alaw
allow=gsm
"""

    with open(SIP_CONF, "a") as f:
        f.write(ext_config)

    # Reload
    asterisk_cmd("sip reload")

    return {"success": True, "extension": ext.number}


@app.delete("/extensions/{number}")
async def delete_extension(number: str):
    """Delete a SIP extension"""
    if not SIP_CONF.exists():
        raise HTTPException(status_code=404, detail="Asterisk not configured")

    with open(SIP_CONF) as f:
        lines = f.readlines()

    # Find and remove extension block
    new_lines = []
    skip = False
    for line in lines:
        if line.strip().startswith(f"[{number}]"):
            skip = True
            continue
        elif line.strip().startswith("[") and skip:
            skip = False
        if not skip:
            new_lines.append(line)

    with open(SIP_CONF, "w") as f:
        f.writelines(new_lines)

    asterisk_cmd("sip reload")
    return {"success": True}


@app.get("/peers")
async def list_peers():
    """List SIP peers and their status"""
    result = asterisk_cmd("sip show peers")
    if not result["success"]:
        return {"peers": []}

    peers = []
    lines = result["stdout"].strip().split("\n")
    for line in lines[1:]:  # Skip header
        if "/" in line:
            parts = line.split()
            if len(parts) >= 5:
                peers.append({
                    "name": parts[0].split("/")[0],
                    "host": parts[1],
                    "dyn": parts[2] == "D",
                    "status": parts[-1] if parts[-1] in ["OK", "UNREACHABLE", "UNKNOWN"] else "UNKNOWN"
                })

    return {"peers": peers}


@app.get("/channels")
async def list_channels():
    """List active channels"""
    result = asterisk_cmd("core show channels")
    if not result["success"]:
        return {"channels": []}

    channels = []
    lines = result["stdout"].strip().split("\n")
    for line in lines[1:-1]:  # Skip header and footer
        if "SIP" in line or "PJSIP" in line:
            parts = line.split()
            if len(parts) >= 4:
                channels.append({
                    "channel": parts[0],
                    "context": parts[1],
                    "state": parts[-1]
                })

    return {"channels": channels}


@app.get("/calls")
async def list_calls():
    """List active calls"""
    result = asterisk_cmd("core show calls")
    if not result["success"]:
        return {"calls": [], "count": 0}

    lines = result["stdout"].strip().split("\n")
    count = 0
    for line in lines:
        if "active call" in line:
            count = int(line.split()[0])

    return {"calls": [], "count": count}


@app.get("/trunks")
async def list_trunks():
    """List SIP trunks"""
    if not SIP_CONF.exists():
        return {"trunks": []}

    trunks = []
    current = None
    is_trunk = False

    with open(SIP_CONF) as f:
        for line in f:
            line = line.strip()
            if line.startswith("[") and line.endswith("]"):
                if current and is_trunk:
                    trunks.append(current)
                name = line[1:-1]
                current = {"name": name, "host": "", "username": ""}
                is_trunk = False
            elif current and "=" in line:
                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip()
                if key == "type" and value == "peer":
                    is_trunk = True
                elif key == "host" and value != "dynamic":
                    current["host"] = value
                    is_trunk = True
                elif key == "username":
                    current["username"] = value

        if current and is_trunk:
            trunks.append(current)

    return {"trunks": trunks}


@app.get("/logs")
async def get_logs(lines: int = 100):
    """Get Asterisk logs"""
    log_files = [
        Path("/var/log/asterisk/messages"),
        Path("/var/log/asterisk/full")
    ]

    for log_file in log_files:
        if log_file.exists():
            result = run_cmd(["tail", "-n", str(lines), str(log_file)])
            if result["success"]:
                return {"logs": result["stdout"].split("\n")}

    return {"logs": []}


@app.get("/config")
async def get_config():
    """Get basic Asterisk configuration"""
    config = {
        "sip_port": 5060,
        "rtp_start": 10000,
        "rtp_end": 20000
    }

    # Try to read from sip.conf
    if SIP_CONF.exists():
        with open(SIP_CONF) as f:
            for line in f:
                if line.strip().startswith("bindport"):
                    config["sip_port"] = int(line.split("=")[1].strip())

    return {"config": config}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
