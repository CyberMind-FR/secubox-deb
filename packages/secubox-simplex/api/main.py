#!/usr/bin/env python3
"""SecuBox SimpleX API - Private Messaging Server"""

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from typing import Optional
import subprocess
import os
import json
from pathlib import Path

app = FastAPI(title="SecuBox SimpleX API", version="1.0.0")

CONTAINER_NAME = "simplex"
DATA_DIR = Path("/var/lib/secubox/simplex")
LXC_ROOT = Path("/var/lib/lxc") / CONTAINER_NAME / "rootfs"
SMP_PORT = 5223
XFTP_PORT = 443


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


def lxc_exec(cmd: str, timeout: int = 30) -> dict:
    """Execute command inside LXC container"""
    return run_cmd(["lxc-attach", "-n", CONTAINER_NAME, "--", "bash", "-c", cmd], timeout)


def get_container_ip() -> Optional[str]:
    """Get container IP address"""
    result = run_cmd(["lxc-info", "-n", CONTAINER_NAME, "-iH"])
    if result["success"] and result["stdout"].strip():
        return result["stdout"].strip().split("\n")[0]
    return None


def container_exists() -> bool:
    """Check if container exists"""
    result = run_cmd(["lxc-info", "-n", CONTAINER_NAME])
    return result["success"]


def container_running() -> bool:
    """Check if container is running"""
    result = run_cmd(["lxc-info", "-n", CONTAINER_NAME, "-sH"])
    return result.get("stdout", "").strip() == "RUNNING"


@app.get("/health")
async def health():
    """Health check endpoint"""
    return {"status": "ok", "service": "simplex"}


@app.get("/status")
async def status():
    """Get SimpleX server status"""
    exists = container_exists()
    running = container_running() if exists else False
    ip = get_container_ip() if running else None

    smp_running = False
    xftp_running = False
    server_address = None

    if running:
        # Check SMP server
        result = lxc_exec("systemctl is-active smp-server 2>/dev/null || pgrep -x smp-server")
        smp_running = result.get("stdout", "").strip() in ["active", ""] or result["success"]

        # Check XFTP server
        result = lxc_exec("systemctl is-active xftp-server 2>/dev/null || pgrep -x xftp-server")
        xftp_running = result.get("stdout", "").strip() in ["active", ""] or result["success"]

        # Get server address
        result = lxc_exec("cat /etc/opt/simplex/smp-server.ini 2>/dev/null | grep 'SERVER_ADDRESS' | cut -d'=' -f2")
        if result["success"]:
            server_address = result["stdout"].strip()

    return {
        "container_exists": exists,
        "running": running,
        "container_ip": ip,
        "smp_running": smp_running,
        "xftp_running": xftp_running,
        "smp_port": SMP_PORT,
        "xftp_port": XFTP_PORT,
        "server_address": server_address
    }


@app.post("/install")
async def install(server_address: str = ""):
    """Install SimpleX SMP server in LXC container"""
    if container_exists():
        raise HTTPException(status_code=400, detail="Container already exists")

    # Create data directory
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    # Create container
    result = run_cmd([
        "lxc-create", "-n", CONTAINER_NAME, "-t", "download",
        "--", "-d", "debian", "-r", "bookworm", "-a", "amd64"
    ], timeout=300)

    if not result["success"]:
        raise HTTPException(status_code=500, detail=f"Container creation failed: {result.get('stderr')}")

    # Start container
    run_cmd(["lxc-start", "-n", CONTAINER_NAME])

    # Wait for network
    import time
    for _ in range(30):
        if get_container_ip():
            break
        time.sleep(1)

    ip = get_container_ip()
    if not server_address:
        server_address = ip

    # Install dependencies and SimpleX
    lxc_exec("apt-get update && apt-get install -y curl ca-certificates", timeout=120)

    # Download and install SimpleX SMP server
    lxc_exec("""
curl -L -o /tmp/smp-server.deb https://github.com/simplex-chat/simplexmq/releases/latest/download/smp-server-ubuntu-22_04-x86-64.deb 2>/dev/null || \
curl -L -o /tmp/smp-server.deb https://github.com/simplex-chat/simplexmq/releases/download/v5.8.0/smp-server-ubuntu-22_04-x86-64.deb
dpkg -i /tmp/smp-server.deb || apt-get install -f -y
""", timeout=180)

    # Initialize SMP server
    lxc_exec(f"""
mkdir -p /etc/opt/simplex /var/opt/simplex
smp-server init -y --ip={server_address} || true
systemctl enable smp-server 2>/dev/null || true
systemctl start smp-server 2>/dev/null || true
""", timeout=60)

    # Get server fingerprint
    result = lxc_exec("cat /etc/opt/simplex/fingerprint 2>/dev/null || echo ''")
    fingerprint = result.get("stdout", "").strip()

    return {
        "success": True,
        "message": "SimpleX SMP server installed",
        "container_ip": ip,
        "server_address": server_address,
        "fingerprint": fingerprint,
        "smp_port": SMP_PORT
    }


@app.post("/start")
async def start():
    """Start SimpleX container"""
    if not container_exists():
        raise HTTPException(status_code=404, detail="Container not found. Install first.")

    result = run_cmd(["lxc-start", "-n", CONTAINER_NAME])
    if not result["success"]:
        raise HTTPException(status_code=500, detail=result.get("stderr", "Start failed"))

    import time
    time.sleep(3)

    # Start services
    lxc_exec("systemctl start smp-server 2>/dev/null || true")

    return {"success": True, "container_ip": get_container_ip()}


@app.post("/stop")
async def stop():
    """Stop SimpleX container"""
    result = run_cmd(["lxc-stop", "-n", CONTAINER_NAME])
    if not result["success"]:
        raise HTTPException(status_code=500, detail=result.get("stderr", "Stop failed"))
    return {"success": True}


@app.post("/restart")
async def restart():
    """Restart SimpleX container"""
    run_cmd(["lxc-stop", "-n", CONTAINER_NAME])
    import time
    time.sleep(2)
    run_cmd(["lxc-start", "-n", CONTAINER_NAME])
    time.sleep(3)
    lxc_exec("systemctl restart smp-server 2>/dev/null || true")
    return {"success": True, "container_ip": get_container_ip()}


@app.delete("/container")
async def delete_container():
    """Delete SimpleX container"""
    if container_running():
        run_cmd(["lxc-stop", "-n", CONTAINER_NAME])

    result = run_cmd(["lxc-destroy", "-n", CONTAINER_NAME])
    if not result["success"]:
        raise HTTPException(status_code=500, detail=result.get("stderr", "Destroy failed"))

    return {"success": True, "message": "Container deleted"}


@app.get("/fingerprint")
async def get_fingerprint():
    """Get server fingerprint for client connection"""
    if not container_running():
        raise HTTPException(status_code=400, detail="Container not running")

    result = lxc_exec("cat /etc/opt/simplex/fingerprint 2>/dev/null")
    if result["success"] and result["stdout"].strip():
        return {"fingerprint": result["stdout"].strip()}

    raise HTTPException(status_code=404, detail="Fingerprint not found")


@app.get("/connection-string")
async def get_connection_string():
    """Get SMP server connection string for clients"""
    if not container_running():
        raise HTTPException(status_code=400, detail="Container not running")

    # Get fingerprint
    fp_result = lxc_exec("cat /etc/opt/simplex/fingerprint 2>/dev/null")
    fingerprint = fp_result.get("stdout", "").strip()

    # Get server address
    addr_result = lxc_exec("cat /etc/opt/simplex/smp-server.ini 2>/dev/null | grep 'SERVER_ADDRESS' | cut -d'=' -f2")
    address = addr_result.get("stdout", "").strip() or get_container_ip()

    if fingerprint and address:
        connection_string = f"smp://{fingerprint}@{address}"
        return {
            "connection_string": connection_string,
            "fingerprint": fingerprint,
            "address": address,
            "port": SMP_PORT
        }

    raise HTTPException(status_code=404, detail="Could not generate connection string")


@app.get("/config")
async def get_config():
    """Get SMP server configuration"""
    if not container_running():
        raise HTTPException(status_code=400, detail="Container not running")

    result = lxc_exec("cat /etc/opt/simplex/smp-server.ini 2>/dev/null")
    if result["success"]:
        config = {}
        for line in result["stdout"].split("\n"):
            if "=" in line and not line.strip().startswith("#"):
                key, _, value = line.partition("=")
                config[key.strip()] = value.strip()
        return {"config": config}

    return {"config": {}}


@app.get("/logs")
async def get_logs(lines: int = 100):
    """Get SMP server logs"""
    if not container_running():
        return {"logs": []}

    result = lxc_exec(f"journalctl -u smp-server -n {lines} --no-pager 2>/dev/null || tail -n {lines} /var/log/smp-server.log 2>/dev/null || echo 'No logs'")
    if result["success"]:
        return {"logs": result["stdout"].split("\n")}
    return {"logs": []}


@app.get("/stats")
async def get_stats():
    """Get server statistics"""
    if not container_running():
        return {"stats": {}}

    # Get basic stats
    result = lxc_exec("ls /var/opt/simplex/smp-server/ 2>/dev/null | wc -l")
    queue_count = int(result.get("stdout", "0").strip()) if result["success"] else 0

    result = lxc_exec("du -sh /var/opt/simplex/ 2>/dev/null | cut -f1")
    storage_used = result.get("stdout", "0").strip() if result["success"] else "0"

    return {
        "stats": {
            "queues": queue_count,
            "storage_used": storage_used
        }
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
