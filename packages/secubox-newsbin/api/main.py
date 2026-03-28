#!/usr/bin/env python3
"""SecuBox Newsbin API - RSS News Aggregator with Miniflux"""

from fastapi import FastAPI, HTTPException, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional, List
import subprocess
import os
import json
from pathlib import Path

app = FastAPI(title="SecuBox Newsbin API", version="1.0.0")

CONTAINER_NAME = "newsbin"
DATA_DIR = Path("/var/lib/secubox/newsbin")
LXC_ROOT = Path("/var/lib/lxc") / CONTAINER_NAME / "rootfs"


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
    return {"status": "ok", "service": "newsbin"}


@app.get("/status")
async def status():
    """Get Newsbin status"""
    exists = container_exists()
    running = container_running() if exists else False
    ip = get_container_ip() if running else None

    stats = {}
    if running:
        # Get feed/entry counts from Miniflux
        result = lxc_exec("miniflux -info 2>/dev/null || echo '{}'")
        try:
            if result["success"]:
                # Parse miniflux stats output
                lines = result["stdout"].strip().split("\n")
                for line in lines:
                    if "feeds:" in line.lower():
                        stats["feeds"] = int(line.split(":")[-1].strip())
                    elif "entries:" in line.lower():
                        stats["entries"] = int(line.split(":")[-1].strip())
        except:
            pass

    return {
        "container_exists": exists,
        "running": running,
        "container_ip": ip,
        "feeds": stats.get("feeds", 0),
        "entries": stats.get("entries", 0),
        "miniflux_port": 8080 if running else None
    }


@app.post("/install")
async def install(admin_user: str = "admin", admin_pass: str = "secubox"):
    """Install Newsbin with Miniflux in LXC container"""
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

    # Install dependencies
    lxc_exec("apt-get update && apt-get install -y postgresql miniflux ca-certificates", timeout=300)

    # Configure PostgreSQL
    lxc_exec("systemctl enable postgresql && systemctl start postgresql")
    lxc_exec("su - postgres -c \"createuser -d miniflux 2>/dev/null || true\"")
    lxc_exec("su - postgres -c \"createdb -O miniflux miniflux 2>/dev/null || true\"")
    lxc_exec("su - postgres -c \"psql -c \\\"ALTER USER miniflux WITH PASSWORD 'miniflux';\\\"\"")

    # Configure Miniflux
    lxc_exec(f"""cat > /etc/miniflux.conf << 'CONF'
DATABASE_URL=postgres://miniflux:miniflux@localhost/miniflux?sslmode=disable
LISTEN_ADDR=0.0.0.0:8080
RUN_MIGRATIONS=1
CREATE_ADMIN=1
ADMIN_USERNAME={admin_user}
ADMIN_PASSWORD={admin_pass}
CONF
""")

    # Run migrations and start
    lxc_exec("miniflux -migrate", timeout=60)
    lxc_exec("systemctl enable miniflux && systemctl start miniflux")

    return {
        "success": True,
        "message": f"Miniflux installed. Admin: {admin_user}",
        "container_ip": get_container_ip()
    }


@app.post("/start")
async def start():
    """Start Newsbin container"""
    if not container_exists():
        raise HTTPException(status_code=404, detail="Container not found. Install first.")

    result = run_cmd(["lxc-start", "-n", CONTAINER_NAME])
    if not result["success"]:
        raise HTTPException(status_code=500, detail=result.get("stderr", "Start failed"))

    import time
    time.sleep(3)
    return {"success": True, "container_ip": get_container_ip()}


@app.post("/stop")
async def stop():
    """Stop Newsbin container"""
    result = run_cmd(["lxc-stop", "-n", CONTAINER_NAME])
    if not result["success"]:
        raise HTTPException(status_code=500, detail=result.get("stderr", "Stop failed"))
    return {"success": True}


@app.post("/restart")
async def restart():
    """Restart Newsbin container"""
    run_cmd(["lxc-stop", "-n", CONTAINER_NAME])
    import time
    time.sleep(2)
    run_cmd(["lxc-start", "-n", CONTAINER_NAME])
    time.sleep(3)
    return {"success": True, "container_ip": get_container_ip()}


@app.delete("/container")
async def delete_container():
    """Delete Newsbin container"""
    if container_running():
        run_cmd(["lxc-stop", "-n", CONTAINER_NAME])

    result = run_cmd(["lxc-destroy", "-n", CONTAINER_NAME])
    if not result["success"]:
        raise HTTPException(status_code=500, detail=result.get("stderr", "Destroy failed"))

    return {"success": True, "message": "Container deleted"}


@app.get("/feeds")
async def list_feeds():
    """List RSS feeds"""
    if not container_running():
        return {"feeds": [], "error": "Container not running"}

    # Query Miniflux API
    result = lxc_exec("curl -s http://localhost:8080/v1/feeds -u admin:secubox 2>/dev/null || echo '[]'")
    try:
        feeds = json.loads(result.get("stdout", "[]"))
        return {"feeds": feeds}
    except:
        return {"feeds": []}


@app.post("/feeds")
async def add_feed(url: str, category: Optional[str] = None):
    """Add a new RSS feed"""
    if not container_running():
        raise HTTPException(status_code=400, detail="Container not running")

    body = {"feed_url": url}
    if category:
        body["category_id"] = category

    result = lxc_exec(f"curl -s -X POST http://localhost:8080/v1/feeds -u admin:secubox -H 'Content-Type: application/json' -d '{json.dumps(body)}'")

    try:
        response = json.loads(result.get("stdout", "{}"))
        return response
    except:
        raise HTTPException(status_code=500, detail="Failed to add feed")


@app.delete("/feeds/{feed_id}")
async def delete_feed(feed_id: int):
    """Delete a feed"""
    if not container_running():
        raise HTTPException(status_code=400, detail="Container not running")

    result = lxc_exec(f"curl -s -X DELETE http://localhost:8080/v1/feeds/{feed_id} -u admin:secubox")
    return {"success": True}


@app.get("/entries")
async def list_entries(limit: int = 50, unread: bool = True):
    """List feed entries"""
    if not container_running():
        return {"entries": []}

    status_filter = "status=unread" if unread else ""
    result = lxc_exec(f"curl -s 'http://localhost:8080/v1/entries?limit={limit}&{status_filter}' -u admin:secubox 2>/dev/null || echo '{{\"entries\":[]}}'")

    try:
        data = json.loads(result.get("stdout", '{"entries":[]}'))
        return data
    except:
        return {"entries": []}


@app.get("/logs")
async def get_logs(lines: int = 100):
    """Get Miniflux logs"""
    if not container_running():
        return {"logs": []}

    result = lxc_exec(f"journalctl -u miniflux -n {lines} --no-pager 2>/dev/null || echo ''")
    if result["success"]:
        return {"logs": result["stdout"].split("\n")}
    return {"logs": []}


@app.post("/refresh")
async def refresh_feeds():
    """Force refresh all feeds"""
    if not container_running():
        raise HTTPException(status_code=400, detail="Container not running")

    lxc_exec("curl -s -X PUT http://localhost:8080/v1/feeds/refresh -u admin:secubox")
    return {"success": True, "message": "Feed refresh triggered"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
