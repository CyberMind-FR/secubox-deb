"""
SecuBox Watchdog API
Service and container health monitoring with auto-recovery
"""

from fastapi import FastAPI, Depends, HTTPException, Query
from pydantic import BaseModel
from typing import Optional, List
from pathlib import Path
import subprocess
import os
import time
import json
import httpx

# Import shared auth
import sys
sys.path.insert(0, '/usr/lib/secubox/core')
try:
    from secubox_core.auth import require_jwt
except ImportError:
    async def require_jwt():
        return {"sub": "dev"}

app = FastAPI(title="SecuBox Watchdog API", version="1.0.0")

# Configuration
LXC_PATH = Path("/srv/lxc")
LOG_FILE = Path("/var/log/secubox/watchdog.log")
CONFIG_FILE = Path("/etc/secubox/watchdog.json")
ALERT_STATE_DIR = Path("/tmp/watchdog")

# Default monitored items
DEFAULT_CONFIG = {
    "enabled": True,
    "interval": 60,
    "alert_cooldown": 300,
    "containers": [
        {"name": "mailserver", "enabled": True, "critical": True},
        {"name": "roundcube", "enabled": True, "critical": False},
        {"name": "nextcloud", "enabled": True, "critical": False},
        {"name": "gitea", "enabled": True, "critical": False}
    ],
    "services": [
        {"name": "nginx", "process": "nginx", "enabled": True, "critical": True},
        {"name": "haproxy", "process": "haproxy", "enabled": True, "critical": True},
        {"name": "crowdsec", "process": "crowdsec", "enabled": True, "critical": False},
        {"name": "nftables", "process": "nft", "enabled": False, "critical": True}
    ],
    "endpoints": [
        {"name": "Portal", "host": "localhost", "path": "/portal/", "enabled": True},
        {"name": "Hub API", "host": "localhost", "path": "/api/v1/hub/status", "enabled": True}
    ]
}


# Models
class ContainerRestart(BaseModel):
    name: str


class ServiceRestart(BaseModel):
    name: str


class LogRequest(BaseModel):
    lines: int = 50


# Helpers
def run_cmd(cmd: list, timeout: int = 30) -> tuple:
    """Run command and return (success, stdout, stderr)"""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.returncode == 0, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return False, "", "Command timed out"
    except Exception as e:
        return False, "", str(e)


def load_config() -> dict:
    """Load watchdog configuration"""
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text())
        except:
            pass
    return DEFAULT_CONFIG.copy()


def save_config(config: dict):
    """Save watchdog configuration"""
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(config, indent=2))


def log_event(message: str):
    """Log an event to the watchdog log"""
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"[{timestamp}] {message}\n")


def lxc_running(name: str) -> tuple:
    """Check if LXC container is running, returns (running, pid)"""
    success, out, _ = run_cmd(["lxc-info", "-P", str(LXC_PATH), "-n", name, "-s", "-p"])
    running = success and "RUNNING" in out
    pid = 0
    if running:
        for line in out.split('\n'):
            if 'PID:' in line:
                try:
                    pid = int(line.split(':')[1].strip())
                except:
                    pass
    return running, pid


def service_running(process: str) -> tuple:
    """Check if a service process is running, returns (running, pid)"""
    success, out, _ = run_cmd(["pgrep", "-x", process])
    if success and out.strip():
        try:
            pid = int(out.strip().split('\n')[0])
            return True, pid
        except:
            pass
    # Try with -f for full command match
    success, out, _ = run_cmd(["pgrep", "-f", process])
    if success and out.strip():
        try:
            pid = int(out.strip().split('\n')[0])
            return True, pid
        except:
            pass
    return False, 0


async def check_endpoint(host: str, path: str = "/", expected_codes: list = [200]) -> tuple:
    """Check HTTP endpoint health, returns (healthy, code)"""
    try:
        async with httpx.AsyncClient(verify=False, timeout=5.0) as client:
            url = f"https://{host}{path}"
            resp = await client.get(url)
            return resp.status_code in expected_codes, resp.status_code
    except:
        pass
    try:
        async with httpx.AsyncClient(verify=False, timeout=5.0) as client:
            url = f"http://{host}{path}"
            resp = await client.get(url)
            return resp.status_code in expected_codes, resp.status_code
    except:
        return False, 0


# Public endpoints
@app.get("/status")
async def get_status():
    """Get full watchdog status"""
    config = load_config()

    # Check if watchdog daemon is running
    daemon_running, _ = service_running("watchdogctl")

    # Container status
    containers = []
    for c in config.get("containers", []):
        if not c.get("enabled", True):
            continue
        running, pid = lxc_running(c["name"])
        containers.append({
            "name": c["name"],
            "state": "running" if running else "stopped",
            "pid": pid,
            "critical": c.get("critical", False)
        })

    # Service status
    services = []
    for s in config.get("services", []):
        if not s.get("enabled", True):
            continue
        running, pid = service_running(s["process"])
        services.append({
            "name": s["name"],
            "process": s["process"],
            "state": "running" if running else "stopped",
            "pid": pid,
            "critical": s.get("critical", False)
        })

    # Endpoint status
    endpoints = []
    for e in config.get("endpoints", []):
        if not e.get("enabled", True):
            continue
        healthy, code = await check_endpoint(e.get("host", "localhost"), e.get("path", "/"))
        endpoints.append({
            "name": e["name"],
            "host": e.get("host", "localhost"),
            "path": e.get("path", "/"),
            "code": code,
            "healthy": healthy
        })

    return {
        "enabled": config.get("enabled", True),
        "running": daemon_running,
        "interval": config.get("interval", 60),
        "containers": containers,
        "services": services,
        "endpoints": endpoints
    }


@app.get("/containers")
async def get_containers():
    """Get detailed container list"""
    config = load_config()
    containers = []

    for c in config.get("containers", []):
        running, pid = lxc_running(c["name"])
        containers.append({
            "name": c["name"],
            "state": "running" if running else "stopped",
            "pid": pid,
            "enabled": c.get("enabled", True),
            "critical": c.get("critical", False)
        })

    # Also check for containers not in config
    if LXC_PATH.exists():
        for container_dir in LXC_PATH.iterdir():
            if not container_dir.is_dir():
                continue
            if not (container_dir / "config").exists():
                continue
            name = container_dir.name
            if not any(c["name"] == name for c in containers):
                running, pid = lxc_running(name)
                containers.append({
                    "name": name,
                    "state": "running" if running else "stopped",
                    "pid": pid,
                    "enabled": False,
                    "critical": False
                })

    return {"containers": containers}


@app.get("/services")
async def get_services():
    """Get detailed service list"""
    config = load_config()
    services = []

    for s in config.get("services", []):
        running, pid = service_running(s["process"])
        services.append({
            "name": s["name"],
            "process": s["process"],
            "state": "running" if running else "stopped",
            "pid": pid,
            "enabled": s.get("enabled", True),
            "critical": s.get("critical", False)
        })

    return {"services": services}


@app.get("/endpoints")
async def get_endpoints():
    """Get detailed endpoint list"""
    config = load_config()
    endpoints = []

    for e in config.get("endpoints", []):
        healthy, code = await check_endpoint(e.get("host", "localhost"), e.get("path", "/"))
        endpoints.append({
            "name": e["name"],
            "host": e.get("host", "localhost"),
            "path": e.get("path", "/"),
            "code": code,
            "healthy": healthy,
            "enabled": e.get("enabled", True)
        })

    return {"endpoints": endpoints}


@app.get("/logs")
async def get_logs(lines: int = Query(50, ge=1, le=500)):
    """Get watchdog logs"""
    log_lines = []
    total = 0

    if LOG_FILE.exists():
        all_lines = LOG_FILE.read_text().strip().split('\n')
        total = len(all_lines)
        log_lines = all_lines[-lines:] if lines < total else all_lines

    return {
        "lines": log_lines,
        "total": total
    }


@app.get("/config")
async def get_config():
    """Get watchdog configuration"""
    return load_config()


# Protected endpoints
@app.post("/container/restart")
async def restart_container(req: ContainerRestart, user: dict = Depends(require_jwt)):
    """Restart a container"""
    container_dir = LXC_PATH / req.name

    if not container_dir.exists() or not (container_dir / "config").exists():
        raise HTTPException(status_code=404, detail="Container not found")

    log_event(f"Manual restart requested for container: {req.name}")

    # Stop container
    run_cmd(["lxc-stop", "-P", str(LXC_PATH), "-n", req.name], timeout=30)
    time.sleep(1)

    # Start container
    success, out, err = run_cmd(["lxc-start", "-P", str(LXC_PATH), "-n", req.name], timeout=30)
    time.sleep(2)

    running, pid = lxc_running(req.name)

    if running:
        log_event(f"Container {req.name} restarted successfully (PID: {pid})")
        return {"success": True, "state": "running", "pid": pid}
    else:
        log_event(f"Container {req.name} failed to start: {err}")
        return {"success": False, "error": "Container failed to start", "state": "stopped"}


@app.post("/service/restart")
async def restart_service(req: ServiceRestart, user: dict = Depends(require_jwt)):
    """Restart a service"""
    config = load_config()

    # Find service in config
    service = None
    for s in config.get("services", []):
        if s["name"] == req.name:
            service = s
            break

    if not service:
        raise HTTPException(status_code=404, detail="Service not found in configuration")

    log_event(f"Manual restart requested for service: {req.name}")

    # Try systemctl restart
    success, out, err = run_cmd(["systemctl", "restart", req.name], timeout=30)
    time.sleep(2)

    running, pid = service_running(service["process"])

    if running:
        log_event(f"Service {req.name} restarted successfully (PID: {pid})")
        return {"success": True, "state": "running", "pid": pid}
    else:
        log_event(f"Service {req.name} failed to start")
        return {"success": False, "error": "Service failed to start", "state": "stopped"}


@app.post("/check")
async def run_check(user: dict = Depends(require_jwt)):
    """Run a manual health check"""
    log_event("Manual health check triggered")

    status = await get_status()
    issues = []

    # Check containers
    for c in status["containers"]:
        if c["state"] != "running":
            issues.append(f"Container {c['name']} is {c['state']}")

    # Check services
    for s in status["services"]:
        if s["state"] != "running":
            issues.append(f"Service {s['name']} is {s['state']}")

    # Check endpoints
    for e in status["endpoints"]:
        if not e["healthy"]:
            issues.append(f"Endpoint {e['name']} returned {e['code']}")

    return {
        "success": True,
        "issues": issues,
        "message": f"Health check completed, {len(issues)} issues found"
    }


@app.post("/logs/clear")
async def clear_logs(user: dict = Depends(require_jwt)):
    """Clear watchdog logs"""
    if LOG_FILE.exists():
        LOG_FILE.write_text("")

    # Clear alert states
    ALERT_STATE_DIR.mkdir(parents=True, exist_ok=True)
    for f in ALERT_STATE_DIR.glob("*.alert"):
        f.unlink()

    log_event("Logs cleared")
    return {"success": True}


@app.post("/config")
async def update_config(config: dict, user: dict = Depends(require_jwt)):
    """Update watchdog configuration"""
    save_config(config)
    log_event("Configuration updated")
    return {"success": True}


@app.get("/info")
async def get_info():
    """Get module info"""
    return {
        "module": "secubox-watchdog",
        "version": "1.0.0",
        "description": "Service and container health monitoring"
    }
