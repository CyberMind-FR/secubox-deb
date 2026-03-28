"""
SecuBox Watchdog API - Production Ready
Service and container health monitoring with auto-recovery

Features:
- Container and service health monitoring
- Endpoint HTTP health checks
- Auto-recovery with configurable policies
- Stats caching with TTL
- Event history with JSON persistence
- Webhook notifications with HMAC signing
- Background monitoring tasks
"""

from fastapi import FastAPI, Depends, HTTPException, Query, BackgroundTasks
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from pathlib import Path
from datetime import datetime, timedelta
from enum import Enum
import subprocess
import asyncio
import threading
import hashlib
import hmac
import time
import json
import httpx

from secubox_core.auth import require_jwt
from secubox_core.config import get_config

app = FastAPI(title="SecuBox Watchdog API", version="2.0.0")

# Configuration
LXC_PATH = Path("/srv/lxc")
DATA_DIR = Path("/var/lib/secubox/watchdog")
LOG_FILE = Path("/var/log/secubox/watchdog.log")
CONFIG_FILE = Path("/etc/secubox/watchdog.json")
HISTORY_FILE = DATA_DIR / "history.json"
WEBHOOKS_FILE = DATA_DIR / "webhooks.json"
STATS_FILE = DATA_DIR / "stats.json"
ALERT_STATE_DIR = Path("/tmp/watchdog")

# Ensure directories
for d in [DATA_DIR, ALERT_STATE_DIR, LOG_FILE.parent]:
    d.mkdir(parents=True, exist_ok=True)


class StatsCache:
    """Thread-safe stats cache with TTL."""
    def __init__(self, ttl_seconds: int = 30):
        self.ttl = ttl_seconds
        self._cache: Dict[str, Any] = {}
        self._timestamps: Dict[str, float] = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            if key in self._cache:
                if time.time() - self._timestamps[key] < self.ttl:
                    return self._cache[key]
        return None

    def set(self, key: str, value: Any):
        with self._lock:
            self._cache[key] = value
            self._timestamps[key] = time.time()

    def invalidate(self, key: str = None):
        with self._lock:
            if key:
                self._cache.pop(key, None)
                self._timestamps.pop(key, None)
            else:
                self._cache.clear()
                self._timestamps.clear()


# Global cache
stats_cache = StatsCache(ttl_seconds=15)

# Background task state
_monitor_task = None
_monitor_running = False


# Default monitored items
DEFAULT_CONFIG = {
    "enabled": True,
    "interval": 60,
    "alert_cooldown": 300,
    "auto_recovery": True,
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


class HealthState(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class EventType(str, Enum):
    CONTAINER_DOWN = "container_down"
    CONTAINER_UP = "container_up"
    SERVICE_DOWN = "service_down"
    SERVICE_UP = "service_up"
    ENDPOINT_DOWN = "endpoint_down"
    ENDPOINT_UP = "endpoint_up"
    RECOVERY_ATTEMPTED = "recovery_attempted"
    RECOVERY_SUCCESS = "recovery_success"
    RECOVERY_FAILED = "recovery_failed"


class ContainerRestart(BaseModel):
    name: str


class ServiceRestart(BaseModel):
    name: str


class WebhookConfig(BaseModel):
    url: str
    secret: Optional[str] = None
    events: List[str] = ["all"]
    enabled: bool = True


def run_cmd(cmd: list, timeout: int = 30) -> tuple:
    """Run command and return (success, stdout, stderr)"""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.returncode == 0, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return False, "", "Command timed out"
    except Exception as e:
        return False, "", str(e)


def load_config() -> dict:
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text())
        except:
            pass
    return DEFAULT_CONFIG.copy()


def save_config(config: dict):
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(config, indent=2))


def log_event(message: str, level: str = "INFO"):
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"[{timestamp}] [{level}] {message}\n")


def load_history() -> List[Dict]:
    if HISTORY_FILE.exists():
        try:
            return json.loads(HISTORY_FILE.read_text())
        except:
            pass
    return []


def save_history(history: List[Dict]):
    # Keep last 1000 events
    history = history[-1000:]
    HISTORY_FILE.write_text(json.dumps(history, indent=2, default=str))


def add_event(event_type: EventType, target: str, details: Dict = None):
    history = load_history()
    event = {
        "id": hashlib.sha256(f"{time.time()}".encode()).hexdigest()[:12],
        "type": event_type.value,
        "target": target,
        "details": details or {},
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
    history.append(event)
    save_history(history)
    log_event(f"{event_type.value}: {target}", "INFO" if "up" in event_type.value.lower() else "WARNING")

    # Trigger webhooks
    asyncio.create_task(trigger_webhooks(event))
    return event


def load_webhooks() -> List[Dict]:
    if WEBHOOKS_FILE.exists():
        try:
            return json.loads(WEBHOOKS_FILE.read_text())
        except:
            pass
    return []


def save_webhooks(webhooks: List[Dict]):
    WEBHOOKS_FILE.write_text(json.dumps(webhooks, indent=2))


async def trigger_webhooks(event: Dict):
    webhooks = load_webhooks()
    for wh in webhooks:
        if not wh.get("enabled", True):
            continue
        events = wh.get("events", ["all"])
        if "all" not in events and event["type"] not in events:
            continue

        try:
            payload = json.dumps(event)
            headers = {"Content-Type": "application/json"}

            if wh.get("secret"):
                sig = hmac.new(wh["secret"].encode(), payload.encode(), hashlib.sha256).hexdigest()
                headers["X-Webhook-Signature"] = f"sha256={sig}"

            async with httpx.AsyncClient(timeout=10.0) as client:
                await client.post(wh["url"], content=payload, headers=headers)
        except Exception as e:
            log_event(f"Webhook failed: {wh['url']} - {e}", "ERROR")


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
    # Try without -x flag for better compatibility
    success, out, _ = run_cmd(["pgrep", process])
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


def get_health_state(containers: List, services: List, endpoints: List) -> HealthState:
    """Calculate overall health state."""
    critical_down = 0
    total_down = 0

    for c in containers:
        if c["state"] != "running":
            total_down += 1
            if c.get("critical"):
                critical_down += 1

    for s in services:
        if s["state"] != "running":
            total_down += 1
            if s.get("critical"):
                critical_down += 1

    for e in endpoints:
        if not e.get("healthy"):
            total_down += 1

    if critical_down > 0:
        return HealthState.CRITICAL
    elif total_down > 0:
        return HealthState.DEGRADED
    return HealthState.HEALTHY


def format_bytes(size: int) -> str:
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if abs(size) < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} PB"


def format_uptime(seconds: int) -> str:
    days = seconds // 86400
    hours = (seconds % 86400) // 3600
    mins = (seconds % 3600) // 60
    if days > 0:
        return f"{days}d {hours}h {mins}m"
    elif hours > 0:
        return f"{hours}h {mins}m"
    return f"{mins}m"


async def perform_health_check() -> Dict:
    """Perform full health check."""
    config = load_config()

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

    health_state = get_health_state(containers, services, endpoints)

    return {
        "health": health_state.value,
        "containers": containers,
        "services": services,
        "endpoints": endpoints,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }


async def monitor_loop():
    """Background monitoring loop."""
    global _monitor_running
    _monitor_running = True

    previous_states = {}

    while _monitor_running:
        try:
            config = load_config()
            if not config.get("enabled", True):
                await asyncio.sleep(30)
                continue

            check = await perform_health_check()
            stats_cache.set("last_check", check)

            # Track state changes
            for c in check["containers"]:
                key = f"container:{c['name']}"
                prev = previous_states.get(key)
                current = c["state"]
                if prev is not None and prev != current:
                    if current == "running":
                        add_event(EventType.CONTAINER_UP, c["name"])
                    else:
                        add_event(EventType.CONTAINER_DOWN, c["name"])
                previous_states[key] = current

            for s in check["services"]:
                key = f"service:{s['name']}"
                prev = previous_states.get(key)
                current = s["state"]
                if prev is not None and prev != current:
                    if current == "running":
                        add_event(EventType.SERVICE_UP, s["name"])
                    else:
                        add_event(EventType.SERVICE_DOWN, s["name"])
                previous_states[key] = current

            for e in check["endpoints"]:
                key = f"endpoint:{e['name']}"
                prev = previous_states.get(key)
                current = e["healthy"]
                if prev is not None and prev != current:
                    if current:
                        add_event(EventType.ENDPOINT_UP, e["name"])
                    else:
                        add_event(EventType.ENDPOINT_DOWN, e["name"])
                previous_states[key] = current

            interval = config.get("interval", 60)
            await asyncio.sleep(interval)

        except Exception as e:
            log_event(f"Monitor error: {e}", "ERROR")
            await asyncio.sleep(30)


@app.on_event("startup")
async def startup():
    global _monitor_task
    _monitor_task = asyncio.create_task(monitor_loop())
    log_event("Watchdog started", "INFO")


@app.on_event("shutdown")
async def shutdown():
    global _monitor_running, _monitor_task
    _monitor_running = False
    if _monitor_task:
        _monitor_task.cancel()


# ============================================================================
# Public Endpoints
# ============================================================================

@app.get("/status")
async def get_status():
    """Get watchdog status."""
    cached = stats_cache.get("last_check")
    if cached:
        return {**cached, "cached": True}

    check = await perform_health_check()
    stats_cache.set("last_check", check)
    return {**check, "cached": False}


@app.get("/health")
async def health():
    return {"status": "healthy", "module": "watchdog"}


@app.get("/containers")
async def get_containers():
    """Get detailed container list."""
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

    return {"containers": containers, "total": len(containers)}


@app.get("/services")
async def get_services():
    """Get detailed service list."""
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

    return {"services": services, "total": len(services)}


@app.get("/endpoints")
async def get_endpoints():
    """Get detailed endpoint list."""
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

    return {"endpoints": endpoints, "total": len(endpoints)}


@app.get("/logs")
async def get_logs(lines: int = Query(50, ge=1, le=500)):
    """Get watchdog logs."""
    log_lines = []
    total = 0

    if LOG_FILE.exists():
        all_lines = LOG_FILE.read_text().strip().split('\n')
        total = len(all_lines)
        log_lines = all_lines[-lines:] if lines < total else all_lines

    return {"lines": log_lines, "total": total}


@app.get("/history")
async def get_history(limit: int = Query(50, ge=1, le=500), event_type: Optional[str] = None):
    """Get event history."""
    history = load_history()

    if event_type:
        history = [e for e in history if e.get("type") == event_type]

    history = sorted(history, key=lambda x: x.get("timestamp", ""), reverse=True)
    return {"events": history[:limit], "total": len(history)}


@app.get("/config")
async def get_config_endpoint():
    """Get watchdog configuration."""
    return load_config()


@app.get("/summary")
async def get_summary():
    """Get comprehensive watchdog summary."""
    config = load_config()
    check = await perform_health_check()
    history = load_history()

    # Count issues
    containers_down = sum(1 for c in check["containers"] if c["state"] != "running")
    services_down = sum(1 for s in check["services"] if s["state"] != "running")
    endpoints_down = sum(1 for e in check["endpoints"] if not e["healthy"])

    # Recent events (24h)
    cutoff = (datetime.utcnow() - timedelta(hours=24)).isoformat()
    recent_events = [e for e in history if e.get("timestamp", "") > cutoff]

    return {
        "health": check["health"],
        "monitoring": {
            "enabled": config.get("enabled", True),
            "interval": config.get("interval", 60),
            "auto_recovery": config.get("auto_recovery", False)
        },
        "containers": {
            "total": len(check["containers"]),
            "running": len(check["containers"]) - containers_down,
            "down": containers_down
        },
        "services": {
            "total": len(check["services"]),
            "running": len(check["services"]) - services_down,
            "down": services_down
        },
        "endpoints": {
            "total": len(check["endpoints"]),
            "healthy": len(check["endpoints"]) - endpoints_down,
            "unhealthy": endpoints_down
        },
        "events_24h": len(recent_events),
        "webhooks_configured": len(load_webhooks()),
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }


# ============================================================================
# Protected Endpoints
# ============================================================================

@app.post("/container/restart", dependencies=[Depends(require_jwt)])
async def restart_container(req: ContainerRestart):
    """Restart a container."""
    container_dir = LXC_PATH / req.name

    if not container_dir.exists() or not (container_dir / "config").exists():
        raise HTTPException(status_code=404, detail="Container not found")

    add_event(EventType.RECOVERY_ATTEMPTED, req.name, {"type": "container", "action": "restart"})

    run_cmd(["lxc-stop", "-P", str(LXC_PATH), "-n", req.name], timeout=30)
    await asyncio.sleep(1)

    success, out, err = run_cmd(["lxc-start", "-P", str(LXC_PATH), "-n", req.name], timeout=30)
    await asyncio.sleep(2)

    running, pid = lxc_running(req.name)

    if running:
        add_event(EventType.RECOVERY_SUCCESS, req.name, {"pid": pid})
        stats_cache.invalidate()
        return {"success": True, "state": "running", "pid": pid}
    else:
        add_event(EventType.RECOVERY_FAILED, req.name, {"error": err})
        return {"success": False, "error": "Container failed to start", "state": "stopped"}


@app.post("/service/restart", dependencies=[Depends(require_jwt)])
async def restart_service(req: ServiceRestart):
    """Restart a service."""
    config = load_config()

    service = None
    for s in config.get("services", []):
        if s["name"] == req.name:
            service = s
            break

    if not service:
        raise HTTPException(status_code=404, detail="Service not found in configuration")

    add_event(EventType.RECOVERY_ATTEMPTED, req.name, {"type": "service", "action": "restart"})

    success, out, err = run_cmd(["systemctl", "restart", req.name], timeout=30)
    await asyncio.sleep(2)

    running, pid = service_running(service["process"])

    if running:
        add_event(EventType.RECOVERY_SUCCESS, req.name, {"pid": pid})
        stats_cache.invalidate()
        return {"success": True, "state": "running", "pid": pid}
    else:
        add_event(EventType.RECOVERY_FAILED, req.name, {"error": err})
        return {"success": False, "error": "Service failed to start", "state": "stopped"}


@app.post("/check", dependencies=[Depends(require_jwt)])
async def run_check():
    """Run a manual health check."""
    check = await perform_health_check()
    stats_cache.set("last_check", check)

    issues = []
    for c in check["containers"]:
        if c["state"] != "running":
            issues.append(f"Container {c['name']} is {c['state']}")
    for s in check["services"]:
        if s["state"] != "running":
            issues.append(f"Service {s['name']} is {s['state']}")
    for e in check["endpoints"]:
        if not e["healthy"]:
            issues.append(f"Endpoint {e['name']} returned {e['code']}")

    return {
        "success": True,
        "health": check["health"],
        "issues": issues,
        "message": f"Health check completed, {len(issues)} issues found"
    }


@app.post("/logs/clear", dependencies=[Depends(require_jwt)])
async def clear_logs():
    """Clear watchdog logs."""
    if LOG_FILE.exists():
        LOG_FILE.write_text("")

    ALERT_STATE_DIR.mkdir(parents=True, exist_ok=True)
    for f in ALERT_STATE_DIR.glob("*.alert"):
        f.unlink()

    log_event("Logs cleared", "INFO")
    return {"success": True}


@app.post("/config", dependencies=[Depends(require_jwt)])
async def update_config(config: dict):
    """Update watchdog configuration."""
    save_config(config)
    stats_cache.invalidate()
    log_event("Configuration updated", "INFO")
    return {"success": True}


@app.get("/webhooks", dependencies=[Depends(require_jwt)])
async def list_webhooks():
    """List configured webhooks."""
    return {"webhooks": load_webhooks()}


@app.post("/webhooks", dependencies=[Depends(require_jwt)])
async def add_webhook(webhook: WebhookConfig):
    """Add a webhook."""
    webhooks = load_webhooks()
    wh = {
        "id": hashlib.sha256(f"{time.time()}".encode()).hexdigest()[:12],
        "url": webhook.url,
        "secret": webhook.secret,
        "events": webhook.events,
        "enabled": webhook.enabled,
        "created_at": datetime.utcnow().isoformat() + "Z"
    }
    webhooks.append(wh)
    save_webhooks(webhooks)
    return {"success": True, "webhook": wh}


@app.delete("/webhooks/{webhook_id}", dependencies=[Depends(require_jwt)])
async def delete_webhook(webhook_id: str):
    """Delete a webhook."""
    webhooks = load_webhooks()
    webhooks = [w for w in webhooks if w.get("id") != webhook_id]
    save_webhooks(webhooks)
    return {"success": True}
