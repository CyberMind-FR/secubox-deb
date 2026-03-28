"""
SecuBox Tor Shield API - Production Ready
Tor anonymity network and hidden services management

Features:
- Tor service management with presets
- Hidden service (.onion) management
- Circuit monitoring and visualization
- IP leak detection
- Stats caching with TTL
- Event history tracking
- Webhook notifications
- Traffic statistics
"""

from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from pathlib import Path
from datetime import datetime, timedelta
import subprocess
import asyncio
import threading
import socket
import hashlib
import hmac
import time
import json
import httpx

from secubox_core.auth import require_jwt
from secubox_core.config import get_config

app = FastAPI(title="SecuBox Tor Shield API", version="2.0.0")

# Configuration
TOR_CONTROL_PORT = 9051
TOR_SOCKS_PORT = 9050
TOR_DATA = Path("/var/lib/tor")
TOR_CONTROL_SOCKET = Path("/run/tor/control")
DATA_DIR = Path("/var/lib/secubox/tor")
CONFIG_FILE = Path("/etc/secubox/tor.json")
HISTORY_FILE = DATA_DIR / "history.json"
WEBHOOKS_FILE = DATA_DIR / "webhooks.json"
STATS_FILE = DATA_DIR / "stats_history.json"

# Ensure directories
DATA_DIR.mkdir(parents=True, exist_ok=True)


class StatsCache:
    """Thread-safe stats cache with TTL."""
    def __init__(self, ttl_seconds: int = 15):
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

DEFAULT_CONFIG = {
    "enabled": False,
    "mode": "transparent",
    "dns_over_tor": True,
    "kill_switch": True,
    "bridges_enabled": False,
    "bridge_type": "obfs4",
    "hidden_services": []
}


class EnableRequest(BaseModel):
    preset: str = "anonymous"


class HiddenService(BaseModel):
    name: str
    local_port: int = Field(default=80, ge=1, le=65535)
    virtual_port: int = Field(default=80, ge=1, le=65535)


class HiddenServiceRemove(BaseModel):
    name: str


class WebhookConfig(BaseModel):
    url: str
    secret: Optional[str] = None
    events: List[str] = ["all"]
    enabled: bool = True


def run_cmd(cmd: list, timeout: int = 30) -> tuple:
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


def load_history() -> List[Dict]:
    if HISTORY_FILE.exists():
        try:
            return json.loads(HISTORY_FILE.read_text())
        except:
            pass
    return []


def save_history(history: List[Dict]):
    history = history[-500:]
    HISTORY_FILE.write_text(json.dumps(history, indent=2, default=str))


def add_event(event_type: str, details: Dict = None):
    history = load_history()
    event = {
        "id": hashlib.sha256(f"{time.time()}".encode()).hexdigest()[:12],
        "type": event_type,
        "details": details or {},
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
    history.append(event)
    save_history(history)
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
        except:
            pass


def format_bytes(size: int) -> str:
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if abs(size) < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} PB"


def tor_running() -> bool:
    success, out, _ = run_cmd(["pgrep", "tor"])
    return success and out.strip() != ""


def tor_control(command: str) -> str:
    try:
        if TOR_CONTROL_SOCKET.exists():
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect(str(TOR_CONTROL_SOCKET))
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect(("127.0.0.1", TOR_CONTROL_PORT))

        cookie_file = Path("/run/tor/control.authcookie")
        if cookie_file.exists():
            cookie = cookie_file.read_bytes().hex()
            sock.send(f"AUTHENTICATE {cookie}\r\n".encode())
        else:
            sock.send(b"AUTHENTICATE\r\n")

        response = sock.recv(1024).decode()
        if "250 OK" not in response:
            sock.close()
            return ""

        sock.send(f"{command}\r\n".encode())
        response = sock.recv(4096).decode()
        sock.close()
        return response
    except:
        return ""


def get_bootstrap_progress() -> int:
    response = tor_control("GETINFO status/bootstrap-phase")
    if "PROGRESS=" in response:
        try:
            progress = response.split("PROGRESS=")[1].split()[0]
            return int(progress)
        except:
            pass
    return 0


def get_circuit_count() -> int:
    response = tor_control("GETINFO circuit-status")
    return response.count("BUILT")


def get_traffic_stats() -> tuple:
    read_resp = tor_control("GETINFO traffic/read")
    write_resp = tor_control("GETINFO traffic/written")

    bytes_read = 0
    bytes_written = 0

    if "250" in read_resp:
        try:
            bytes_read = int(read_resp.split("250")[0].split("=")[1].strip())
        except:
            pass

    if "250" in write_resp:
        try:
            bytes_written = int(write_resp.split("250")[0].split("=")[1].strip())
        except:
            pass

    return bytes_read, bytes_written


# ============================================================================
# Public Endpoints
# ============================================================================

@app.get("/status")
async def get_status():
    """Get Tor Shield status."""
    cached = stats_cache.get("status")
    if cached:
        return {**cached, "cached": True}

    config = load_config()
    running = tor_running()

    status = {
        "enabled": config.get("enabled", False),
        "running": running,
        "mode": config.get("mode", "transparent"),
        "dns_over_tor": config.get("dns_over_tor", True),
        "kill_switch": config.get("kill_switch", True),
        "bridges_enabled": config.get("bridges_enabled", False),
        "bridge_type": config.get("bridge_type", "obfs4")
    }

    if running:
        status["bootstrap"] = get_bootstrap_progress()
        status["circuit_count"] = get_circuit_count()
        bytes_read, bytes_written = get_traffic_stats()
        status["bytes_read"] = bytes_read
        status["bytes_written"] = bytes_written
        status["bytes_read_human"] = format_bytes(bytes_read)
        status["bytes_written_human"] = format_bytes(bytes_written)

        exit_ip_cache = Path("/tmp/tor_exit_ip")
        if exit_ip_cache.exists():
            status["exit_ip"] = exit_ip_cache.read_text().strip()
            status["is_tor"] = True
        else:
            status["exit_ip"] = "unknown"
            status["is_tor"] = False
    else:
        status["bootstrap"] = 0
        status["circuit_count"] = 0
        status["bytes_read"] = 0
        status["bytes_written"] = 0
        status["bytes_read_human"] = "0 B"
        status["bytes_written_human"] = "0 B"

    stats_cache.set("status", status)
    return status


@app.get("/health")
async def health():
    return {"status": "healthy", "module": "tor"}


@app.get("/summary")
async def get_summary():
    """Get comprehensive Tor summary."""
    config = load_config()
    running = tor_running()
    history = load_history()

    hidden_services = []
    for hs in config.get("hidden_services", []):
        hostname_file = TOR_DATA / f"hidden_service_{hs['name']}" / "hostname"
        onion_address = hostname_file.read_text().strip() if hostname_file.exists() else ""
        hidden_services.append({
            "name": hs["name"],
            "has_address": bool(onion_address)
        })

    bytes_read, bytes_written = (0, 0)
    bootstrap = 0
    circuits = 0
    if running:
        bytes_read, bytes_written = get_traffic_stats()
        bootstrap = get_bootstrap_progress()
        circuits = get_circuit_count()

    # Recent events
    cutoff = (datetime.utcnow() - timedelta(hours=24)).isoformat()
    recent_events = [e for e in history if e.get("timestamp", "") > cutoff]

    return {
        "enabled": config.get("enabled", False),
        "running": running,
        "mode": config.get("mode", "transparent"),
        "bootstrap": bootstrap,
        "circuits": circuits,
        "traffic": {
            "bytes_read": bytes_read,
            "bytes_written": bytes_written,
            "read_human": format_bytes(bytes_read),
            "written_human": format_bytes(bytes_written)
        },
        "hidden_services": {
            "total": len(hidden_services),
            "active": sum(1 for hs in hidden_services if hs["has_address"])
        },
        "security": {
            "dns_over_tor": config.get("dns_over_tor", True),
            "kill_switch": config.get("kill_switch", True),
            "bridges_enabled": config.get("bridges_enabled", False)
        },
        "events_24h": len(recent_events),
        "webhooks_configured": len(load_webhooks()),
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }


@app.get("/circuits")
async def get_circuits():
    """Get active Tor circuits."""
    if not tor_running():
        return {"circuits": [], "total": 0}

    response = tor_control("GETINFO circuit-status")
    circuits = []

    for line in response.split('\n'):
        if "BUILT" in line:
            parts = line.split()
            if len(parts) >= 3:
                circuit_id = parts[0]
                status = parts[1]
                path = parts[2] if len(parts) > 2 else ""

                nodes = []
                for node in path.split(','):
                    if '~' in node:
                        fp, name = node.split('~', 1)
                        nodes.append({"fingerprint": fp.lstrip('$'), "name": name})
                    elif node:
                        nodes.append({"fingerprint": node.lstrip('$'), "name": node})

                circuits.append({
                    "id": circuit_id,
                    "status": status,
                    "path": path,
                    "nodes": nodes,
                    "hops": len(nodes)
                })

    return {"circuits": circuits, "total": len(circuits)}


@app.get("/hidden_services")
async def get_hidden_services():
    """Get configured hidden services."""
    config = load_config()
    services = []

    for hs in config.get("hidden_services", []):
        hostname_file = TOR_DATA / f"hidden_service_{hs['name']}" / "hostname"
        onion_address = ""
        if hostname_file.exists():
            onion_address = hostname_file.read_text().strip()

        services.append({
            "name": hs["name"],
            "enabled": hs.get("enabled", True),
            "local_port": hs.get("local_port", 80),
            "virtual_port": hs.get("virtual_port", 80),
            "onion_address": onion_address,
            "has_address": bool(onion_address)
        })

    return {"services": services, "total": len(services)}


@app.get("/history")
async def get_history(limit: int = 50):
    """Get event history."""
    history = load_history()
    history = sorted(history, key=lambda x: x.get("timestamp", ""), reverse=True)
    return {"events": history[:limit], "total": len(history)}


# ============================================================================
# Protected Endpoints
# ============================================================================

@app.post("/enable", dependencies=[Depends(require_jwt)])
async def enable_tor(req: EnableRequest):
    """Enable Tor Shield."""
    config = load_config()

    presets = {
        "anonymous": {"mode": "transparent", "dns_over_tor": True, "kill_switch": True},
        "stealth": {"mode": "transparent", "dns_over_tor": True, "kill_switch": True, "bridges_enabled": True},
        "minimal": {"mode": "socks", "dns_over_tor": True, "kill_switch": False}
    }

    preset_config = presets.get(req.preset, presets["anonymous"])
    config.update(preset_config)
    config["enabled"] = True
    config["current_preset"] = req.preset
    save_config(config)

    run_cmd(["systemctl", "start", "tor"])
    stats_cache.invalidate()
    add_event("tor_enabled", {"preset": req.preset})

    return {"success": True, "message": f"Tor Shield enabling with preset: {req.preset}", "preset": req.preset}


@app.post("/disable", dependencies=[Depends(require_jwt)])
async def disable_tor():
    """Disable Tor Shield."""
    config = load_config()
    config["enabled"] = False
    save_config(config)

    run_cmd(["systemctl", "stop", "tor"])
    stats_cache.invalidate()
    add_event("tor_disabled", {})

    return {"success": True, "message": "Tor Shield disabled"}


@app.post("/new_identity", dependencies=[Depends(require_jwt)])
async def new_identity():
    """Request a new Tor identity."""
    if not tor_running():
        raise HTTPException(status_code=400, detail="Tor is not running")

    response = tor_control("SIGNAL NEWNYM")

    if "250 OK" in response:
        exit_ip_cache = Path("/tmp/tor_exit_ip")
        if exit_ip_cache.exists():
            exit_ip_cache.unlink()

        stats_cache.invalidate()
        add_event("new_identity", {})
        return {"success": True, "message": "New identity requested"}
    else:
        return {"success": False, "error": "Failed to request new identity"}


@app.post("/check_leaks", dependencies=[Depends(require_jwt)])
async def check_leaks():
    """Check for IP/DNS leaks."""
    if not tor_running():
        raise HTTPException(status_code=400, detail="Tor is not running")

    tests = []
    leak_count = 0

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            real_ip_resp = await client.get("https://api.ipify.org")
            real_ip = real_ip_resp.text.strip()

            tor_check = await client.get(
                "https://check.torproject.org/api/ip",
                proxy=f"socks5://127.0.0.1:{TOR_SOCKS_PORT}"
            )
            tor_data = tor_check.json()
            tor_ip = tor_data.get("IP", "")
            is_tor = tor_data.get("IsTor", False)

            if tor_ip and tor_ip != real_ip:
                tests.append({"name": "IP Leak", "passed": True, "message": "IP protected"})
            else:
                tests.append({"name": "IP Leak", "passed": False, "message": "Potential IP leak"})
                leak_count += 1

            if is_tor:
                tests.append({"name": "Tor Detection", "passed": True, "message": "Traffic via Tor confirmed"})
            else:
                tests.append({"name": "Tor Detection", "passed": False, "message": "Traffic may not be through Tor"})
                leak_count += 1

    except Exception as e:
        tests.append({"name": "Connection", "passed": False, "message": str(e)})
        leak_count += 1

    add_event("leak_check", {"tests": len(tests), "leaks": leak_count})
    return {"tests": tests, "leak_count": leak_count, "protected": leak_count == 0}


@app.post("/hidden_service/add", dependencies=[Depends(require_jwt)])
async def add_hidden_service(req: HiddenService):
    """Add a hidden service."""
    config = load_config()

    name = "".join(c for c in req.name if c.isalnum() or c in "_-")

    for hs in config.get("hidden_services", []):
        if hs["name"] == name:
            raise HTTPException(status_code=400, detail="Hidden service already exists")

    if "hidden_services" not in config:
        config["hidden_services"] = []

    config["hidden_services"].append({
        "name": name,
        "enabled": True,
        "local_port": req.local_port,
        "virtual_port": req.virtual_port
    })

    save_config(config)

    if config.get("enabled"):
        run_cmd(["systemctl", "reload", "tor"])

    stats_cache.invalidate()
    add_event("hidden_service_added", {"name": name})
    return {"success": True, "message": "Hidden service created", "name": name}


@app.post("/hidden_service/remove", dependencies=[Depends(require_jwt)])
async def remove_hidden_service(req: HiddenServiceRemove):
    """Remove a hidden service."""
    config = load_config()

    hidden_services = config.get("hidden_services", [])
    config["hidden_services"] = [hs for hs in hidden_services if hs["name"] != req.name]

    save_config(config)

    hs_dir = TOR_DATA / f"hidden_service_{req.name}"
    if hs_dir.exists():
        import shutil
        shutil.rmtree(hs_dir, ignore_errors=True)

    if config.get("enabled"):
        run_cmd(["systemctl", "reload", "tor"])

    stats_cache.invalidate()
    add_event("hidden_service_removed", {"name": req.name})
    return {"success": True, "message": "Hidden service removed"}


@app.post("/refresh_ips", dependencies=[Depends(require_jwt)])
async def refresh_ips():
    """Refresh cached IP addresses."""
    async def fetch_ips():
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                real_resp = await client.get("https://api.ipify.org")
                Path("/tmp/tor_real_ip").write_text(real_resp.text.strip())

                if tor_running():
                    tor_resp = await client.get(
                        "https://check.torproject.org/api/ip",
                        proxy=f"socks5://127.0.0.1:{TOR_SOCKS_PORT}"
                    )
                    tor_data = tor_resp.json()
                    Path("/tmp/tor_exit_ip").write_text(tor_data.get("IP", ""))
        except:
            pass

    asyncio.create_task(fetch_ips())
    stats_cache.invalidate()
    return {"success": True, "message": "IP refresh started"}


@app.get("/webhooks", dependencies=[Depends(require_jwt)])
async def list_webhooks():
    return {"webhooks": load_webhooks()}


@app.post("/webhooks", dependencies=[Depends(require_jwt)])
async def add_webhook(webhook: WebhookConfig):
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
    webhooks = load_webhooks()
    webhooks = [w for w in webhooks if w.get("id") != webhook_id]
    save_webhooks(webhooks)
    return {"success": True}


@app.get("/info")
async def get_info():
    return {
        "module": "secubox-tor",
        "version": "2.0.0",
        "description": "Tor anonymity network and hidden services"
    }
