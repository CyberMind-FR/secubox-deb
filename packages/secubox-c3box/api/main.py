"""SecuBox C3box API - Services Portal with Enhanced Monitoring"""
import subprocess
import threading
import time
import json
import asyncio
import hashlib
import hmac
import httpx
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, Depends, BackgroundTasks
from pydantic import BaseModel, Field, field_validator
from secubox_core.auth import require_jwt
from secubox_core.config import get_config

app = FastAPI(title="SecuBox C3Box Services Portal")
config = get_config("c3box")

# Configuration
DATA_DIR = Path("/var/lib/secubox/c3box")
DATA_DIR.mkdir(parents=True, exist_ok=True)
WEBHOOKS_FILE = DATA_DIR / "webhooks.json"
HISTORY_FILE = DATA_DIR / "history.json"


# Service catalog with metadata
SERVICES = [
    {"name": "crowdsec", "category": "security", "icon": "🛡️", "desc": "IDS/IPS Protection", "port": None, "critical": True},
    {"name": "wireguard", "category": "security", "icon": "🔒", "desc": "VPN Server", "port": 51820, "critical": False},
    {"name": "waf", "category": "security", "icon": "🔥", "desc": "Web Application Firewall", "port": None, "critical": True},
    {"name": "nac", "category": "security", "icon": "👁️", "desc": "Network Access Control", "port": None, "critical": False},
    {"name": "auth", "category": "security", "icon": "🎫", "desc": "OAuth2 & Captive Portal", "port": None, "critical": False},
    {"name": "haproxy", "category": "network", "icon": "⚡", "desc": "Load Balancer", "port": 443, "critical": True},
    {"name": "vhost", "category": "network", "icon": "🌐", "desc": "Virtual Hosts", "port": None, "critical": False},
    {"name": "netmodes", "category": "network", "icon": "🔀", "desc": "Network Modes", "port": None, "critical": False},
    {"name": "dpi", "category": "network", "icon": "🔍", "desc": "Deep Packet Inspection", "port": None, "critical": False},
    {"name": "qos", "category": "network", "icon": "📶", "desc": "Bandwidth Manager", "port": None, "critical": False},
    {"name": "droplet", "category": "apps", "icon": "📁", "desc": "File Publisher", "port": None, "critical": False},
    {"name": "streamlit", "category": "apps", "icon": "📊", "desc": "Python Apps", "port": None, "critical": False},
    {"name": "streamforge", "category": "apps", "icon": "🔨", "desc": "App Manager", "port": None, "critical": False},
    {"name": "metablogizer", "category": "apps", "icon": "📝", "desc": "Static Sites", "port": None, "critical": False},
    {"name": "publish", "category": "apps", "icon": "🚀", "desc": "Publishing Hub", "port": None, "critical": False},
    {"name": "dns", "category": "comm", "icon": "🌍", "desc": "DNS Server", "port": 53, "critical": True},
    {"name": "mail", "category": "comm", "icon": "📧", "desc": "Email Server", "port": 25, "critical": False},
    {"name": "webmail", "category": "comm", "icon": "💌", "desc": "Roundcube/SOGo", "port": None, "critical": False},
    {"name": "users", "category": "comm", "icon": "👥", "desc": "Identity Manager", "port": None, "critical": False},
    {"name": "netdata", "category": "monitoring", "icon": "📈", "desc": "Real-time Monitoring", "port": 19999, "critical": False},
    {"name": "cdn", "category": "network", "icon": "🌐", "desc": "Cache Server", "port": None, "critical": False},
    {"name": "mediaflow", "category": "apps", "icon": "🎬", "desc": "Media Streaming", "port": None, "critical": False},
]


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

    def clear(self):
        with self._lock:
            self._cache.clear()
            self._timestamps.clear()


stats_cache = StatsCache(ttl_seconds=15)


# Pydantic Models
class WebhookConfig(BaseModel):
    url: str
    events: List[str] = Field(default=["service_down", "service_up", "critical_down"])
    secret: Optional[str] = None
    enabled: bool = True

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        if not v.startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")
        return v


class ServiceAction(BaseModel):
    action: str = Field(..., pattern="^(start|stop|restart)$")


# State tracking
_previous_states: Dict[str, bool] = {}
_monitoring_task: Optional[asyncio.Task] = None


def check_service(name: str) -> bool:
    """Check if a secubox service is running."""
    try:
        result = subprocess.run(
            ["systemctl", "is-active", f"secubox-{name}"],
            capture_output=True, text=True, timeout=5
        )
        return result.stdout.strip() == "active"
    except Exception:
        return False


def get_service_uptime(name: str) -> Optional[str]:
    """Get service uptime from systemctl."""
    try:
        result = subprocess.run(
            ["systemctl", "show", f"secubox-{name}", "--property=ActiveEnterTimestamp"],
            capture_output=True, text=True, timeout=5
        )
        if "=" in result.stdout:
            timestamp = result.stdout.strip().split("=", 1)[1]
            if timestamp and timestamp != "n/a":
                return timestamp
    except Exception:
        pass
    return None


def get_service_memory(name: str) -> Optional[int]:
    """Get service memory usage in bytes."""
    try:
        result = subprocess.run(
            ["systemctl", "show", f"secubox-{name}", "--property=MemoryCurrent"],
            capture_output=True, text=True, timeout=5
        )
        if "=" in result.stdout:
            value = result.stdout.strip().split("=", 1)[1]
            if value and value.isdigit():
                return int(value)
    except Exception:
        pass
    return None


def _load_webhooks() -> List[Dict[str, Any]]:
    """Load webhooks from file."""
    if WEBHOOKS_FILE.exists():
        try:
            return json.loads(WEBHOOKS_FILE.read_text())
        except Exception:
            pass
    return []


def _save_webhooks(webhooks: List[Dict[str, Any]]):
    """Save webhooks to file."""
    WEBHOOKS_FILE.write_text(json.dumps(webhooks, indent=2))


def _load_history() -> List[Dict[str, Any]]:
    """Load service history from file."""
    if HISTORY_FILE.exists():
        try:
            return json.loads(HISTORY_FILE.read_text())
        except Exception:
            pass
    return []


def _save_history(history: List[Dict[str, Any]]):
    """Save service history to file."""
    # Keep last 1000 entries
    history = history[-1000:]
    HISTORY_FILE.write_text(json.dumps(history, indent=2))


def _record_event(service: str, event: str, details: Optional[Dict] = None):
    """Record a service event in history."""
    history = _load_history()
    entry = {
        "timestamp": datetime.now().isoformat(),
        "service": service,
        "event": event,
        "details": details or {}
    }
    history.append(entry)
    _save_history(history)


async def _send_webhook(url: str, payload: Dict[str, Any], secret: Optional[str] = None):
    """Send webhook notification."""
    try:
        headers = {"Content-Type": "application/json"}
        body = json.dumps(payload)

        if secret:
            signature = hmac.new(
                secret.encode(),
                body.encode(),
                hashlib.sha256
            ).hexdigest()
            headers["X-SecuBox-Signature"] = f"sha256={signature}"

        async with httpx.AsyncClient(timeout=10.0) as client:
            await client.post(url, content=body, headers=headers)
    except Exception:
        pass


async def _notify_webhooks(event: str, data: Dict[str, Any]):
    """Send notifications to all webhooks for event."""
    webhooks = _load_webhooks()
    for webhook in webhooks:
        if webhook.get("enabled", True) and event in webhook.get("events", []):
            await _send_webhook(
                webhook["url"],
                {"event": event, "data": data, "timestamp": datetime.now().isoformat()},
                webhook.get("secret")
            )


async def _monitor_services():
    """Background task to monitor services and send alerts."""
    global _previous_states

    while True:
        try:
            for svc in SERVICES:
                name = svc["name"]
                running = check_service(name)
                prev = _previous_states.get(name)

                if prev is not None and prev != running:
                    event = "service_up" if running else "service_down"
                    event_data = {
                        "service": name,
                        "category": svc["category"],
                        "critical": svc.get("critical", False),
                        "running": running
                    }

                    _record_event(name, event, event_data)
                    await _notify_webhooks(event, event_data)

                    if svc.get("critical") and not running:
                        await _notify_webhooks("critical_down", event_data)

                _previous_states[name] = running

        except Exception:
            pass

        await asyncio.sleep(30)


@app.on_event("startup")
async def startup():
    """Start background monitoring."""
    global _monitoring_task
    _monitoring_task = asyncio.create_task(_monitor_services())


@app.on_event("shutdown")
async def shutdown():
    """Stop background monitoring."""
    global _monitoring_task
    if _monitoring_task:
        _monitoring_task.cancel()


# Public endpoints
@app.get("/status")
async def status():
    """Public status endpoint."""
    return {
        "module": "c3box",
        "status": "ok",
        "version": "2.0.0",
        "description": "Services Portal with Enhanced Monitoring"
    }


@app.get("/services")
async def list_services():
    """List all available services with status."""
    cached = stats_cache.get("services")
    if cached:
        return cached

    services_with_status = []
    for svc in SERVICES:
        svc_copy = svc.copy()
        svc_copy["running"] = check_service(svc["name"])
        svc_copy["url"] = f"/{svc['name']}/"
        svc_copy["uptime"] = get_service_uptime(svc["name"]) if svc_copy["running"] else None
        services_with_status.append(svc_copy)

    result = {
        "services": services_with_status,
        "total": len(services_with_status),
        "running": sum(1 for s in services_with_status if s["running"]),
        "critical_running": sum(1 for s in services_with_status if s["running"] and s.get("critical")),
        "critical_total": sum(1 for s in services_with_status if s.get("critical")),
        "timestamp": datetime.now().isoformat()
    }

    stats_cache.set("services", result)
    return result


@app.get("/services/by-category")
async def services_by_category():
    """Get services grouped by category."""
    services = (await list_services())["services"]

    by_category: Dict[str, List[Dict]] = {}
    for svc in services:
        cat = svc["category"]
        if cat not in by_category:
            by_category[cat] = []
        by_category[cat].append(svc)

    return {
        "categories": by_category,
        "category_stats": {
            cat: {
                "total": len(svcs),
                "running": sum(1 for s in svcs if s["running"])
            }
            for cat, svcs in by_category.items()
        }
    }


@app.get("/services/{name}")
async def get_service(name: str):
    """Get detailed status for a specific service."""
    svc = next((s for s in SERVICES if s["name"] == name), None)
    if not svc:
        return {"error": "Service not found"}

    running = check_service(name)

    result = svc.copy()
    result["running"] = running
    result["uptime"] = get_service_uptime(name) if running else None
    result["memory_bytes"] = get_service_memory(name) if running else None
    result["url"] = f"/{name}/"

    # Get recent history for this service
    history = _load_history()
    result["recent_events"] = [
        h for h in history[-50:]
        if h.get("service") == name
    ][-10:]

    return result


@app.post("/services/{name}/control", dependencies=[Depends(require_jwt)])
async def control_service(name: str, action: ServiceAction, background_tasks: BackgroundTasks):
    """Start, stop, or restart a service."""
    svc = next((s for s in SERVICES if s["name"] == name), None)
    if not svc:
        return {"success": False, "error": "Service not found"}

    try:
        result = subprocess.run(
            ["systemctl", action.action, f"secubox-{name}"],
            capture_output=True, text=True, timeout=30
        )
        success = result.returncode == 0

        if success:
            _record_event(name, f"service_{action.action}", {"by": "api"})
            stats_cache.clear()

        return {
            "success": success,
            "action": action.action,
            "service": name,
            "output": result.stdout if success else result.stderr
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Operation timed out"}
    except Exception as e:
        return {"success": False, "error": str(e)}


@app.get("/health")
async def health_check():
    """Get overall system health."""
    services = (await list_services())["services"]

    critical_services = [s for s in services if s.get("critical")]
    critical_down = [s["name"] for s in critical_services if not s["running"]]

    if critical_down:
        status = "critical"
    elif sum(1 for s in services if not s["running"]) > len(services) // 2:
        status = "degraded"
    else:
        status = "healthy"

    return {
        "status": status,
        "total_services": len(services),
        "running_services": sum(1 for s in services if s["running"]),
        "critical_down": critical_down,
        "timestamp": datetime.now().isoformat()
    }


@app.get("/history", dependencies=[Depends(require_jwt)])
async def get_history(limit: int = 100, service: Optional[str] = None):
    """Get service event history."""
    history = _load_history()

    if service:
        history = [h for h in history if h.get("service") == service]

    return {
        "events": history[-limit:],
        "total": len(history)
    }


@app.get("/webhooks", dependencies=[Depends(require_jwt)])
async def list_webhooks():
    """List configured webhooks."""
    return {"webhooks": _load_webhooks()}


@app.post("/webhooks", dependencies=[Depends(require_jwt)])
async def add_webhook(webhook: WebhookConfig):
    """Add a new webhook."""
    webhooks = _load_webhooks()
    webhook_data = webhook.model_dump()
    webhook_data["id"] = hashlib.md5(webhook.url.encode()).hexdigest()[:8]
    webhook_data["created_at"] = datetime.now().isoformat()
    webhooks.append(webhook_data)
    _save_webhooks(webhooks)
    return {"success": True, "webhook": webhook_data}


@app.delete("/webhooks/{webhook_id}", dependencies=[Depends(require_jwt)])
async def delete_webhook(webhook_id: str):
    """Delete a webhook."""
    webhooks = _load_webhooks()
    webhooks = [w for w in webhooks if w.get("id") != webhook_id]
    _save_webhooks(webhooks)
    return {"success": True}


@app.get("/summary")
async def summary():
    """Get portal summary."""
    services = (await list_services())["services"]
    health = await health_check()

    by_category: Dict[str, Dict[str, int]] = {}
    for svc in services:
        cat = svc["category"]
        if cat not in by_category:
            by_category[cat] = {"total": 0, "running": 0}
        by_category[cat]["total"] += 1
        if svc["running"]:
            by_category[cat]["running"] += 1

    # Recent events
    history = _load_history()
    recent_events = history[-10:]

    return {
        "health": health["status"],
        "services": {
            "total": len(services),
            "running": sum(1 for s in services if s["running"]),
            "stopped": sum(1 for s in services if not s["running"]),
            "critical_ok": health["total_services"] - len(health.get("critical_down", [])),
        },
        "by_category": by_category,
        "recent_events": recent_events,
        "webhooks_configured": len(_load_webhooks()),
        "timestamp": datetime.now().isoformat()
    }


@app.get("/info", dependencies=[Depends(require_jwt)])
async def info():
    """Protected info endpoint."""
    return {"config": dict(config)}
