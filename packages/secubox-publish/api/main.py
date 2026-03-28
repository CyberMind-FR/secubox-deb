"""SecuBox Publishing Platform - Unified Dashboard with Enhanced Monitoring

Layer 2 orchestrator module that provides a unified interface to all publishing modules.
Follows the 2-layer architecture: simple UI -> aggregated API -> individual module APIs.
"""
import httpx
import json
import threading
import time
import asyncio
import hashlib
import hmac
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field, field_validator
from secubox_core.auth import require_jwt
from secubox_core.config import get_config

app = FastAPI(title="SecuBox Publishing Platform", version="2.0.0")

# Configuration
DATA_DIR = Path("/var/lib/secubox/publish")
DATA_DIR.mkdir(parents=True, exist_ok=True)
HISTORY_FILE = DATA_DIR / "history.json"
WEBHOOKS_FILE = DATA_DIR / "webhooks.json"
STATS_FILE = DATA_DIR / "stats.json"

# Module socket paths
MODULES = {
    "streamlit": "/run/secubox/streamlit.sock",
    "streamforge": "/run/secubox/streamforge.sock",
    "droplet": "/run/secubox/droplet.sock",
    "metablogizer": "/run/secubox/metablogizer.sock",
}


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


stats_cache = StatsCache(ttl_seconds=30)


# Pydantic Models
class CreateAppRequest(BaseModel):
    name: str
    template: str = "basic"


class CreateSiteRequest(BaseModel):
    name: str
    title: Optional[str] = None


class PublishRequest(BaseModel):
    file: str
    domain: Optional[str] = None


class QuickPublishRequest(BaseModel):
    content_type: str = Field(..., pattern="^(app|site|file)$")
    name: str
    template: Optional[str] = None
    data: Optional[dict] = None


class WebhookConfig(BaseModel):
    url: str
    events: List[str] = Field(default=["publish", "deploy", "error", "module_down"])
    secret: Optional[str] = None
    enabled: bool = True

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        if not v.startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")
        return v


# State
_monitoring_task: Optional[asyncio.Task] = None
_previous_module_states: Dict[str, bool] = {}


def _cfg():
    cfg = get_config("publish")
    return {
        "default_publisher": cfg.get("default_publisher", "droplet") if cfg else "droplet",
        "enable_streamlit": cfg.get("enable_streamlit", True) if cfg else True,
        "enable_streamforge": cfg.get("enable_streamforge", True) if cfg else True,
        "enable_droplet": cfg.get("enable_droplet", True) if cfg else True,
        "enable_metablogizer": cfg.get("enable_metablogizer", True) if cfg else True,
    }


def _load_json(filepath: Path, default=None):
    """Load JSON file safely."""
    if filepath.exists():
        try:
            return json.loads(filepath.read_text())
        except Exception:
            pass
    return default if default is not None else []


def _save_json(filepath: Path, data):
    """Save JSON file safely."""
    filepath.write_text(json.dumps(data, indent=2))


def _load_history() -> List[Dict[str, Any]]:
    return _load_json(HISTORY_FILE, [])


def _save_history(history: List[Dict[str, Any]]):
    history = history[-1000:]
    _save_json(HISTORY_FILE, history)


def _load_webhooks() -> List[Dict[str, Any]]:
    return _load_json(WEBHOOKS_FILE, [])


def _save_webhooks(webhooks: List[Dict[str, Any]]):
    _save_json(WEBHOOKS_FILE, webhooks)


def _record_event(event: str, details: Optional[Dict] = None):
    """Record an event in history."""
    history = _load_history()
    entry = {
        "timestamp": datetime.now().isoformat(),
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


async def _call_module(module: str, path: str, method: str = "GET", data: dict = None) -> dict:
    """Call a module's API via Unix socket."""
    socket_path = MODULES.get(module)
    if not socket_path:
        return {"error": f"Unknown module: {module}"}

    try:
        transport = httpx.AsyncHTTPTransport(uds=socket_path)
        async with httpx.AsyncClient(transport=transport, base_url="http://localhost", timeout=30) as client:
            if method == "GET":
                resp = await client.get(path)
            elif method == "POST":
                resp = await client.post(path, json=data or {})
            elif method == "DELETE":
                resp = await client.delete(path)
            else:
                return {"error": f"Unsupported method: {method}"}
            return resp.json()
    except Exception as e:
        return {"error": str(e), "module": module}


async def _check_module_health(module: str) -> bool:
    """Check if a module is healthy."""
    result = await _call_module(module, "/health")
    return "error" not in result and result.get("status") == "ok"


async def _monitor_modules():
    """Background task to monitor module health."""
    global _previous_module_states

    while True:
        try:
            cfg = _cfg()
            for module in MODULES:
                if cfg.get(f"enable_{module}", True):
                    healthy = await _check_module_health(module)
                    prev = _previous_module_states.get(module)

                    if prev is not None and prev != healthy:
                        event = "module_up" if healthy else "module_down"
                        _record_event(event, {"module": module})
                        await _notify_webhooks(event, {"module": module})

                    _previous_module_states[module] = healthy

        except Exception:
            pass

        await asyncio.sleep(60)


@app.on_event("startup")
async def startup():
    """Start background monitoring."""
    global _monitoring_task
    _monitoring_task = asyncio.create_task(_monitor_modules())


@app.on_event("shutdown")
async def shutdown():
    """Stop background monitoring."""
    global _monitoring_task
    if _monitoring_task:
        _monitoring_task.cancel()


# Public endpoints
@app.get("/health")
async def health():
    return {"status": "ok", "module": "publish", "version": "2.0.0"}


@app.get("/status")
async def status():
    """Unified status for all publishing modules."""
    cached = stats_cache.get("status")
    if cached:
        return cached

    cfg = _cfg()
    statuses = {}

    for module in MODULES:
        if cfg.get(f"enable_{module}", True):
            result = await _call_module(module, "/status")
            statuses[module] = {
                "available": "error" not in result,
                "running": result.get("running", result.get("status") == "ok"),
                "details": result
            }

    running_count = sum(1 for s in statuses.values() if s.get("running"))

    result = {
        "module": "publish",
        "status": "ok" if running_count > 0 else "degraded",
        "modules": statuses,
        "summary": {
            "total": len(statuses),
            "running": running_count,
        },
        "timestamp": datetime.now().isoformat()
    }

    stats_cache.set("status", result)
    return result


# Protected endpoints
@app.get("/overview", dependencies=[Depends(require_jwt)])
async def overview():
    """Unified overview of all publishing content."""
    cached = stats_cache.get("overview")
    if cached:
        return cached

    overview_data = {
        "apps": [],
        "projects": [],
        "files": [],
        "sites": [],
    }

    # Streamlit apps
    result = await _call_module("streamlit", "/apps")
    if "apps" in result:
        overview_data["apps"] = result["apps"]

    # StreamForge projects
    result = await _call_module("streamforge", "/apps")
    if "apps" in result:
        overview_data["projects"] = result["apps"]

    # Droplet files
    result = await _call_module("droplet", "/list")
    if "files" in result:
        overview_data["files"] = result["files"]

    # MetaBlogizer sites
    result = await _call_module("metablogizer", "/sites")
    if "sites" in result:
        overview_data["sites"] = result["sites"]

    overview_data["timestamp"] = datetime.now().isoformat()
    stats_cache.set("overview", overview_data)
    return overview_data


@app.get("/stats", dependencies=[Depends(require_jwt)])
async def stats():
    """Publishing statistics across all modules."""
    overview_data = await overview()

    return {
        "streamlit": {
            "total_apps": len(overview_data.get("apps", [])),
            "running": sum(1 for a in overview_data.get("apps", []) if a.get("running") or a.get("status") == "running"),
        },
        "streamforge": {
            "total_projects": len(overview_data.get("projects", [])),
            "running": sum(1 for p in overview_data.get("projects", []) if p.get("status") == "running"),
        },
        "droplet": {
            "total_files": len(overview_data.get("files", [])),
            "published": sum(1 for f in overview_data.get("files", []) if f.get("published")),
        },
        "metablogizer": {
            "total_sites": len(overview_data.get("sites", [])),
            "published": sum(1 for s in overview_data.get("sites", []) if s.get("published")),
        },
        "timestamp": datetime.now().isoformat()
    }


@app.get("/activity", dependencies=[Depends(require_jwt)])
async def activity(hours: int = 24):
    """Get recent publishing activity."""
    history = _load_history()
    cutoff = datetime.now() - timedelta(hours=hours)

    recent = []
    for entry in history:
        try:
            entry_time = datetime.fromisoformat(entry.get("timestamp", "2000-01-01"))
            if entry_time >= cutoff:
                recent.append(entry)
        except ValueError:
            continue

    # Group by event type
    by_type: Dict[str, int] = {}
    for entry in recent:
        event = entry.get("event", "unknown")
        by_type[event] = by_type.get(event, 0) + 1

    return {
        "events": recent[-50:],
        "total": len(recent),
        "by_type": by_type,
        "hours": hours
    }


# Streamlit Operations
@app.get("/streamlit/apps", dependencies=[Depends(require_jwt)])
async def streamlit_apps():
    return await _call_module("streamlit", "/apps")


@app.post("/streamlit/deploy", dependencies=[Depends(require_jwt)])
async def streamlit_deploy(name: str):
    result = await _call_module("streamlit", f"/app/{name}/start", "POST")
    if "error" not in result:
        _record_event("deploy", {"type": "streamlit", "name": name})
        await _notify_webhooks("deploy", {"type": "streamlit", "name": name})
        stats_cache.clear()
    return result


@app.post("/streamlit/stop", dependencies=[Depends(require_jwt)])
async def streamlit_stop(name: str):
    result = await _call_module("streamlit", f"/app/{name}/stop", "POST")
    if "error" not in result:
        _record_event("stop", {"type": "streamlit", "name": name})
        stats_cache.clear()
    return result


# StreamForge Operations
@app.get("/streamforge/templates", dependencies=[Depends(require_jwt)])
async def streamforge_templates():
    return await _call_module("streamforge", "/templates")


@app.post("/streamforge/create", dependencies=[Depends(require_jwt)])
async def streamforge_create(req: CreateAppRequest):
    result = await _call_module("streamforge", "/app", "POST", {"name": req.name, "template": req.template})
    if "error" not in result:
        _record_event("create", {"type": "streamforge", "name": req.name, "template": req.template})
        stats_cache.clear()
    return result


# Droplet Operations
@app.get("/droplet/files", dependencies=[Depends(require_jwt)])
async def droplet_files():
    return await _call_module("droplet", "/list")


@app.post("/droplet/publish", dependencies=[Depends(require_jwt)])
async def droplet_publish(req: PublishRequest):
    result = await _call_module("droplet", "/publish", "POST", {"file": req.file, "domain": req.domain})
    if "error" not in result:
        _record_event("publish", {"type": "droplet", "file": req.file, "domain": req.domain})
        await _notify_webhooks("publish", {"type": "droplet", "file": req.file})
        stats_cache.clear()
    return result


# MetaBlogizer Operations
@app.get("/metablogizer/sites", dependencies=[Depends(require_jwt)])
async def metablogizer_sites():
    return await _call_module("metablogizer", "/sites")


@app.post("/metablogizer/create", dependencies=[Depends(require_jwt)])
async def metablogizer_create(req: CreateSiteRequest):
    result = await _call_module("metablogizer", "/site", "POST", {"name": req.name, "title": req.title})
    if "error" not in result:
        _record_event("create", {"type": "metablogizer", "name": req.name})
        stats_cache.clear()
    return result


@app.post("/metablogizer/publish/{name}", dependencies=[Depends(require_jwt)])
async def metablogizer_publish(name: str):
    result = await _call_module("metablogizer", f"/site/{name}/publish", "POST")
    if "error" not in result:
        _record_event("publish", {"type": "metablogizer", "name": name})
        await _notify_webhooks("publish", {"type": "metablogizer", "name": name})
        stats_cache.clear()
    return result


# Quick Actions
@app.post("/quick-publish", dependencies=[Depends(require_jwt)])
async def quick_publish(req: QuickPublishRequest):
    """Unified quick publish action."""
    if req.content_type == "app":
        result = await _call_module("streamforge", "/app", "POST", {
            "name": req.name,
            "template": req.template or "basic"
        })
        if "error" not in result:
            await _call_module("streamlit", f"/app/{req.name}/start", "POST")
            _record_event("quick_publish", {"type": "app", "name": req.name})
            await _notify_webhooks("deploy", {"type": "app", "name": req.name})
            stats_cache.clear()
        return result

    elif req.content_type == "site":
        result = await _call_module("metablogizer", "/site", "POST", {
            "name": req.name,
            "title": req.data.get("title") if req.data else req.name
        })
        if "error" not in result:
            await _call_module("metablogizer", f"/site/{req.name}/publish", "POST")
            _record_event("quick_publish", {"type": "site", "name": req.name})
            await _notify_webhooks("publish", {"type": "site", "name": req.name})
            stats_cache.clear()
        return result

    elif req.content_type == "file":
        result = await _call_module("droplet", "/publish", "POST", {
            "file": req.name,
            "domain": req.data.get("domain") if req.data else None
        })
        if "error" not in result:
            _record_event("quick_publish", {"type": "file", "name": req.name})
            await _notify_webhooks("publish", {"type": "file", "name": req.name})
            stats_cache.clear()
        return result

    raise HTTPException(400, f"Unknown content type: {req.content_type}")


# History
@app.get("/history", dependencies=[Depends(require_jwt)])
async def get_history(limit: int = 100):
    history = _load_history()
    return {
        "events": history[-limit:],
        "total": len(history)
    }


# Webhooks
@app.get("/webhooks", dependencies=[Depends(require_jwt)])
async def list_webhooks():
    return {"webhooks": _load_webhooks()}


@app.post("/webhooks", dependencies=[Depends(require_jwt)])
async def add_webhook(webhook: WebhookConfig):
    webhooks = _load_webhooks()
    webhook_data = webhook.model_dump()
    webhook_data["id"] = hashlib.md5(webhook.url.encode()).hexdigest()[:8]
    webhook_data["created_at"] = datetime.now().isoformat()
    webhooks.append(webhook_data)
    _save_webhooks(webhooks)
    return {"success": True, "webhook": webhook_data}


@app.delete("/webhooks/{webhook_id}", dependencies=[Depends(require_jwt)])
async def delete_webhook(webhook_id: str):
    webhooks = _load_webhooks()
    webhooks = [w for w in webhooks if w.get("id") != webhook_id]
    _save_webhooks(webhooks)
    return {"success": True}


@app.get("/summary")
async def summary():
    """Get publishing platform summary."""
    status_info = await status()
    stats_info = await stats() if status_info.get("summary", {}).get("running", 0) > 0 else {}

    return {
        "platform_status": status_info.get("status", "unknown"),
        "modules": {
            name: {
                "available": info.get("available", False),
                "running": info.get("running", False)
            }
            for name, info in status_info.get("modules", {}).items()
        },
        "content": {
            "apps": stats_info.get("streamlit", {}).get("total_apps", 0),
            "projects": stats_info.get("streamforge", {}).get("total_projects", 0),
            "files": stats_info.get("droplet", {}).get("total_files", 0),
            "sites": stats_info.get("metablogizer", {}).get("total_sites", 0),
        },
        "webhooks_configured": len(_load_webhooks()),
        "recent_events": _load_history()[-5:],
        "timestamp": datetime.now().isoformat()
    }
