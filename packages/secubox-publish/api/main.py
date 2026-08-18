# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""SecuBox Publishing Platform - Unified Dashboard with Enhanced Monitoring

Layer 2 orchestrator module that provides a unified interface to all publishing modules.
Follows the 2-layer architecture: simple UI -> aggregated API -> individual module APIs.

ISP Home Publish feature: Upload ZIP → Auto-detect type → Publish → Download bundle
"""
import httpx
import json
import threading
import time
import asyncio
import hashlib
import hmac
import zipfile
import tarfile
import shutil
import tempfile
import importlib.util
import io
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional, Callable
import contextvars
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Form, Request
from fastapi.responses import StreamingResponse, FileResponse
from pydantic import BaseModel, Field, field_validator
from secubox_core.auth import require_jwt
from secubox_core.config import get_config

app = FastAPI(title="SecuBox Publishing Platform", version="3.0.0")

# Auth-forwarding for inter-module calls. Sibling module endpoints are all
# require_jwt, so _call_module must present the ORIGINAL caller's credentials —
# a freshly minted service token would carry a jti absent from sessions.json and
# be rejected ("Session révoquée"). A middleware stashes the caller's bearer/
# cookie into this ContextVar for the duration of the request; _call_module
# reads it. Background tasks (health/status polling) run with no token — fine,
# those sibling endpoints are public.
_caller_token: contextvars.ContextVar = contextvars.ContextVar("sbx_caller_token", default="")


@app.middleware("http")
async def _capture_caller_token(request: Request, call_next):
    tok = ""
    auth = request.headers.get("authorization", "")
    if auth[:7].lower() == "bearer ":
        tok = auth[7:].strip()
    if not tok:
        tok = request.cookies.get("secubox_session", "")
    reset = _caller_token.set(tok)
    try:
        return await call_next(request)
    finally:
        _caller_token.reset(reset)

# Configuration
DATA_DIR = Path("/var/lib/secubox/publish")
DATA_DIR.mkdir(parents=True, exist_ok=True)
HISTORY_FILE = DATA_DIR / "history.json"
WEBHOOKS_FILE = DATA_DIR / "webhooks.json"
STATS_FILE = DATA_DIR / "stats.json"
BUNDLES_DIR = DATA_DIR / "bundles"
BUNDLES_DIR.mkdir(parents=True, exist_ok=True)
PLUGINS_DIR = Path("/srv/secubox/modules/publish/plugins")
PLUGINS_DIR.mkdir(parents=True, exist_ok=True)

# Sibling modules are served in-process by the aggregator; we reach them with an
# authenticated call to the aggregator socket at /api/v1/<module>/... The old
# per-module standalone sockets (droplet.sock, streamlit.sock, …) are not
# running, so targeting them directly always failed (connection refused).
AGGREGATOR_SOCK = "/run/secubox/aggregator.sock"
MODULES = {"streamlit", "streamforge", "droplet", "metablogizer"}

# Content type detection patterns
CONTENT_SIGNATURES = {
    "streamlit": ["app.py", "streamlit_app.py", "main.py", "requirements.txt"],
    "static": ["index.html", "index.htm", "default.html"],
    "hugo": ["config.toml", "hugo.toml", "config.yaml"],
    "jekyll": ["_config.yml", "Gemfile"],
    "hexo": ["_config.yml", "package.json", "themes/"],
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


class ISPPublishResult(BaseModel):
    """Result of ISP Home Publish operation."""
    success: bool
    name: str
    domain: str
    content_type: str
    url: Optional[str] = None
    download_url: Optional[str] = None
    qrcode_url: Optional[str] = None
    files_count: int = 0
    detected_files: List[str] = []
    infrastructure: Dict[str, Any] = {}
    message: str = ""


class PluginInfo(BaseModel):
    """Plugin metadata."""
    name: str
    version: str
    description: str
    author: str
    hooks: List[str] = []
    enabled: bool = True


# Plugin system
class PluginManager:
    """Module injection plugin system for extending publish capabilities."""

    def __init__(self):
        self._plugins: Dict[str, Any] = {}
        self._hooks: Dict[str, List[Callable]] = {
            "pre_upload": [],
            "post_upload": [],
            "pre_publish": [],
            "post_publish": [],
            "content_detect": [],
            "bundle_create": [],
            "bundle_extract": [],
        }

    def load_plugins(self):
        """Load all plugins from plugins directory."""
        if not PLUGINS_DIR.exists():
            return

        for plugin_file in PLUGINS_DIR.glob("*.py"):
            if plugin_file.name.startswith("_"):
                continue
            try:
                spec = importlib.util.spec_from_file_location(
                    plugin_file.stem, plugin_file
                )
                if spec and spec.loader:
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)

                    if hasattr(module, "PLUGIN_INFO"):
                        info = module.PLUGIN_INFO
                        self._plugins[info.get("name", plugin_file.stem)] = {
                            "module": module,
                            "info": info,
                        }

                        # Register hooks
                        for hook_name in self._hooks:
                            if hasattr(module, f"hook_{hook_name}"):
                                self._hooks[hook_name].append(
                                    getattr(module, f"hook_{hook_name}")
                                )
            except Exception as e:
                print(f"Failed to load plugin {plugin_file}: {e}")

    async def run_hook(self, hook_name: str, **kwargs) -> Dict[str, Any]:
        """Run all registered hooks for a given hook point."""
        results = {}
        for handler in self._hooks.get(hook_name, []):
            try:
                if asyncio.iscoroutinefunction(handler):
                    result = await handler(**kwargs)
                else:
                    result = handler(**kwargs)
                if result:
                    results.update(result)
            except Exception as e:
                results[f"error_{handler.__name__}"] = str(e)
        return results

    def list_plugins(self) -> List[Dict[str, Any]]:
        """List all loaded plugins."""
        return [
            {
                "name": name,
                "info": data.get("info", {}),
            }
            for name, data in self._plugins.items()
        ]


plugin_manager = PluginManager()


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


async def _call_module(module: str, path: str, method: str = "GET", data: dict = None, timeout: int = 30) -> dict:
    """Call a module's API via Unix socket."""
    if module not in MODULES:
        return {"error": f"Unknown module: {module}"}

    # Route through the aggregator at /api/v1/<module><path>, forwarding the
    # caller's credentials so the sibling's require_jwt accepts the call.
    url = f"/api/v1/{module}{path}"
    headers = {}
    tok = _caller_token.get()
    if tok:
        headers["Authorization"] = f"Bearer {tok}"

    try:
        transport = httpx.AsyncHTTPTransport(uds=AGGREGATOR_SOCK)
        async with httpx.AsyncClient(transport=transport, base_url="http://localhost",
                                     timeout=timeout, headers=headers) as client:
            if method == "GET":
                resp = await client.get(url)
            elif method == "POST":
                resp = await client.post(url, json=data or {})
            elif method == "DELETE":
                resp = await client.delete(url)
            else:
                return {"error": f"Unsupported method: {method}"}
            try:
                return resp.json()
            except Exception:
                return {"error": f"non-json response {resp.status_code}", "status": resp.status_code}
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
    """Start background monitoring and load plugins."""
    global _monitoring_task
    _monitoring_task = asyncio.create_task(_monitor_modules())
    plugin_manager.load_plugins()


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


# ══════════════════════════════════════════════════════════════════════════════
# ISP Home Publish — Upload ZIP → Auto-detect → Publish → Download Bundle
# ══════════════════════════════════════════════════════════════════════════════

def _detect_content_type(extracted_path: Path) -> str:
    """Auto-detect content type from extracted files."""
    files = set()
    for f in extracted_path.rglob("*"):
        if f.is_file():
            files.add(f.name)
            files.add(f.relative_to(extracted_path).as_posix())

    # Check each signature pattern
    for content_type, patterns in CONTENT_SIGNATURES.items():
        matches = sum(1 for p in patterns if any(p in f for f in files))
        if matches >= 1:
            return content_type

    # Default to static if index.html exists anywhere
    if any("index.html" in f or "index.htm" in f for f in files):
        return "static"

    return "unknown"


def _extract_archive(file_path: Path, extract_to: Path) -> List[str]:
    """Extract ZIP or TAR archive and return list of files."""
    extracted_files = []

    if file_path.suffix == ".zip" or str(file_path).endswith(".zip"):
        with zipfile.ZipFile(file_path, "r") as zf:
            zf.extractall(extract_to)
            extracted_files = zf.namelist()
    elif file_path.suffix in (".tar", ".gz", ".tgz", ".bz2"):
        with tarfile.open(file_path, "r:*") as tf:
            tf.extractall(extract_to)
            extracted_files = tf.getnames()
    else:
        # Single file - just copy
        shutil.copy(file_path, extract_to / file_path.name)
        extracted_files = [file_path.name]

    return extracted_files


async def _prepare_infrastructure(name: str, domain: str, content_type: str) -> Dict[str, Any]:
    """
    Prepare full infrastructure for publishing:
    - MetaBlogizer site
    - Nginx VHost
    - HAProxy VHost + ACL
    - MITMProxy WAF route
    - SSL Certificate
    - Vortex DNS record (if available)

    Returns status dict with infrastructure component statuses.
    """
    infra_status: Dict[str, Any] = {
        "metablogizer": {"status": "pending"},
        "vhost": {"status": "pending"},
        "haproxy": {"status": "pending"},
        "mitmproxy": {"status": "pending"},
        "certificate": {"status": "pending"},
        "dns": {"status": "pending"},
    }

    # 1. Create metablogizer site (60s timeout for file operations)
    try:
        result = await _call_module("metablogizer", "/site", "POST", {
            "name": name,
            "domain": domain,
        }, timeout=60)
        infra_status["metablogizer"] = {
            "status": "ok" if "error" not in result else "error",
            "details": result,
        }
    except Exception as e:
        infra_status["metablogizer"] = {"status": "error", "error": str(e)}

    # 2-5. Routing + cert are owned by metablogizer's publisher wizard, which
    #      performs them through the secubox-publishctl root helper. This hub
    #      runs as unprivileged `secubox` and MUST NOT write /etc/nginx or
    #      /etc/haproxy or the WAF route file directly (those writes silently
    #      failed — the root cause of published sites answering 421).
    try:
        route = await _call_module("metablogizer", "/publish/route", "POST",
                                   {"domain": domain}, timeout=60)
        rok = bool(route.get("ok"))
        cert = route.get("cert") or {}
        infra_status["vhost"] = {"status": "ok" if rok else "error", "details": route.get("route")}
        infra_status["haproxy"] = {"status": "ok" if rok else "error", "details": "routed via metablogizer wizard"}
        infra_status["mitmproxy"] = {"status": "ok" if rok else "error", "details": route.get("route")}
        infra_status["certificate"] = {
            "status": "ok" if cert.get("mode") in ("wildcard", "issued") else "pending",
            "details": cert,
        }
    except Exception as e:  # noqa: BLE001 — never let provisioning break the response
        infra_status["vhost"] = {"status": "error", "error": str(e)}
        infra_status["certificate"] = {"status": "error", "error": str(e)}

    # 6. DNS - gk2.secubox.in domains use wildcard DNS
    if domain.endswith(".gk2.secubox.in"):
        infra_status["dns"] = {"status": "ok", "details": "Wildcard DNS active"}
    else:
        infra_status["dns"] = {"status": "pending", "details": "Manual DNS needed"}

    return infra_status


async def _publish_to_module(content_type: str, name: str, source_path: Path, domain: Optional[str] = None) -> Dict[str, Any]:
    """Route content to appropriate publishing module."""
    if content_type == "streamlit":
        # Copy to streamlit apps directory and start
        result = await _call_module("streamlit", "/app", "POST", {
            "name": name,
            "source": str(source_path),
        })
        if "error" not in result:
            await _call_module("streamlit", f"/app/{name}/start", "POST")
        return result

    elif content_type in ("static", "hugo", "jekyll", "hexo"):
        # Create metablogizer site and upload content
        await _call_module("metablogizer", "/site", "POST", {"name": name})

        # Create ZIP of content for upload
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            for file in source_path.rglob("*"):
                if file.is_file():
                    zf.write(file, file.relative_to(source_path))
        zip_buffer.seek(0)

        # Upload via metablogizer
        result = await _call_module("metablogizer", f"/site/{name}/upload", "POST", {
            "content": zip_buffer.getvalue().hex(),
        })

        if "error" not in result:
            await _call_module("metablogizer", f"/site/{name}/publish", "POST")

        return result

    else:
        # Default: use droplet for unknown types
        result = await _call_module("droplet", "/upload", "POST", {
            "name": name,
            "source": str(source_path),
            "domain": domain,
        })
        return result


@app.post("/isp/upload", dependencies=[Depends(require_jwt)])
async def isp_upload(
    file: UploadFile = File(...),
    name: Optional[str] = Form(None),
    domain: Optional[str] = Form(None),
    auto_publish: bool = Form(True),
):
    """
    ISP Home Publish: Upload ZIP/HTML → Auto-detect type → Publish

    This is the main entry point for the "first ISP home publish all" feature.
    Accepts ZIP, TAR.GZ, or HTML files and automatically:
    1. Detects content type (Streamlit app, static site, Hugo, Jekyll, etc.)
    2. Routes to appropriate publishing module (streamlit, metablogizer, droplet)
    3. Publishes and returns live URL + downloadable bundle URL
    """
    # Run pre-upload hooks (results used by plugins for validation/logging)
    await plugin_manager.run_hook("pre_upload", file=file, name=name)

    # Generate name if not provided
    if not name:
        name = Path(file.filename).stem if file.filename else f"publish-{int(time.time())}"
    name = name.lower().replace(" ", "-").replace("_", "-")

    # Save uploaded file
    temp_dir = Path(tempfile.mkdtemp(prefix="isp_publish_"))
    upload_path = temp_dir / (file.filename or "upload.zip")

    try:
        content = await file.read()
        upload_path.write_bytes(content)

        # Extract archive
        extract_dir = temp_dir / "extracted"
        extract_dir.mkdir()
        extracted_files = _extract_archive(upload_path, extract_dir)

        # Run content detection hooks
        hook_detect = await plugin_manager.run_hook("content_detect", path=extract_dir, files=extracted_files)

        # Auto-detect content type
        content_type = hook_detect.get("content_type") or _detect_content_type(extract_dir)

        # Run pre-publish hooks
        await plugin_manager.run_hook("pre_publish", name=name, content_type=content_type, path=extract_dir)

        # Publish if auto_publish is enabled
        result = {"success": False, "message": "Upload only, not published"}
        url = None
        infra_status = {}

        # Determine final domain
        final_domain = domain or f"{name}.gk2.secubox.in"

        if auto_publish:
            # Prepare full infrastructure first
            infra_status = await _prepare_infrastructure(name, final_domain, content_type)

            # Then publish content to module
            result = await _publish_to_module(content_type, name, extract_dir, final_domain)

            if "error" not in result:
                # Determine URL based on content type
                if content_type == "streamlit":
                    url = f"/apps/{name}/"
                elif content_type in ("static", "hugo", "jekyll", "hexo"):
                    url = f"https://{final_domain}/"
                else:
                    url = result.get("url")

        # Create downloadable bundle
        bundle_path = BUNDLES_DIR / f"{name}.zip"
        with zipfile.ZipFile(bundle_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for file_path in extract_dir.rglob("*"):
                if file_path.is_file():
                    zf.write(file_path, file_path.relative_to(extract_dir))

        # Record event
        _record_event("isp_publish", {
            "name": name,
            "content_type": content_type,
            "files_count": len(extracted_files),
            "auto_publish": auto_publish,
            "domain": domain,
        })

        # Run post-publish hooks
        await plugin_manager.run_hook("post_publish", name=name, content_type=content_type, url=url)

        # Notify webhooks
        await _notify_webhooks("publish", {
            "type": "isp_home",
            "name": name,
            "content_type": content_type,
            "url": url,
        })

        stats_cache.clear()

        return ISPPublishResult(
            success="error" not in result,
            name=name,
            domain=final_domain,
            content_type=content_type,
            url=url,
            download_url=f"/api/v1/publish/bundle/{name}.zip",
            qrcode_url=f"/api/v1/publish/bundle/{name}/qrcode" if url else None,
            files_count=len(extracted_files),
            detected_files=extracted_files[:20],
            infrastructure=infra_status,
            message=result.get("message", "Published successfully" if "error" not in result else result.get("error", "Unknown error")),
        )

    except Exception as e:
        _record_event("isp_publish_error", {"name": name, "error": str(e)})
        raise HTTPException(500, f"Publishing failed: {str(e)}")

    finally:
        # Cleanup temp directory (keep bundle)
        shutil.rmtree(temp_dir, ignore_errors=True)


@app.get("/bundle/{name}.zip")
async def download_bundle(name: str):
    """
    Download published content as ZIP bundle.

    This enables the "zip downloadable from the banner" feature.
    """
    bundle_path = BUNDLES_DIR / f"{name}.zip"

    if not bundle_path.exists():
        # Try to create bundle from metablogizer
        result = await _call_module("metablogizer", f"/site/{name}/export")
        if "error" in result:
            raise HTTPException(404, f"Bundle not found: {name}")

        # Save the export
        if "content" in result:
            bundle_path.write_bytes(bytes.fromhex(result["content"]))

    if not bundle_path.exists():
        raise HTTPException(404, f"Bundle not found: {name}")

    return FileResponse(
        path=bundle_path,
        filename=f"{name}.zip",
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{name}.zip"',
            "X-SecuBox-Bundle": name,
        }
    )


@app.get("/bundle/{name}/qrcode")
async def bundle_qrcode(name: str):
    """Generate QR code for bundle download URL."""
    try:
        import qrcode  # type: ignore
        from io import BytesIO

        # Generate QR code for bundle URL
        bundle_url = f"/api/v1/publish/bundle/{name}.zip"

        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(bundle_url)
        qr.make(fit=True)

        img = qr.make_image(fill_color="#c9a84c", back_color="#0a0a0f")

        buffer = BytesIO()
        img.save(buffer)  # PIL Image save defaults to PNG
        buffer.seek(0)

        return StreamingResponse(buffer, media_type="image/png")

    except ImportError:
        raise HTTPException(501, "QR code generation requires 'qrcode' package")


@app.get("/bundles", dependencies=[Depends(require_jwt)])
async def list_bundles():
    """List all available download bundles."""
    bundles = []

    for bundle_file in BUNDLES_DIR.glob("*.zip"):
        stat = bundle_file.stat()
        bundles.append({
            "name": bundle_file.stem,
            "filename": bundle_file.name,
            "size_bytes": stat.st_size,
            "size_human": f"{stat.st_size / 1024 / 1024:.1f} MB",
            "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
            "download_url": f"/api/v1/publish/bundle/{bundle_file.name}",
        })

    return {
        "bundles": sorted(bundles, key=lambda x: x["created"], reverse=True),
        "total": len(bundles),
    }


@app.delete("/bundle/{name}", dependencies=[Depends(require_jwt)])
async def delete_bundle(name: str):
    """Delete a bundle."""
    bundle_path = BUNDLES_DIR / f"{name}.zip"

    if not bundle_path.exists():
        raise HTTPException(404, f"Bundle not found: {name}")

    bundle_path.unlink()
    _record_event("bundle_deleted", {"name": name})

    return {"success": True, "message": f"Bundle {name} deleted"}


# ══════════════════════════════════════════════════════════════════════════════
# Plugin System — Module Injection Enhancer
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/plugins", dependencies=[Depends(require_jwt)])
async def list_plugins():
    """List all loaded plugins."""
    return {
        "plugins": plugin_manager.list_plugins(),
        "hooks": list(plugin_manager._hooks.keys()),
    }


@app.post("/plugins/reload", dependencies=[Depends(require_jwt)])
async def reload_plugins():
    """Reload all plugins from disk."""
    plugin_manager._plugins.clear()
    for hook_list in plugin_manager._hooks.values():
        hook_list.clear()

    plugin_manager.load_plugins()

    return {
        "success": True,
        "loaded": len(plugin_manager._plugins),
        "plugins": plugin_manager.list_plugins(),
    }


# ══════════════════════════════════════════════════════════════════════════════
# Banner Integration — Eyemote Download Links
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/banner/links")
async def banner_links():
    """
    Get links for eyemote banner integration.
    Returns URLs that can be embedded in the SVG banner for direct downloads.
    """
    bundles = []

    for bundle_file in sorted(BUNDLES_DIR.glob("*.zip"), key=lambda x: x.stat().st_mtime, reverse=True)[:5]:
        bundles.append({
            "name": bundle_file.stem,
            "url": f"/api/v1/publish/bundle/{bundle_file.name}",
            "size": f"{bundle_file.stat().st_size / 1024:.0f}K",
        })

    return {
        "publish_url": "/api/v1/publish/isp/upload",
        "bundles": bundles,
        "recent_count": len(bundles),
    }
