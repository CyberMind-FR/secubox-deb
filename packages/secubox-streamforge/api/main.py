"""SecuBox StreamForge API - Streamlit App Builder with Enhanced Monitoring"""
import os
import subprocess
import shutil
import json
import threading
import time
import asyncio
import hashlib
import hmac
import httpx
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator
from secubox_core.auth import router as auth_router, require_jwt
from secubox_core.config import get_config
from secubox_core.logger import get_logger

app = FastAPI(title="secubox-streamforge", version="2.0.0", root_path="/api/v1/streamforge")
app.include_router(auth_router, prefix="/auth")
router = APIRouter()
log = get_logger("streamforge")

# Configuration
DATA_DIR = Path("/var/lib/secubox/streamforge")
DATA_DIR.mkdir(parents=True, exist_ok=True)
HISTORY_FILE = DATA_DIR / "history.json"
WEBHOOKS_FILE = DATA_DIR / "webhooks.json"
STATS_FILE = DATA_DIR / "stats.json"

APPS_DIR = "/srv/streamlit/apps"
TEMPLATES_DIR = "/usr/share/secubox/streamforge/templates"


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

    def clear(self):
        with self._lock:
            self._cache.clear()
            self._timestamps.clear()


stats_cache = StatsCache(ttl_seconds=15)


# Pydantic Models
class AppCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=50, pattern="^[a-zA-Z0-9_-]+$")
    template: Optional[str] = "basic"
    port: Optional[int] = None
    domain: Optional[str] = None


class FileWrite(BaseModel):
    content: str = Field(..., max_length=500000)


class WebhookConfig(BaseModel):
    url: str
    events: List[str] = Field(default=["app_created", "app_started", "app_stopped", "app_deleted"])
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
_previous_app_states: Dict[str, str] = {}


def _format_bytes(size: int) -> str:
    """Format bytes to human readable string."""
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


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


def _cfg():
    cfg = get_config("streamforge")
    return {
        "apps_dir": cfg.get("apps_dir", APPS_DIR) if cfg else APPS_DIR,
        "templates_dir": cfg.get("templates_dir", TEMPLATES_DIR) if cfg else TEMPLATES_DIR,
    }


def _get_app_status(name: str, port: int) -> str:
    """Check if app is running by port."""
    if not port:
        return "stopped"
    try:
        result = subprocess.run(
            ["ss", "-tln", f"sport = :{port}"],
            capture_output=True, text=True, timeout=5
        )
        return "running" if str(port) in result.stdout else "stopped"
    except Exception:
        return "unknown"


def _get_app_size(app_dir: Path) -> int:
    """Get total size of app directory."""
    total = 0
    try:
        for f in app_dir.rglob("*"):
            if f.is_file():
                total += f.stat().st_size
    except Exception:
        pass
    return total


def _load_apps() -> List[dict]:
    """Load apps from apps directory."""
    apps = []
    apps_dir = Path(_cfg()["apps_dir"])
    if not apps_dir.exists():
        return apps

    cfg = get_config("streamforge") or {}
    app_configs = cfg.get("apps", {})

    for app_dir in apps_dir.iterdir():
        if not app_dir.is_dir() or app_dir.name.startswith("."):
            continue

        name = app_dir.name
        app_cfg = app_configs.get(name, {})
        port = app_cfg.get("port", 0)
        size = _get_app_size(app_dir)

        # Count files
        src_dir = app_dir / "src"
        file_count = len(list(src_dir.rglob("*"))) if src_dir.exists() else 0

        # Get modification time
        try:
            mtime = max(f.stat().st_mtime for f in app_dir.rglob("*") if f.is_file())
            modified = datetime.fromtimestamp(mtime).isoformat()
        except Exception:
            modified = None

        apps.append({
            "name": name,
            "enabled": app_cfg.get("enabled", False),
            "port": port,
            "domain": app_cfg.get("domain", ""),
            "entrypoint": app_cfg.get("entrypoint", "app.py"),
            "memory": app_cfg.get("memory", "512M"),
            "status": _get_app_status(name, port),
            "directory": str(app_dir),
            "size_bytes": size,
            "size_human": _format_bytes(size),
            "file_count": file_count,
            "modified": modified
        })

    return apps


async def _monitor_apps():
    """Background task to monitor app states."""
    global _previous_app_states

    while True:
        try:
            apps = _load_apps()

            for app in apps:
                name = app["name"]
                current_status = app["status"]
                prev_status = _previous_app_states.get(name)

                if prev_status is not None and prev_status != current_status:
                    if current_status == "running":
                        event = "app_started"
                    elif current_status == "stopped":
                        event = "app_stopped"
                    else:
                        event = "app_status_changed"

                    _record_event(event, {"app": name, "status": current_status})
                    await _notify_webhooks(event, {"app": name, "status": current_status})

                _previous_app_states[name] = current_status

        except Exception:
            pass

        await asyncio.sleep(30)


@app.on_event("startup")
async def startup():
    """Start background monitoring."""
    global _monitoring_task
    _monitoring_task = asyncio.create_task(_monitor_apps())


@app.on_event("shutdown")
async def shutdown():
    """Stop background monitoring."""
    global _monitoring_task
    if _monitoring_task:
        _monitoring_task.cancel()


# Public endpoints
@router.get("/health")
async def health():
    return {"status": "ok", "module": "streamforge", "version": "2.0.0"}


@router.get("/status")
async def status():
    """StreamForge status (public)."""
    cached = stats_cache.get("status")
    if cached:
        return cached

    apps = _load_apps()
    running = sum(1 for a in apps if a["status"] == "running")
    total_size = sum(a.get("size_bytes", 0) for a in apps)

    result = {
        "app_count": len(apps),
        "running_count": running,
        "stopped_count": len(apps) - running,
        "total_size": total_size,
        "total_size_human": _format_bytes(total_size),
        "apps_dir": _cfg()["apps_dir"],
        "timestamp": datetime.now().isoformat()
    }

    stats_cache.set("status", result)
    return result


@router.get("/apps")
async def list_apps():
    """List all apps (public)."""
    cached = stats_cache.get("apps")
    if cached:
        return cached

    apps = _load_apps()
    result = {
        "apps": apps,
        "count": len(apps),
        "running": sum(1 for a in apps if a["status"] == "running")
    }

    stats_cache.set("apps", result)
    return result


@router.get("/templates")
async def list_templates():
    """List available templates (public)."""
    templates = []
    tpl_dir = Path(_cfg()["templates_dir"])
    if tpl_dir.exists():
        for tpl in tpl_dir.iterdir():
            if tpl.is_dir():
                readme = tpl / "README.md"
                desc = readme.read_text()[:200] if readme.exists() else ""
                templates.append({
                    "name": tpl.name,
                    "description": desc,
                    "files": len(list(tpl.glob("*")))
                })
    return {"templates": templates, "count": len(templates)}


# Protected endpoints
@router.get("/app/{name}")
async def get_app(name: str, user=Depends(require_jwt)):
    """Get app details."""
    apps = _load_apps()
    for a in apps:
        if a["name"] == name:
            app_dir = Path(a["directory"])
            files = []
            src_dir = app_dir / "src"
            if src_dir.exists():
                for f in src_dir.rglob("*"):
                    if f.is_file():
                        rel_path = f.relative_to(src_dir)
                        files.append({
                            "name": str(rel_path),
                            "size": f.stat().st_size,
                            "size_human": _format_bytes(f.stat().st_size)
                        })
            a["files"] = files[:50]  # Limit to 50 files

            # Get recent history for this app
            history = _load_history()
            a["recent_events"] = [
                h for h in history[-50:]
                if h.get("details", {}).get("app") == name
            ][-10:]

            return a
    raise HTTPException(404, f"App not found: {name}")


@router.post("/app")
async def create_app(req: AppCreate, user=Depends(require_jwt)):
    """Create a new app."""
    apps_dir = Path(_cfg()["apps_dir"])
    app_dir = apps_dir / req.name

    if app_dir.exists():
        raise HTTPException(400, f"App already exists: {req.name}")

    try:
        app_dir.mkdir(parents=True)
        src_dir = app_dir / "src"
        src_dir.mkdir()

        # Copy template or create basic app.py
        tpl_dir = Path(_cfg()["templates_dir"]) / (req.template or "basic")
        if tpl_dir.exists():
            shutil.copytree(tpl_dir, src_dir, dirs_exist_ok=True)
        else:
            (src_dir / "app.py").write_text('''import streamlit as st

st.set_page_config(page_title="My App", layout="wide")
st.title("Welcome to Streamlit!")
st.write("Edit src/app.py to customize this app.")
''')
            (src_dir / "requirements.txt").write_text("streamlit\n")

        log.info("Created app: %s", req.name)
        _record_event("app_created", {
            "app": req.name,
            "template": req.template,
            "by": user.get("sub", "unknown")
        })
        await _notify_webhooks("app_created", {"app": req.name, "template": req.template})
        stats_cache.clear()

        return {
            "success": True,
            "name": req.name,
            "directory": str(app_dir),
            "template": req.template
        }

    except Exception as e:
        log.error("Failed to create app %s: %s", req.name, e)
        raise HTTPException(500, str(e))


@router.post("/app/{name}/start")
async def start_app(name: str, user=Depends(require_jwt)):
    """Start an app."""
    apps = _load_apps()
    app = next((a for a in apps if a["name"] == name), None)
    if not app:
        raise HTTPException(404, f"App not found: {name}")

    port = app.get("port") or 8501
    app_dir = Path(app["directory"]) / "src"
    entrypoint = app.get("entrypoint", "app.py")

    # Start streamlit in background
    result = subprocess.run(
        ["systemctl", "start", f"streamlit-app@{name}"],
        capture_output=True, text=True, timeout=10
    )

    if result.returncode != 0:
        # Fallback: direct start
        subprocess.Popen(
            ["streamlit", "run", str(app_dir / entrypoint), "--server.port", str(port)],
            cwd=str(app_dir),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    log.info("Started app: %s on port %d", name, port)
    _record_event("app_started", {"app": name, "port": port, "by": user.get("sub", "unknown")})
    await _notify_webhooks("app_started", {"app": name, "port": port})
    stats_cache.clear()

    return {"success": True, "name": name, "port": port}


@router.post("/app/{name}/stop")
async def stop_app(name: str, user=Depends(require_jwt)):
    """Stop an app."""
    result = subprocess.run(
        ["systemctl", "stop", f"streamlit-app@{name}"],
        capture_output=True, text=True, timeout=10
    )

    if result.returncode != 0:
        subprocess.run(["pkill", "-f", f"streamlit.*{name}"], timeout=5)

    log.info("Stopped app: %s", name)
    _record_event("app_stopped", {"app": name, "by": user.get("sub", "unknown")})
    await _notify_webhooks("app_stopped", {"app": name})
    stats_cache.clear()

    return {"success": True, "name": name}


@router.post("/app/{name}/restart")
async def restart_app(name: str, user=Depends(require_jwt)):
    """Restart an app."""
    await stop_app(name, user)
    await asyncio.sleep(1)
    return await start_app(name, user)


@router.delete("/app/{name}")
async def delete_app(name: str, user=Depends(require_jwt)):
    """Delete an app."""
    apps_dir = Path(_cfg()["apps_dir"])
    app_dir = apps_dir / name

    if not app_dir.exists():
        raise HTTPException(404, f"App not found: {name}")

    # Stop first
    subprocess.run(["systemctl", "stop", f"streamlit-app@{name}"], timeout=5)

    shutil.rmtree(app_dir)
    log.info("Deleted app: %s", name)
    _record_event("app_deleted", {"app": name, "by": user.get("sub", "unknown")})
    await _notify_webhooks("app_deleted", {"app": name})
    stats_cache.clear()

    return {"success": True, "name": name}


# File Operations
@router.get("/app/{name}/file/{path:path}")
async def read_file(name: str, path: str, user=Depends(require_jwt)):
    """Read a file from app."""
    apps_dir = Path(_cfg()["apps_dir"])
    file_path = apps_dir / name / "src" / path

    if not file_path.exists():
        raise HTTPException(404, "File not found")
    if not file_path.is_file():
        raise HTTPException(400, "Not a file")

    try:
        file_path.resolve().relative_to((apps_dir / name).resolve())
    except ValueError:
        raise HTTPException(403, "Access denied")

    return {
        "content": file_path.read_text()[:50000],
        "path": path,
        "size": file_path.stat().st_size
    }


@router.put("/app/{name}/file/{path:path}")
async def write_file(name: str, path: str, req: FileWrite, user=Depends(require_jwt)):
    """Write a file to app."""
    apps_dir = Path(_cfg()["apps_dir"])
    file_path = apps_dir / name / "src" / path

    try:
        file_path.resolve().relative_to((apps_dir / name).resolve())
    except ValueError:
        raise HTTPException(403, "Access denied")

    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text(req.content)

    log.info("Wrote file: %s/%s", name, path)
    _record_event("file_written", {"app": name, "path": path, "by": user.get("sub", "unknown")})
    stats_cache.clear()

    return {"success": True, "path": path, "size": len(req.content)}


# History
@router.get("/history")
async def get_history(limit: int = 100, app: Optional[str] = None, user=Depends(require_jwt)):
    """Get event history."""
    history = _load_history()

    if app:
        history = [h for h in history if h.get("details", {}).get("app") == app]

    return {
        "events": history[-limit:],
        "total": len(history)
    }


# Webhooks
@router.get("/webhooks")
async def list_webhooks(user=Depends(require_jwt)):
    return {"webhooks": _load_webhooks()}


@router.post("/webhooks")
async def add_webhook(webhook: WebhookConfig, user=Depends(require_jwt)):
    webhooks = _load_webhooks()
    webhook_data = webhook.model_dump()
    webhook_data["id"] = hashlib.md5(webhook.url.encode()).hexdigest()[:8]
    webhook_data["created_at"] = datetime.now().isoformat()
    webhooks.append(webhook_data)
    _save_webhooks(webhooks)
    return {"success": True, "webhook": webhook_data}


@router.delete("/webhooks/{webhook_id}")
async def delete_webhook(webhook_id: str, user=Depends(require_jwt)):
    webhooks = _load_webhooks()
    webhooks = [w for w in webhooks if w.get("id") != webhook_id]
    _save_webhooks(webhooks)
    return {"success": True}


@router.get("/summary")
async def summary():
    """Get StreamForge summary."""
    status_info = await status()
    apps = _load_apps()

    return {
        "apps": {
            "total": status_info["app_count"],
            "running": status_info["running_count"],
            "stopped": status_info["stopped_count"]
        },
        "storage": {
            "total": status_info["total_size_human"],
            "by_app": {a["name"]: a["size_human"] for a in apps[:10]}
        },
        "templates": len(list(Path(_cfg()["templates_dir"]).glob("*"))) if Path(_cfg()["templates_dir"]).exists() else 0,
        "recent_events": _load_history()[-5:],
        "webhooks_configured": len(_load_webhooks()),
        "timestamp": datetime.now().isoformat()
    }


app.include_router(router)
