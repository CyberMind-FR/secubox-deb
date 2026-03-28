"""SecuBox Webmail API - Roundcube/SOGo Management with Enhanced Monitoring"""
import subprocess
import os
import json
import threading
import time
import asyncio
import hashlib
import hmac
import httpx
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, Depends, BackgroundTasks
from pydantic import BaseModel, Field, field_validator
from secubox_core.auth import require_jwt
from secubox_core.config import get_config

app = FastAPI(title="SecuBox Webmail")
config = get_config("webmail")

# Configuration
DATA_DIR = Path("/var/lib/secubox/webmail")
DATA_DIR.mkdir(parents=True, exist_ok=True)
WEBHOOKS_FILE = DATA_DIR / "webhooks.json"
STATS_FILE = DATA_DIR / "stats.json"
HISTORY_FILE = DATA_DIR / "history.json"


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
class WebmailConfig(BaseModel):
    default_host: Optional[str] = None
    smtp_server: Optional[str] = None
    plugins: Optional[List[str]] = None


class WebhookConfig(BaseModel):
    url: str
    events: List[str] = Field(default=["service_down", "service_up", "error"])
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
_previous_running: Optional[bool] = None


def check_service(name: str) -> bool:
    """Check if systemd service is running."""
    try:
        result = subprocess.run(
            ["systemctl", "is-active", name],
            capture_output=True, text=True, timeout=5
        )
        return result.stdout.strip() == "active"
    except Exception:
        return False


def get_webmail_type() -> str:
    """Detect installed webmail type."""
    if os.path.exists("/etc/roundcube"):
        return "roundcube"
    elif os.path.exists("/etc/sogo"):
        return "sogo"
    return "none"


def get_service_name() -> Optional[str]:
    """Get the main service name for this webmail type."""
    webmail_type = get_webmail_type()
    if webmail_type == "roundcube":
        return "php-fpm"
    elif webmail_type == "sogo":
        return "sogo"
    return None


def get_storage_stats() -> Dict[str, Any]:
    """Get webmail storage statistics."""
    webmail_type = get_webmail_type()
    stats = {"type": webmail_type, "storage_bytes": 0, "cache_bytes": 0}

    try:
        if webmail_type == "roundcube":
            # Check Roundcube data directories
            data_dir = Path("/var/lib/roundcube")
            cache_dir = Path("/var/lib/roundcube/temp")
            log_dir = Path("/var/log/roundcube")

            if data_dir.exists():
                stats["storage_bytes"] = sum(
                    f.stat().st_size for f in data_dir.rglob("*") if f.is_file()
                )
            if cache_dir.exists():
                stats["cache_bytes"] = sum(
                    f.stat().st_size for f in cache_dir.rglob("*") if f.is_file()
                )
            if log_dir.exists():
                stats["log_bytes"] = sum(
                    f.stat().st_size for f in log_dir.rglob("*") if f.is_file()
                )

        elif webmail_type == "sogo":
            # Check SOGo data directories
            data_dir = Path("/var/lib/sogo")
            log_dir = Path("/var/log/sogo")

            if data_dir.exists():
                stats["storage_bytes"] = sum(
                    f.stat().st_size for f in data_dir.rglob("*") if f.is_file()
                )
            if log_dir.exists():
                stats["log_bytes"] = sum(
                    f.stat().st_size for f in log_dir.rglob("*") if f.is_file()
                )
    except Exception:
        pass

    return stats


def _format_bytes(size: int) -> str:
    """Format bytes to human readable string."""
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def get_active_sessions() -> int:
    """Get count of active webmail sessions."""
    webmail_type = get_webmail_type()
    try:
        if webmail_type == "roundcube":
            session_dir = Path("/var/lib/php/sessions")
            if session_dir.exists():
                return len(list(session_dir.glob("sess_*")))
        elif webmail_type == "sogo":
            # SOGo stores sessions in database, try to count
            result = subprocess.run(
                ["sogo-tool", "sessions-count"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                try:
                    return int(result.stdout.strip())
                except ValueError:
                    pass
    except Exception:
        pass
    return 0


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
    """Load event history from file."""
    if HISTORY_FILE.exists():
        try:
            return json.loads(HISTORY_FILE.read_text())
        except Exception:
            pass
    return []


def _save_history(history: List[Dict[str, Any]]):
    """Save event history to file."""
    history = history[-500:]
    HISTORY_FILE.write_text(json.dumps(history, indent=2))


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


async def _monitor_service():
    """Background task to monitor webmail service."""
    global _previous_running

    while True:
        try:
            webmail_type = get_webmail_type()
            if webmail_type != "none":
                service_name = get_service_name()
                running = check_service(service_name) if service_name else False

                if _previous_running is not None and _previous_running != running:
                    event = "service_up" if running else "service_down"
                    event_data = {
                        "type": webmail_type,
                        "service": service_name,
                        "running": running
                    }
                    _record_event(event, event_data)
                    await _notify_webhooks(event, event_data)

                _previous_running = running

        except Exception:
            pass

        await asyncio.sleep(30)


@app.on_event("startup")
async def startup():
    """Start background monitoring."""
    global _monitoring_task
    _monitoring_task = asyncio.create_task(_monitor_service())


@app.on_event("shutdown")
async def shutdown():
    """Stop background monitoring."""
    global _monitoring_task
    if _monitoring_task:
        _monitoring_task.cancel()


# Public endpoints
@app.get("/status")
async def status():
    """Get webmail status."""
    cached = stats_cache.get("status")
    if cached:
        return cached

    webmail_type = get_webmail_type()
    service_name = get_service_name()

    if webmail_type == "roundcube":
        running = check_service("apache2") or check_service("nginx") or check_service("php-fpm")
    elif webmail_type == "sogo":
        running = check_service("sogo")
    else:
        running = False

    result = {
        "type": webmail_type,
        "service": service_name,
        "running": running,
        "url": config.get("url", "/webmail"),
        "mail_server": config.get("mail_server", "localhost"),
        "active_sessions": get_active_sessions() if running else 0,
        "timestamp": datetime.now().isoformat()
    }

    stats_cache.set("status", result)
    return result


@app.get("/health")
async def health_check():
    """Get webmail health status."""
    webmail_type = get_webmail_type()

    if webmail_type == "none":
        return {"status": "not_installed", "checks": {}}

    checks = {}
    service_name = get_service_name()

    # Service check
    checks["service"] = check_service(service_name) if service_name else False

    # Database check (for SOGo)
    if webmail_type == "sogo":
        try:
            result = subprocess.run(
                ["sogo-tool", "check-tables"],
                capture_output=True, text=True, timeout=10
            )
            checks["database"] = result.returncode == 0
        except Exception:
            checks["database"] = False

    # Web server check
    checks["webserver"] = check_service("nginx") or check_service("apache2")

    all_ok = all(checks.values())

    return {
        "status": "healthy" if all_ok else "degraded",
        "type": webmail_type,
        "checks": checks,
        "timestamp": datetime.now().isoformat()
    }


# Protected endpoints
@app.post("/start", dependencies=[Depends(require_jwt)])
async def start():
    """Start webmail service."""
    webmail_type = get_webmail_type()
    service_name = get_service_name()

    if not service_name:
        return {"success": False, "error": "No webmail installed"}

    try:
        result = subprocess.run(
            ["systemctl", "start", service_name],
            capture_output=True, text=True, timeout=30
        )
        success = result.returncode == 0
        if success:
            _record_event("service_start", {"type": webmail_type})
            stats_cache.clear()
        return {"success": success, "output": result.stdout if success else result.stderr}
    except Exception as e:
        return {"success": False, "error": str(e)}


@app.post("/stop", dependencies=[Depends(require_jwt)])
async def stop():
    """Stop webmail service."""
    service_name = get_service_name()

    if not service_name:
        return {"success": False, "error": "No webmail installed"}

    try:
        result = subprocess.run(
            ["systemctl", "stop", service_name],
            capture_output=True, text=True, timeout=30
        )
        success = result.returncode == 0
        if success:
            _record_event("service_stop", {"type": get_webmail_type()})
            stats_cache.clear()
        return {"success": success}
    except Exception as e:
        return {"success": False, "error": str(e)}


@app.post("/restart", dependencies=[Depends(require_jwt)])
async def restart():
    """Restart webmail service."""
    webmail_type = get_webmail_type()
    service_name = get_service_name()

    if not service_name:
        return {"success": False, "error": "No webmail installed"}

    try:
        result = subprocess.run(
            ["systemctl", "restart", service_name],
            capture_output=True, text=True, timeout=30
        )
        success = result.returncode == 0
        if success:
            _record_event("service_restart", {"type": webmail_type})
            stats_cache.clear()
        return {"success": success}
    except Exception as e:
        return {"success": False, "error": str(e)}


@app.get("/config", dependencies=[Depends(require_jwt)])
async def get_config_endpoint():
    """Get webmail configuration."""
    webmail_type = get_webmail_type()
    conf = {
        "type": webmail_type,
        "mail_server": config.get("mail_server", "localhost"),
        "smtp_server": config.get("smtp_server", "localhost"),
        "plugins": config.get("plugins", [])
    }

    # Try to get actual config
    if webmail_type == "roundcube":
        conf_file = Path("/etc/roundcube/config.inc.php")
        if conf_file.exists():
            conf["config_file"] = str(conf_file)
    elif webmail_type == "sogo":
        conf_file = Path("/etc/sogo/sogo.conf")
        if conf_file.exists():
            conf["config_file"] = str(conf_file)

    return conf


@app.put("/config", dependencies=[Depends(require_jwt)])
async def update_config(data: WebmailConfig):
    """Update webmail configuration."""
    _record_event("config_update", {"changes": data.model_dump(exclude_none=True)})
    return {"success": True, "message": "Configuration updated"}


@app.get("/logs", dependencies=[Depends(require_jwt)])
async def get_logs(lines: int = 100):
    """Get webmail logs."""
    webmail_type = get_webmail_type()
    try:
        if webmail_type == "roundcube":
            log_file = "/var/log/roundcube/errors.log"
        elif webmail_type == "sogo":
            log_file = "/var/log/sogo/sogo.log"
        else:
            return {"logs": "No webmail installed", "lines": 0}

        if os.path.exists(log_file):
            result = subprocess.run(
                ["tail", "-n", str(min(lines, 1000)), log_file],
                capture_output=True, text=True, timeout=10
            )
            log_lines = result.stdout.split("\n")
            return {
                "logs": result.stdout,
                "lines": len(log_lines),
                "file": log_file
            }
        return {"logs": "Log file not found", "lines": 0, "file": log_file}
    except Exception as e:
        return {"logs": str(e), "lines": 0, "error": True}


@app.get("/logs/errors", dependencies=[Depends(require_jwt)])
async def get_error_logs(hours: int = 24):
    """Get recent error logs."""
    logs_result = await get_logs(lines=500)
    if "error" in logs_result:
        return logs_result

    # Parse for errors
    errors = []
    cutoff = datetime.now() - timedelta(hours=hours)

    for line in logs_result.get("logs", "").split("\n"):
        if "error" in line.lower() or "warning" in line.lower():
            errors.append(line)

    return {
        "errors": errors[-100:],
        "total": len(errors),
        "hours": hours
    }


@app.post("/clear-cache", dependencies=[Depends(require_jwt)])
async def clear_cache():
    """Clear webmail cache."""
    webmail_type = get_webmail_type()
    try:
        cleared = 0
        if webmail_type == "roundcube":
            cache_dir = Path("/var/lib/roundcube/temp")
            if cache_dir.exists():
                for f in cache_dir.iterdir():
                    if f.is_file():
                        f.unlink()
                        cleared += 1
        elif webmail_type == "sogo":
            result = subprocess.run(
                ["sogo-tool", "expire-sessions", "0"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                cleared = 1

        _record_event("cache_cleared", {"cleared": cleared})
        stats_cache.clear()
        return {"success": True, "cleared": cleared}
    except Exception as e:
        return {"success": False, "error": str(e)}


@app.get("/storage", dependencies=[Depends(require_jwt)])
async def get_storage():
    """Get storage statistics."""
    stats = get_storage_stats()
    stats["storage_human"] = _format_bytes(stats.get("storage_bytes", 0))
    stats["cache_human"] = _format_bytes(stats.get("cache_bytes", 0))
    stats["log_human"] = _format_bytes(stats.get("log_bytes", 0))
    stats["timestamp"] = datetime.now().isoformat()
    return stats


@app.get("/history", dependencies=[Depends(require_jwt)])
async def get_history(limit: int = 100):
    """Get event history."""
    history = _load_history()
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
    """Get webmail summary."""
    status_info = await status()
    health = await health_check()
    storage = get_storage_stats()

    # Recent history
    history = _load_history()
    recent = history[-5:]

    return {
        "type": status_info["type"],
        "running": status_info["running"],
        "health": health["status"],
        "active_sessions": status_info.get("active_sessions", 0),
        "storage": {
            "data": _format_bytes(storage.get("storage_bytes", 0)),
            "cache": _format_bytes(storage.get("cache_bytes", 0)),
            "logs": _format_bytes(storage.get("log_bytes", 0))
        },
        "mail_server": status_info["mail_server"],
        "recent_events": recent,
        "webhooks_configured": len(_load_webhooks()),
        "timestamp": datetime.now().isoformat()
    }
