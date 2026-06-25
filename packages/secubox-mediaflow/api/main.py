"""SecuBox MediaFlow API - Media Stream Detection and Monitoring"""
from fastapi import FastAPI, APIRouter, Depends, BackgroundTasks
from pydantic import BaseModel, Field, field_validator
from secubox_core.auth import router as auth_router, require_jwt
from secubox_core.config import get_config
import httpx
import subprocess
import json
import threading
import time
import asyncio
import hashlib
import hmac
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional

app = FastAPI(title="secubox-mediaflow", version="2.0.0", root_path="/api/v1/mediaflow")

# ══════════════════════════════════════════════════════════════════
# Health Check Endpoint (public, no auth)
# ══════════════════════════════════════════════════════════════════

@app.get("/health")
async def health_check():
    """Public health check endpoint for sidebar status."""
    return {"status": "ok", "module": "deb"}

app.include_router(auth_router, prefix="/auth")
router = APIRouter()

# Configuration
DATA_DIR = Path("/var/lib/secubox/mediaflow")
DATA_DIR.mkdir(parents=True, exist_ok=True)
ALERTS_FILE = DATA_DIR / "alerts.json"
HISTORY_FILE = DATA_DIR / "history.json"
WEBHOOKS_FILE = DATA_DIR / "webhooks.json"
SETTINGS_FILE = DATA_DIR / "settings.json"
STATS_FILE = DATA_DIR / "stats.json"

DPI_BASE = "http+unix://%2Frun%2Fsecubox%2Fdpi.sock"

MEDIA_APPS = {
    "Netflix", "YouTube", "Twitch", "Disney+", "Spotify",
    "Apple Music", "Tidal", "Zoom", "Teams", "Google Meet",
    "WebEx", "Amazon Prime", "Hulu", "RTSP", "HLS", "DASH",
    "HBO Max", "Paramount+", "Peacock", "Apple TV+", "Crunchyroll",
    "Deezer", "SoundCloud", "Vimeo", "Dailymotion", "TikTok"
}

STREAMING_CATEGORIES = {
    "video": {"Netflix", "YouTube", "Twitch", "Disney+", "Amazon Prime", "Hulu",
              "HBO Max", "Paramount+", "Peacock", "Apple TV+", "Vimeo", "Dailymotion", "TikTok", "Crunchyroll"},
    "audio": {"Spotify", "Apple Music", "Tidal", "Deezer", "SoundCloud"},
    "conferencing": {"Zoom", "Teams", "Google Meet", "WebEx"},
    "protocols": {"RTSP", "HLS", "DASH"}
}


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


stats_cache = StatsCache(ttl_seconds=10)


# Pydantic Models
class AlertRequest(BaseModel):
    name: str
    service: str
    threshold_mb: int = 100
    enabled: bool = True


class SettingsRequest(BaseModel):
    detection_enabled: bool = True
    history_days: int = 7
    alert_on_new_service: bool = False


class WebhookConfig(BaseModel):
    url: str
    events: List[str] = Field(default=["threshold_exceeded", "new_service", "service_down"])
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


def _load_alerts() -> List[Dict[str, Any]]:
    return _load_json(ALERTS_FILE, [])


def _save_alerts(alerts: List[Dict[str, Any]]):
    _save_json(ALERTS_FILE, alerts)


def _load_history() -> List[Dict[str, Any]]:
    return _load_json(HISTORY_FILE, [])


def _save_history(history: List[Dict[str, Any]]):
    history = history[-2000:]  # Keep last 2000 entries
    _save_json(HISTORY_FILE, history)


def _load_webhooks() -> List[Dict[str, Any]]:
    return _load_json(WEBHOOKS_FILE, [])


def _save_webhooks(webhooks: List[Dict[str, Any]]):
    _save_json(WEBHOOKS_FILE, webhooks)


def _load_settings() -> Dict[str, Any]:
    return _load_json(SETTINGS_FILE, {
        "detection_enabled": True,
        "history_days": 7,
        "alert_on_new_service": False
    })


def _save_settings(settings: Dict[str, Any]):
    _save_json(SETTINGS_FILE, settings)


def _record_stream(service: str, bytes_transferred: int, src_ip: str = None):
    """Record a stream event in history."""
    history = _load_history()
    entry = {
        "timestamp": datetime.now().isoformat(),
        "service": service,
        "bytes": bytes_transferred,
        "bytes_human": _format_bytes(bytes_transferred),
        "src_ip": src_ip
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


async def _dpi(path: str) -> Dict[str, Any]:
    """Make request to DPI service."""
    try:
        async with httpx.AsyncClient(
            transport=httpx.AsyncHTTPTransport(uds="/run/secubox/dpi.sock"),
            timeout=5
        ) as c:
            r = await c.get(f"http://dpi{path}")
            return r.json()
    except Exception:
        return {}


async def _check_alerts(media_stats: Dict[str, Dict[str, Any]]):
    """Check if any alerts need to be triggered."""
    alerts = _load_alerts()
    for alert in alerts:
        if not alert.get("enabled", True):
            continue

        service = alert.get("service")
        threshold_bytes = alert.get("threshold_mb", 100) * 1024 * 1024

        if service in media_stats:
            current_bytes = media_stats[service].get("bytes", 0)
            if current_bytes > threshold_bytes:
                await _notify_webhooks("threshold_exceeded", {
                    "alert_name": alert.get("name"),
                    "service": service,
                    "current_mb": current_bytes / (1024 * 1024),
                    "threshold_mb": alert.get("threshold_mb")
                })


async def _monitor_streams():
    """Background task to monitor media streams."""
    seen_services: set = set()

    while True:
        try:
            settings = _load_settings()
            if settings.get("detection_enabled", True):
                ex = await _dpi("/exfil")
                media_stats: Dict[str, Dict[str, Any]] = {}

                for f in _exfil_media_flows(ex):
                    name = f.get("service") or f.get("dst") or "Unknown"
                    if name not in media_stats:
                        media_stats[name] = {"name": name, "flows": 0, "bytes": 0}
                    media_stats[name]["flows"] += int(f.get("flows", 1) or 1)
                    media_stats[name]["bytes"] += int(f.get("up_bytes", 0) or 0) + int(f.get("down_bytes", 0) or 0)

                    # Check for new services
                    if settings.get("alert_on_new_service") and name not in seen_services:
                        seen_services.add(name)
                        await _notify_webhooks("new_service", {"service": name, "category": "media"})

                # Check alerts
                await _check_alerts(media_stats)

                # Update stats cache
                stats_cache.set("media_stats", media_stats)

        except Exception:
            pass

        await asyncio.sleep(30)


@app.on_event("startup")
async def startup():
    """Start background monitoring."""
    global _monitoring_task
    _monitoring_task = asyncio.create_task(_monitor_streams())


@app.on_event("shutdown")
async def shutdown():
    """Stop background monitoring."""
    global _monitoring_task
    if _monitoring_task:
        _monitoring_task.cancel()


# Public endpoints
@router.get("/health")
async def health():
    return {"status": "ok", "module": "mediaflow", "version": "2.0.0"}


# The DPI engine now exposes a public, category-tagged exfil view (the netifyd
# /flows path is dead). Media = the exfil classifier's "media" category.
MEDIA_CATEGORIES = {"media"}


def _exfil_media_flows(exfil: Dict[str, Any]):
    """Flatten exfil devices->services + active_flows to category=='media' rows."""
    rows = []
    for dev in exfil.get("devices", []) or []:
        for s in dev.get("services", []) or []:
            if s.get("category") in MEDIA_CATEGORIES:
                rows.append(s)
    for f in exfil.get("active_flows", []) or []:
        if f.get("category") in MEDIA_CATEGORIES:
            rows.append(f)
    return rows


@router.get("/status")
async def status(user=Depends(require_jwt)):
    try:
        ex = await _dpi("/exfil")
        settings = _load_settings()
        media = _exfil_media_flows(ex)
        return {
            "running": bool(ex) and "error" not in ex,
            "source": "dpi-exfil",
            "devices": len(ex.get("devices", []) or []),
            "active_flows": len(ex.get("active_flows", []) or []),
            "media_flows": len(media),
            "media_detection": settings.get("detection_enabled", True),
            "monitored_categories": sorted(MEDIA_CATEGORIES),
            "generated_at": ex.get("generated_at"),
            "timestamp": datetime.now().isoformat(),
        }
    except Exception as e:
        return {"running": False, "error": str(e)}


@router.get("/services")
async def services(user=Depends(require_jwt)):
    """Active media services (from the DPI exfil view), grouped by service/host."""
    cached = stats_cache.get("services")
    if cached:
        return cached
    try:
        ex = await _dpi("/exfil")
        media: Dict[str, Dict[str, Any]] = {}
        for f in _exfil_media_flows(ex):
            name = f.get("service") or f.get("dst") or "Unknown"
            if name not in media:
                media[name] = {"name": name, "category": "media",
                               "host": f.get("dst"), "cloud": f.get("cloud"),
                               "flows": 0, "bytes": 0, "clients": set()}
            media[name]["flows"] += int(f.get("flows", 1) or 1)
            media[name]["bytes"] += int(f.get("up_bytes", 0) or 0) + int(f.get("down_bytes", 0) or 0)
            if f.get("device"):
                media[name]["clients"].add(f.get("device"))
        result = []
        for data in media.values():
            data["clients"] = len(data["clients"])
            data["bytes_human"] = _format_bytes(data["bytes"])
            result.append(data)
        result.sort(key=lambda x: x["bytes"], reverse=True)
        stats_cache.set("services", result)
        return result
    except Exception:
        return []


@router.get("/services/by-category")
async def services_by_category(user=Depends(require_jwt)):
    """Get services grouped by category."""
    services_list = await services(user)

    by_category: Dict[str, List[Dict]] = {cat: [] for cat in STREAMING_CATEGORIES}
    by_category["other"] = []

    for svc in services_list:
        cat = svc.get("category", "other")
        if cat in by_category:
            by_category[cat].append(svc)
        else:
            by_category["other"].append(svc)

    return {
        "categories": by_category,
        "totals": {
            cat: {
                "services": len(svcs),
                "bytes": sum(s.get("bytes", 0) for s in svcs),
                "bytes_human": _format_bytes(sum(s.get("bytes", 0) for s in svcs))
            }
            for cat, svcs in by_category.items()
        }
    }


@router.get("/clients")
async def clients(user=Depends(require_jwt)):
    """Get clients (devices) seen by the DPI exfil view, with totals."""
    try:
        ex = await _dpi("/exfil")
        out = []
        for d in ex.get("devices", []) or []:
            tot = int(d.get("up_bytes", 0) or 0) + int(d.get("down_bytes", 0) or 0)
            out.append({
                "device": d.get("device"),
                "flows": d.get("flows", 0),
                "up_bytes": d.get("up_bytes", 0),
                "down_bytes": d.get("down_bytes", 0),
                "bytes": tot,
                "bytes_human": _format_bytes(tot),
                "media_flows": sum(1 for s in (d.get("services") or [])
                                   if s.get("category") in MEDIA_CATEGORIES),
            })
        out.sort(key=lambda x: x["bytes"], reverse=True)
        return out
    except Exception:
        return []


@router.get("/get_active_streams")
async def get_active_streams(user=Depends(require_jwt)):
    """Active media streams (category=='media') from the DPI exfil view."""
    try:
        ex = await _dpi("/exfil")
        streams = []
        for f in _exfil_media_flows(ex):
            b = int(f.get("up_bytes", 0) or 0) + int(f.get("down_bytes", 0) or 0)
            streams.append({**f, "bytes": b, "bytes_human": _format_bytes(b)})
        streams.sort(key=lambda x: x["bytes"], reverse=True)
        return streams
    except Exception:
        return []


@router.get("/get_service_details")
async def get_service_details(service: str, user=Depends(require_jwt)):
    """Get detailed info for a specific media service."""
    try:
        ex = await _dpi("/exfil")
        service_flows = [f for f in _exfil_media_flows(ex)
                         if (f.get("service") or f.get("dst")) == service]
        total_bytes = sum(int(f.get("up_bytes", 0) or 0) + int(f.get("down_bytes", 0) or 0)
                          for f in service_flows)
        clients = set(f.get("device") for f in service_flows if f.get("device"))
        return {
            "service": service,
            "category": "media",
            "active_flows": len(service_flows),
            "total_bytes": total_bytes,
            "total_bytes_human": _format_bytes(total_bytes),
            "unique_clients": len(clients),
            "flows": service_flows[:50],
        }
    except Exception:
        return {"service": service, "error": "Failed to fetch details"}


@router.get("/history")
async def history(hours: int = 24, service: Optional[str] = None, user=Depends(require_jwt)):
    """Get streaming history."""
    all_history = _load_history()
    cutoff = datetime.now() - timedelta(hours=hours)

    filtered = []
    for entry in all_history:
        try:
            entry_time = datetime.fromisoformat(entry.get("timestamp", ""))
            if entry_time >= cutoff:
                if service is None or entry.get("service") == service:
                    filtered.append(entry)
        except ValueError:
            continue

    return {
        "history": filtered[-500:],
        "total": len(filtered),
        "hours": hours
    }


@router.post("/clear_history")
async def clear_history(user=Depends(require_jwt)):
    """Clear streaming history."""
    _save_history([])
    return {"success": True}


# Alert management
@router.get("/alerts")
async def get_alerts(user=Depends(require_jwt)):
    """List configured alerts."""
    return {"alerts": _load_alerts()}


@router.post("/alerts")
async def create_alert(req: AlertRequest, user=Depends(require_jwt)):
    """Create a new alert."""
    alerts = _load_alerts()
    alert_data = req.model_dump()
    alert_data["id"] = hashlib.md5(f"{req.name}{req.service}".encode()).hexdigest()[:8]
    alert_data["created_at"] = datetime.now().isoformat()
    alerts.append(alert_data)
    _save_alerts(alerts)
    return {"success": True, "alert": alert_data}


@router.delete("/alerts/{alert_id}")
async def delete_alert(alert_id: str, user=Depends(require_jwt)):
    """Delete an alert."""
    alerts = _load_alerts()
    alerts = [a for a in alerts if a.get("id") != alert_id]
    _save_alerts(alerts)
    return {"success": True}


# Webhook management
@router.get("/webhooks")
async def list_webhooks(user=Depends(require_jwt)):
    """List configured webhooks."""
    return {"webhooks": _load_webhooks()}


@router.post("/webhooks")
async def add_webhook(webhook: WebhookConfig, user=Depends(require_jwt)):
    """Add a new webhook."""
    webhooks = _load_webhooks()
    webhook_data = webhook.model_dump()
    webhook_data["id"] = hashlib.md5(webhook.url.encode()).hexdigest()[:8]
    webhook_data["created_at"] = datetime.now().isoformat()
    webhooks.append(webhook_data)
    _save_webhooks(webhooks)
    return {"success": True, "webhook": webhook_data}


@router.delete("/webhooks/{webhook_id}")
async def delete_webhook(webhook_id: str, user=Depends(require_jwt)):
    """Delete a webhook."""
    webhooks = _load_webhooks()
    webhooks = [w for w in webhooks if w.get("id") != webhook_id]
    _save_webhooks(webhooks)
    return {"success": True}


# Settings
@router.get("/settings")
async def get_settings(user=Depends(require_jwt)):
    """Get module settings."""
    return _load_settings()


@router.post("/settings")
async def update_settings(req: SettingsRequest, user=Depends(require_jwt)):
    """Update module settings."""
    settings = req.model_dump()
    _save_settings(settings)
    return {"success": True, "settings": settings}


# DPI service control
@router.post("/start_netifyd")
def start_netifyd(user=Depends(require_jwt)):
    r = subprocess.run(["systemctl", "start", "netifyd"], capture_output=True, text=True)
    return {"success": r.returncode == 0}


@router.post("/stop_netifyd")
def stop_netifyd(user=Depends(require_jwt)):
    r = subprocess.run(["systemctl", "stop", "netifyd"], capture_output=True, text=True)
    return {"success": r.returncode == 0}


@router.post("/start_ndpid")
def start_ndpid(user=Depends(require_jwt)):
    r = subprocess.run(["systemctl", "start", "ndpid"], capture_output=True, text=True)
    return {"success": r.returncode == 0}


@router.post("/stop_ndpid")
def stop_ndpid(user=Depends(require_jwt)):
    r = subprocess.run(["systemctl", "stop", "ndpid"], capture_output=True, text=True)
    return {"success": r.returncode == 0}


@router.get("/summary")
async def summary(user=Depends(require_jwt)):
    """Get mediaflow summary."""
    try:
        ex = await _dpi("/exfil")
        dpi_running = bool(ex) and "error" not in ex
    except Exception:
        dpi_running = False

    services_list = await services(user)
    settings = _load_settings()
    alerts = _load_alerts()

    total_bytes = sum(s.get("bytes", 0) for s in services_list)

    return {
        "dpi_running": dpi_running,
        "detection_enabled": settings.get("detection_enabled", True),
        "active_services": len(services_list),
        "total_bytes": total_bytes,
        "total_bytes_human": _format_bytes(total_bytes),
        "by_category": {
            cat: sum(1 for s in services_list if s.get("category") == cat)
            for cat in STREAMING_CATEGORIES
        },
        "alerts_configured": len(alerts),
        "webhooks_configured": len(_load_webhooks()),
        "timestamp": datetime.now().isoformat()
    }


app.include_router(router)
