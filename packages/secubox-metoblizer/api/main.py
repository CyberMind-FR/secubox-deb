"""
SecuBox-Deb :: secubox-metoblizer
CyberMind - https://cybermind.fr
Author: Gerald KERMA <devel@cybermind.fr>
License: Proprietary / ANSSI CSPN candidate

Metoblizer - Centralized log aggregator for SecuBox modules.
Aggregates logs/events from netdata, glances, streamlit, and other modules.
Provides presence banner injection and unified log querying.
"""
import asyncio
import json
import time
import threading
import httpx
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, APIRouter, Depends, Query, HTTPException
from pydantic import BaseModel, Field
from secubox_core.auth import router as auth_router, require_jwt
from secubox_core.config import get_config
from secubox_core.logger import get_logger

app = FastAPI(title="secubox-metoblizer", version="1.0.0", root_path="/api/v1/metoblizer")

# ══════════════════════════════════════════════════════════════════
# Health Check Endpoint (public, no auth)
# ══════════════════════════════════════════════════════════════════

@app.get("/health")
async def health_check():
    """Public health check endpoint for sidebar status."""
    return {"status": "ok", "module": "deb"}

app.include_router(auth_router, prefix="/auth")
router = APIRouter()
log = get_logger("metoblizer")

# Configuration
DATA_DIR = Path("/var/lib/secubox/metoblizer")
DATA_DIR.mkdir(parents=True, exist_ok=True)
EVENTS_FILE = DATA_DIR / "events.json"
PRESENCE_DIR = Path("/var/lib/secubox/presence")
PRESENCE_DIR.mkdir(parents=True, exist_ok=True)
BANNER_FILE = DATA_DIR / "banner.json"

# Module endpoints for aggregation
MODULE_ENDPOINTS = {
    "netdata": "http://127.0.0.1:9202/api/v1/netdata",
    "glances": "http://127.0.0.1:9213/api/v1/glances",
    "streamlit": "http://127.0.0.1:9214/api/v1/streamlit",
    "crowdsec": "http://127.0.0.1:9201/api/v1/crowdsec",
}

# In-memory event buffer for fast writes
_event_buffer: List[Dict[str, Any]] = []
_buffer_lock = threading.Lock()
MAX_BUFFER_SIZE = 100
MAX_EVENTS = 10000


class EventCache:
    """Thread-safe event cache with TTL."""

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


cache = EventCache(ttl_seconds=30)


# Pydantic Models
class IngestEvent(BaseModel):
    """Event to ingest into metoblizer."""
    module: str = Field(..., min_length=1, max_length=50)
    event: str = Field(..., min_length=1, max_length=100)
    timestamp: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)
    severity: str = Field(default="info", pattern="^(debug|info|warning|error|critical)$")


class BannerConfig(BaseModel):
    """Banner configuration for presence events."""
    message: str
    type: str = Field(default="info", pattern="^(info|warning|error|success)$")
    duration: int = Field(default=5000, ge=1000, le=60000)
    dismissible: bool = True


class QueryParams(BaseModel):
    """Query parameters for event search."""
    module: Optional[str] = None
    event: Optional[str] = None
    severity: Optional[str] = None
    hours: int = Field(default=24, ge=1, le=168)
    limit: int = Field(default=100, ge=1, le=1000)


def _load_events() -> List[Dict[str, Any]]:
    """Load events from file."""
    if EVENTS_FILE.exists():
        try:
            return json.loads(EVENTS_FILE.read_text())
        except Exception:
            pass
    return []


def _save_events(events: List[Dict[str, Any]]):
    """Save events to file, keeping only recent ones."""
    events = events[-MAX_EVENTS:]
    EVENTS_FILE.write_text(json.dumps(events, indent=2))


def _flush_buffer():
    """Flush event buffer to disk."""
    global _event_buffer
    with _buffer_lock:
        if not _event_buffer:
            return
        events = _load_events()
        events.extend(_event_buffer)
        _save_events(events)
        _event_buffer = []


def _add_event(event: Dict[str, Any]):
    """Add event to buffer."""
    global _event_buffer
    with _buffer_lock:
        _event_buffer.append(event)
        if len(_event_buffer) >= MAX_BUFFER_SIZE:
            # Flush when buffer is full
            events = _load_events()
            events.extend(_event_buffer)
            _save_events(events)
            _event_buffer = []


def _get_banner() -> Optional[Dict[str, Any]]:
    """Get current banner configuration."""
    if BANNER_FILE.exists():
        try:
            banner = json.loads(BANNER_FILE.read_text())
            # Check if banner has expired
            expires = banner.get("expires")
            if expires and datetime.fromisoformat(expires) < datetime.now():
                BANNER_FILE.unlink(missing_ok=True)
                return None
            return banner
        except Exception:
            pass
    return None


def _set_banner(config: Dict[str, Any], duration_seconds: int = 60):
    """Set banner with expiry."""
    config["expires"] = (datetime.now() + timedelta(seconds=duration_seconds)).isoformat()
    config["created"] = datetime.now().isoformat()
    BANNER_FILE.write_text(json.dumps(config, indent=2))


def _read_presence_events() -> List[Dict[str, Any]]:
    """Read presence events from all modules."""
    events = []
    for path in PRESENCE_DIR.glob("*.json"):
        try:
            event = json.loads(path.read_text())
            event["_source_file"] = path.name
            events.append(event)
        except Exception:
            pass
    return events


async def _fetch_module_stats(module: str, endpoint: str) -> Dict[str, Any]:
    """Fetch stats from a module endpoint."""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get(f"{endpoint}/stats")
            if r.status_code == 200:
                return {"module": module, "stats": r.json(), "available": True}
    except Exception as e:
        log.debug("fetch %s failed: %s", module, e)
    return {"module": module, "stats": {}, "available": False}


async def _fetch_module_status(module: str, endpoint: str) -> Dict[str, Any]:
    """Fetch status from a module endpoint."""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get(f"{endpoint}/status")
            if r.status_code == 200:
                return {"module": module, "status": r.json(), "available": True}
    except Exception as e:
        log.debug("status %s failed: %s", module, e)
    return {"module": module, "status": {}, "available": False}


# Background task for periodic buffer flush
_flush_task: Optional[asyncio.Task] = None


async def _periodic_flush():
    """Periodically flush event buffer to disk."""
    while True:
        try:
            _flush_buffer()
        except Exception as e:
            log.warning("flush error: %s", e)
        await asyncio.sleep(30)


@app.on_event("startup")
async def startup():
    """Start background tasks."""
    global _flush_task
    _flush_task = asyncio.create_task(_periodic_flush())


@app.on_event("shutdown")
async def shutdown():
    """Stop background tasks and flush buffer."""
    global _flush_task
    if _flush_task:
        _flush_task.cancel()
    _flush_buffer()


# ══════════════════════════════════════════════════════════════════
# Public Endpoints (dashboard widgets)
# ══════════════════════════════════════════════════════════════════

@router.get("/health")
async def health():
    """Health check."""
    return {"status": "ok", "module": "metoblizer", "version": "1.0.0"}


@router.get("/status")
async def status():
    """Service status (public for dashboard)."""
    cached = cache.get("status")
    if cached:
        return cached

    events = _load_events()
    presence = _read_presence_events()
    banner = _get_banner()

    result = {
        "running": True,
        "events_count": len(events),
        "buffer_size": len(_event_buffer),
        "presence_events": len(presence),
        "banner_active": banner is not None,
        "timestamp": datetime.now().isoformat()
    }
    cache.set("status", result)
    return result


@router.get("/banner")
async def get_banner():
    """Get current banner for injection (public)."""
    banner = _get_banner()
    if banner:
        return {"active": True, "banner": banner}
    return {"active": False, "banner": None}


@router.get("/presence")
async def get_presence():
    """Get presence events from all modules (public for dashboard)."""
    events = _read_presence_events()
    return {
        "events": events,
        "count": len(events),
        "timestamp": datetime.now().isoformat()
    }


@router.get("/recent")
async def recent_events(limit: int = Query(20, ge=1, le=100)):
    """Get recent events (public for dashboard widget)."""
    cached = cache.get(f"recent_{limit}")
    if cached:
        return cached

    events = _load_events()
    recent = events[-limit:]
    recent.reverse()

    result = {
        "events": recent,
        "count": len(recent),
        "total": len(events),
        "timestamp": datetime.now().isoformat()
    }
    cache.set(f"recent_{limit}", result)
    return result


# ══════════════════════════════════════════════════════════════════
# Ingestion Endpoint (modules send events here)
# ══════════════════════════════════════════════════════════════════

@router.post("/ingest")
async def ingest_event(event: IngestEvent):
    """Ingest an event from a module (public for inter-module communication)."""
    event_data = {
        "module": event.module,
        "event": event.event,
        "severity": event.severity,
        "details": event.details,
        "timestamp": event.timestamp or datetime.now().isoformat(),
        "ingested_at": datetime.now().isoformat()
    }

    _add_event(event_data)
    cache.clear()

    # Check if this is a presence event that should trigger a banner
    if event.event in ("wake", "sleep", "start", "stop", "alert"):
        _inject_presence_banner(event)

    log.debug("ingested: %s/%s", event.module, event.event)
    return {"success": True, "event_id": f"{event.module}_{int(time.time()*1000)}"}


def _inject_presence_banner(event: IngestEvent):
    """Inject a banner based on presence event."""
    messages = {
        "wake": f"{event.module} is waking up...",
        "sleep": f"{event.module} is going to sleep",
        "start": f"{event.module} started",
        "stop": f"{event.module} stopped",
        "alert": f"Alert from {event.module}: {event.details.get('message', 'Check logs')}"
    }

    types = {
        "wake": "info",
        "sleep": "info",
        "start": "success",
        "stop": "warning",
        "alert": "error"
    }

    if event.event in messages:
        _set_banner({
            "message": messages[event.event],
            "type": types.get(event.event, "info"),
            "module": event.module,
            "event": event.event,
            "dismissible": True
        }, duration_seconds=30)


# ══════════════════════════════════════════════════════════════════
# Protected Endpoints (require authentication)
# ══════════════════════════════════════════════════════════════════

@router.get("/events")
async def query_events(
    module: Optional[str] = None,
    event: Optional[str] = None,
    severity: Optional[str] = None,
    hours: int = Query(24, ge=1, le=168),
    limit: int = Query(100, ge=1, le=1000),
    user=Depends(require_jwt)
):
    """Query events with filters."""
    events = _load_events()
    cutoff = datetime.now() - timedelta(hours=hours)

    filtered = []
    for e in events:
        try:
            ts = datetime.fromisoformat(e.get("timestamp", "2000-01-01"))
            if ts < cutoff:
                continue
            if module and e.get("module") != module:
                continue
            if event and e.get("event") != event:
                continue
            if severity and e.get("severity") != severity:
                continue
            filtered.append(e)
        except ValueError:
            continue

    filtered.reverse()
    filtered = filtered[:limit]

    return {
        "events": filtered,
        "count": len(filtered),
        "query": {"module": module, "event": event, "severity": severity, "hours": hours}
    }


@router.get("/modules")
async def list_modules(user=Depends(require_jwt)):
    """List configured modules and their status."""
    results = []
    tasks = [_fetch_module_status(m, e) for m, e in MODULE_ENDPOINTS.items()]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    modules = []
    for r in results:
        if isinstance(r, dict):
            modules.append(r)
        elif isinstance(r, Exception):
            log.warning("module check failed: %s", r)

    return {"modules": modules, "configured": list(MODULE_ENDPOINTS.keys())}


@router.get("/aggregate")
async def aggregate_stats(user=Depends(require_jwt)):
    """Aggregate stats from all modules."""
    cached = cache.get("aggregate")
    if cached:
        return cached

    tasks = [_fetch_module_stats(m, e) for m, e in MODULE_ENDPOINTS.items()]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    stats = {}
    for r in results:
        if isinstance(r, dict) and r.get("available"):
            stats[r["module"]] = r["stats"]

    result = {
        "stats": stats,
        "modules_available": len([r for r in results if isinstance(r, dict) and r.get("available")]),
        "modules_total": len(MODULE_ENDPOINTS),
        "timestamp": datetime.now().isoformat()
    }
    cache.set("aggregate", result)
    return result


@router.post("/banner")
async def set_banner_endpoint(config: BannerConfig, user=Depends(require_jwt)):
    """Set a system-wide banner."""
    _set_banner({
        "message": config.message,
        "type": config.type,
        "dismissible": config.dismissible,
        "set_by": user.get("sub", "unknown")
    }, duration_seconds=config.duration // 1000)

    log.info("banner set by %s: %s", user.get("sub"), config.message[:50])
    return {"success": True}


@router.delete("/banner")
async def clear_banner(user=Depends(require_jwt)):
    """Clear the current banner."""
    BANNER_FILE.unlink(missing_ok=True)
    log.info("banner cleared by %s", user.get("sub"))
    return {"success": True}


@router.delete("/events")
async def clear_events(
    older_than_hours: int = Query(24, ge=1),
    user=Depends(require_jwt)
):
    """Clear old events."""
    events = _load_events()
    cutoff = datetime.now() - timedelta(hours=older_than_hours)

    kept = []
    removed = 0
    for e in events:
        try:
            ts = datetime.fromisoformat(e.get("timestamp", "2000-01-01"))
            if ts >= cutoff:
                kept.append(e)
            else:
                removed += 1
        except ValueError:
            removed += 1

    _save_events(kept)
    cache.clear()

    log.info("events cleared by %s: %d removed, %d kept", user.get("sub"), removed, len(kept))
    return {"success": True, "removed": removed, "kept": len(kept)}


@router.get("/summary")
async def summary():
    """Summary for dashboard widget (public)."""
    status_info = await status()
    recent = await recent_events(5)
    banner = _get_banner()

    # Count by severity
    events = _load_events()
    severity_counts = {"debug": 0, "info": 0, "warning": 0, "error": 0, "critical": 0}
    for e in events[-100:]:
        sev = e.get("severity", "info")
        if sev in severity_counts:
            severity_counts[sev] += 1

    return {
        "running": True,
        "events_count": status_info.get("events_count", 0),
        "recent_events": recent.get("events", [])[:3],
        "severity_breakdown": severity_counts,
        "banner_active": banner is not None,
        "banner": banner,
        "modules_configured": len(MODULE_ENDPOINTS),
        "timestamp": datetime.now().isoformat()
    }


@router.get("/config")
async def get_config_endpoint(user=Depends(require_jwt)):
    """Get metoblizer configuration."""
    cfg = get_config("metoblizer")
    return {
        "modules": MODULE_ENDPOINTS,
        "max_events": MAX_EVENTS,
        "max_buffer": MAX_BUFFER_SIZE,
        "data_dir": str(DATA_DIR),
        "config": cfg or {}
    }


app.include_router(router)
