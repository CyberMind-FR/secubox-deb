# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""SecuBox MediaFlow API - Media Stream Detection and Monitoring"""
from fastapi import FastAPI, APIRouter, Depends, BackgroundTasks, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field, field_validator
from secubox_core.auth import router as auth_router, require_jwt
from secubox_core.config import get_config
import os
import re
import shutil
import secrets
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

app = FastAPI(title="secubox-mediaflow", version="2.2.0", root_path="/api/v1/mediaflow")

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

# ── R4 media reverse-catcher: Discovered Media + Clone (#736) ─────────────────
# sbxmitm appends cloneable media URLs it sees on MITM'd flows here (JSONL, one
# record/line). We read it for the "Discovered Media" view and let the operator
# CLONE a URL (yt-dlp if present, else ffmpeg) into the durable library below.
MEDIA_CATCH_PATH = Path("/run/secubox/media-catch.jsonl")
# Durable, capped mirror of the discovery log (the catch log itself is on tmpfs
# and cleared on reboot) so Discovered Media survives reboots.
DISCOVERED_STORE = DATA_DIR / "discovered.json"
DISCOVERED_MAX = 2000
LIBRARY_DIR = DATA_DIR / "library"
CLONE_JOBS_FILE = DATA_DIR / "clone_jobs.json"
CLONE_TIMEOUT_S = int(os.environ.get("SECUBOX_CLONE_TIMEOUT", "1800") or "1800")  # 30 min hard cap

# Clone jobs: id -> {id,url,kind,title,status,file,bytes,error,ts}. Persisted to
# CLONE_JOBS_FILE; an asyncio queue feeds a single background worker.
_clone_jobs: Dict[str, Dict[str, Any]] = {}
_clone_queue: "asyncio.Queue[str]" = asyncio.Queue()
_clone_worker_task: Optional[asyncio.Task] = None

# The DPI collector's 7-day cumulative store (same schema as /exfil's
# devices[].services). /exfil itself is live-window only (~60s), so "Top Media
# Services" reads this instead — otherwise the table blinks empty between streams.
DPI_CUMULATIVE_PATH = Path("/var/lib/secubox/dpi/cumulative.json")

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
    # R4 clone worker (#736) — also lazily (re)started per-request for the
    # aggregator, which imports this module without firing this lifespan hook.
    _ensure_clone_worker()


@app.on_event("shutdown")
async def shutdown():
    """Stop background monitoring."""
    global _monitoring_task
    if _monitoring_task:
        _monitoring_task.cancel()


# Public endpoints
@router.get("/health")
async def health():
    return {"status": "ok", "module": "mediaflow", "version": "2.0.3"}


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


# The DPI flow-capture runs in fixed windows (secubox-dpi-flowcap, 60 s default),
# so the exfil byte counters are "bytes seen this window" — divide by the window
# to turn them into a live rate for the dashboard cards.
_DPI_WINDOW_S = int(os.environ.get("SECUBOX_DPI_WINDOW", "60") or "60")

# Audio vs video split: the DPI collector tags everything streaming as one
# "media" category, but the dashboard separates video / audio streams. Decide by
# the classifier service name first, then fall back to a host substring match.
_AUDIO_HOST_HINTS = ("spotify", "scdn.co", "sndcdn", "pscdn", "deezer", "tidal",
                     "audio", "podcast", "music", "soundcloud")


def _flow_bytes(f: Dict[str, Any]) -> int:
    return int(f.get("up_bytes", 0) or 0) + int(f.get("down_bytes", 0) or 0)


def _stream_type(f: Dict[str, Any]) -> str:
    """Classify a media flow as 'audio' or 'video' (default video)."""
    if (f.get("service") or "") in STREAMING_CATEGORIES["audio"]:
        return "audio"
    host = (f.get("dst") or "").lower()
    if any(h in host for h in _AUDIO_HOST_HINTS):
        return "audio"
    return "video"


def _mbps(total_bytes: int, window_s: int = _DPI_WINDOW_S) -> float:
    """Bytes-over-window → Mbps (bits/s ÷ 1e6)."""
    if window_s <= 0:
        return 0.0
    return round(total_bytes * 8 / window_s / 1_000_000, 2)


def _bw_str(total_bytes: int) -> str:
    """Human Mbps string for a per-stream / per-service bandwidth cell."""
    m = _mbps(total_bytes)
    return f"{m:.2f} Mbps" if m >= 0.01 else _format_bytes(total_bytes)


@router.get("/status")
async def status(user=Depends(require_jwt)):
    try:
        ex = await _dpi("/exfil")
        settings = _load_settings()
        media = _exfil_media_flows(ex)
        video = sum(1 for f in media if _stream_type(f) == "video")
        audio = sum(1 for f in media if _stream_type(f) == "audio")
        total_bytes = sum(_flow_bytes(f) for f in media)
        clients = {f.get("device") for f in media if f.get("device")}
        return {
            # ── dashboard cards (frontend contract: www/mediaflow/index.html) ──
            "video_streams": video,
            "audio_streams": audio,
            "bandwidth_mbps": _mbps(total_bytes),
            "active_clients": len(clients),
            # ── diagnostics ──
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
        return {"running": False, "error": str(e),
                "video_streams": 0, "audio_streams": 0,
                "bandwidth_mbps": 0.0, "active_clients": 0}


def _cumulative_exfil() -> Dict[str, Any]:
    """Load the DPI 7-day cumulative store (same schema as /exfil)."""
    return _load_json(DPI_CUMULATIVE_PATH, {}) or {}


async def _media_services_list() -> List[Dict[str, Any]]:
    """Top media services, grouped by service/host, with the dashboard cells
    (streams / bandwidth / percent). Reads the DPI CUMULATIVE store so the table
    persists across the live 60s windows instead of blinking empty between
    streams; falls back to the live exfil view if cumulative isn't there yet."""
    ex = _cumulative_exfil()
    rows = _exfil_media_flows(ex)
    if not rows:
        rows = _exfil_media_flows(await _dpi("/exfil"))
    media: Dict[str, Dict[str, Any]] = {}
    for f in rows:
        name = f.get("service") or f.get("dst") or "Unknown"
        if name not in media:
            media[name] = {"name": name, "category": "media",
                           "host": f.get("dst"), "cloud": f.get("cloud"),
                           "flows": 0, "bytes": 0, "clients": set()}
        media[name]["flows"] += int(f.get("flows", 1) or 1)
        media[name]["bytes"] += _flow_bytes(f)
        if f.get("device"):
            media[name]["clients"].add(f.get("device"))
    total = sum(d["bytes"] for d in media.values()) or 1
    result = []
    for data in media.values():
        data["clients"] = len(data["clients"])
        data["bytes_human"] = _format_bytes(data["bytes"])
        # frontend table cells: Service / Streams / Bandwidth / Usage %.
        # Bandwidth here is the cumulative TOTAL transferred (not a live rate).
        data["streams"] = data["flows"]
        data["bandwidth"] = _format_bytes(data["bytes"])
        data["percent"] = round(data["bytes"] * 100 / total, 1)
        result.append(data)
    result.sort(key=lambda x: x["bytes"], reverse=True)
    return result


@router.get("/services")
async def services(user=Depends(require_jwt)):
    """Active media services — {services:[…]} per the dashboard contract."""
    cached = stats_cache.get("services")
    if cached is not None:
        return {"services": cached}
    try:
        result = await _media_services_list()
        stats_cache.set("services", result)
        return {"services": result}
    except Exception:
        return {"services": []}


@router.get("/services/by-category")
async def services_by_category(user=Depends(require_jwt)):
    """Get services grouped by category."""
    try:
        services_list = await _media_services_list()
    except Exception:
        services_list = []

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


@router.get("/streams")
async def streams(user=Depends(require_jwt)):
    """Active media streams in the dashboard's table shape:
    {streams:[{client_ip, type, service, bandwidth, duration}]}."""
    try:
        ex = await _dpi("/exfil")
        rows = []
        for f in _exfil_media_flows(ex):
            rows.append({
                "client_ip": f.get("device") or f.get("src") or "—",
                "type": _stream_type(f),
                "service": f.get("service") or f.get("dst") or "Unknown",
                "bandwidth": _bw_str(_flow_bytes(f)),
                "duration": "—",  # exfil windows are stateless — no per-flow age
                "bytes": _flow_bytes(f),
            })
        rows.sort(key=lambda x: x["bytes"], reverse=True)
        return {"streams": rows}
    except Exception:
        return {"streams": []}


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


# ══════════════════════════════════════════════════════════════════
# R4 Discovered Media + Clone (#736)
# ══════════════════════════════════════════════════════════════════

def _parse_catch_log() -> Dict[str, Dict[str, Any]]:
    """Group the current-boot sbxmitm media-catch log (tmpfs) into url -> record."""
    seen: Dict[str, Dict[str, Any]] = {}
    if not MEDIA_CATCH_PATH.exists():
        return seen
    try:
        with MEDIA_CATCH_PATH.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    r = json.loads(line)
                except Exception:
                    continue
                url = r.get("url")
                if not url:
                    continue
                e = seen.get(url)
                if e:
                    e["hits"] += 1
                    e["ts"] = max(e["ts"], r.get("ts", 0))
                    e["bytes"] = max(e.get("bytes", 0), r.get("bytes", 0) or 0)
                else:
                    seen[url] = {"url": url, "host": r.get("host"), "kind": r.get("kind"),
                                 "ctype": r.get("ctype"), "bytes": r.get("bytes", 0) or 0,
                                 "referer": r.get("referer"), "ts": r.get("ts", 0), "hits": 1}
    except Exception:
        pass
    return seen


# ── multi-part stream reconstruction (#736) ──────────────────────────────────
# Adaptive/HLS players fetch a stream as hundreds of tiny segments (.m4s/.ts) plus
# a few .m3u8 playlists. Recording each segment floods the list and none of them
# is cloneable on its own. We collapse every multi-part stream to ONE entry and
# reconstruct the fully-cloneable URL: the MASTER playlist (video+audio) if it was
# seen, else the highest-resolution video variant + an audio variant to mux.
_TWIMG_RE = re.compile(r"^https?://video\.twimg\.com/(amplify_video|ext_tw_video)/(\d+)/")


def _stream_key(url: str) -> Optional[str]:
    """A stable id for the multi-part stream a URL belongs to, or None."""
    m = _TWIMG_RE.match(url or "")
    if m:
        return "twimg:" + m.group(2)  # group by Twitter/X media id
    base = (url or "").split("?", 1)[0].lower()
    if base.endswith(".m4s") or base.endswith(".ts"):
        # generic HLS: group by the path with the last 2 components (range dir +
        # segment file) stripped — collapses a variant's segment run to one key.
        head = (url or "").split("?", 1)[0].rsplit("/", 2)[0]
        return "hls:" + head
    return None


def _res_area(url: str) -> int:
    m = re.search(r"/(\d{2,4})x(\d{2,4})/", url or "")
    return int(m.group(1)) * int(m.group(2)) if m else 0


def _audio_rate(url: str) -> int:
    m = re.search(r"/mp4a/(\d+)/", url or "")
    return int(m.group(1)) if m else 0


def _is_master_m3u8(url: str) -> bool:
    # Twitter master: /pl/{token}.m3u8 with NO avc1/mp4a sub-path (it references
    # every video + audio rendition, so ffmpeg/yt-dlp get the complete A/V).
    u = (url or "").split("?", 1)[0]
    return bool(re.search(r"/pl/[A-Za-z0-9_-]+\.m3u8$", u)) and "/avc1/" not in u and "/mp4a/" not in u


def _collapse_streams(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Collapse multi-part HLS streams to ONE reconstructed, cloneable entry each;
    non-stream records (manifests-as-page, direct media, pages) pass through."""
    groups: Dict[str, Dict[str, Any]] = {}
    out: List[Dict[str, Any]] = []
    for r in records:
        url = r.get("url", "")
        key = _stream_key(url)
        if not key:
            out.append(r)
            continue
        g = groups.get(key)
        if not g:
            g = {"host": r.get("host"), "ts": 0, "parts": 0,
                 "master": None, "video": None, "audio": None, "any": url}
            groups[key] = g
        g["ts"] = max(g["ts"], r.get("ts", 0))
        g["parts"] += int(r.get("hits", 1) or 1)
        low = url.split("?", 1)[0].lower()
        if low.endswith(".m3u8"):
            if _is_master_m3u8(url):
                g["master"] = url
            elif _audio_rate(url) or "/mp4a/" in url:
                if not g["audio"] or _audio_rate(url) > _audio_rate(g["audio"]):
                    g["audio"] = url
            else:  # video variant playlist
                if not g["video"] or _res_area(url) >= _res_area(g["video"]):
                    g["video"] = url
    for key, g in groups.items():
        url = g["master"] or g["video"] or g["any"]
        audio = None if g["master"] else g["audio"]  # master already carries audio
        out.append({
            "url": url, "audio_url": audio, "host": g["host"], "kind": "stream",
            "ctype": "application/vnd.apple.mpegurl", "bytes": 0, "ts": g["ts"],
            "hits": g["parts"], "parts": g["parts"], "stream_id": key.split(":", 1)[1],
        })
    return out


def _read_catch(limit: int = 200) -> List[Dict[str, Any]]:
    """Discovered media, newest first. The live catch log is on tmpfs (cleared on
    reboot), so we merge it into a DURABLE, capped store — discovery survives
    reboots. Multi-part HLS streams are collapsed to ONE reconstructed entry BEFORE
    storing (so the segment flood never reaches the durable store). Merge is
    idempotent OVERRIDE (not increment); part counts take the max, never sum."""
    durable: Dict[str, Dict[str, Any]] = {}
    for r in _load_json(DISCOVERED_STORE, []) or []:
        u = r.get("url")
        if u:
            durable[u] = r
    changed = False
    for rec in _collapse_streams(list(_parse_catch_log().values())):
        u = rec["url"]
        old = durable.get(u)
        if old and rec.get("kind") == "stream":
            rec["parts"] = max(rec.get("parts", 0), old.get("parts", 0))
            rec["hits"] = rec["parts"]
        if (not old) or rec["ts"] >= old.get("ts", 0) or rec.get("hits") != old.get("hits"):
            durable[u] = rec
            changed = True
    rows = sorted(durable.values(), key=lambda x: x.get("ts", 0), reverse=True)
    if len(rows) > DISCOVERED_MAX:
        rows = rows[:DISCOVERED_MAX]
        changed = True
    if changed:
        try:
            _save_json(DISCOVERED_STORE, rows)
        except Exception:
            pass
    return rows[:limit]


def _downloader() -> Optional[str]:
    """Best available cloner: yt-dlp (broadest) else ffmpeg, else None."""
    if shutil.which("yt-dlp"):
        return "yt-dlp"
    if shutil.which("ffmpeg"):
        return "ffmpeg"
    return None


def _save_clone_jobs():
    try:
        _save_json(CLONE_JOBS_FILE, list(_clone_jobs.values()))
    except Exception:
        pass


def _load_clone_jobs():
    for j in _load_json(CLONE_JOBS_FILE, []) or []:
        if j.get("status") == "running":  # stale from a previous run
            j["status"] = "error"; j["error"] = "interrupted (service restart)"
        _clone_jobs[j["id"]] = j


def _ensure_clone_worker():
    """Lazily start the clone worker — the aggregator imports this module in-process
    and never fires its @on_event startup, so we can't rely on a lifespan hook."""
    global _clone_worker_task
    if not _clone_jobs and CLONE_JOBS_FILE.exists():
        _load_clone_jobs()
    if _clone_worker_task is None or _clone_worker_task.done():
        _clone_worker_task = asyncio.create_task(_clone_worker())


async def _run_clone(job_id: str) -> None:
    job = _clone_jobs.get(job_id)
    if not job:
        return
    tool = _downloader()
    if not tool:
        job.update(status="error", error="no downloader (install yt-dlp or ffmpeg)"); _save_clone_jobs(); return
    try:
        LIBRARY_DIR.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        job.update(status="error", error=f"library dir: {e}"); _save_clone_jobs(); return
    url = job["url"]
    audio_url = job.get("audio_url")
    ext = "m4a" if job.get("kind") == "audio" else "mp4"
    out = LIBRARY_DIR / f"{job_id}.{ext}"
    if audio_url:
        # Reconstructed multi-part stream with SEPARATE video + audio variant
        # playlists (no master was seen): mux them with ffmpeg into one file. Always
        # ffmpeg here — yt-dlp can't take two arbitrary playlist inputs like this.
        cmd = ["nice", "-n", "15", "ffmpeg", "-y", "-loglevel", "error",
               "-i", url, "-i", audio_url, "-c", "copy",
               "-map", "0:v:0", "-map", "1:a:0", str(out)]
    elif tool == "yt-dlp":
        cmd = ["nice", "-n", "15", "yt-dlp", "--no-playlist", "--no-progress",
               "--no-part", "-o", str(LIBRARY_DIR / f"{job_id}.%(ext)s"), url]
    else:  # ffmpeg: HLS/DASH manifest or direct media → stream-copy
        cmd = ["nice", "-n", "15", "ffmpeg", "-y", "-loglevel", "error", "-i", url, "-c", "copy", str(out)]
    job.update(status="running", error=None); _save_clone_jobs()
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE)
        try:
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=CLONE_TIMEOUT_S)
        except asyncio.TimeoutError:
            proc.kill(); await proc.wait()
            job.update(status="error", error=f"timeout after {CLONE_TIMEOUT_S}s"); _save_clone_jobs(); return
        if proc.returncode != 0:
            err = (stderr or b"").decode("utf-8", "ignore").strip()[-400:]
            job.update(status="error", error=err or f"exit {proc.returncode}"); _save_clone_jobs(); return
    except Exception as e:
        job.update(status="error", error=str(e)); _save_clone_jobs(); return
    produced = next(iter(sorted(LIBRARY_DIR.glob(f"{job_id}.*"))), None)
    if not produced or not produced.exists() or produced.stat().st_size == 0:
        job.update(status="error", error="no output produced"); _save_clone_jobs(); return
    job.update(status="done", file=produced.name, bytes=produced.stat().st_size, error=None)
    _save_clone_jobs()


async def _clone_worker():
    while True:
        job_id = await _clone_queue.get()
        try:
            await _run_clone(job_id)
        except Exception as e:
            j = _clone_jobs.get(job_id)
            if j:
                j.update(status="error", error=str(e)); _save_clone_jobs()
        finally:
            _clone_queue.task_done()


class CloneRequest(BaseModel):
    url: str
    audio_url: Optional[str] = None  # separate audio playlist to mux (reconstructed streams)
    kind: Optional[str] = None
    title: Optional[str] = None

    @field_validator("url", "audio_url")
    @classmethod
    def _v(cls, v):
        if v is not None and not v.startswith(("http://", "https://")):
            raise ValueError("url must be http(s)")
        return v


@router.get("/discovered")
async def discovered(limit: int = 200, user=Depends(require_jwt)):
    """Media URLs the R4 reverse-catcher saw on MITM'd flows (newest first)."""
    return {"discovered": _read_catch(limit), "downloader": _downloader(),
            "catcher": MEDIA_CATCH_PATH.exists()}


@router.post("/clone")
async def clone(req: CloneRequest, user=Depends(require_jwt)):
    """Enqueue a clone of a discovered media URL into the library."""
    if not _downloader():
        raise HTTPException(503, "no downloader available (install yt-dlp or ffmpeg)")
    _ensure_clone_worker()
    job_id = secrets.token_hex(6)
    title = req.title or req.url.split("/")[-1].split("?")[0] or req.url
    _clone_jobs[job_id] = {"id": job_id, "url": req.url, "audio_url": req.audio_url,
                           "kind": req.kind, "title": title,
                           "status": "queued", "file": None, "bytes": 0, "error": None,
                           "ts": int(time.time())}
    _save_clone_jobs()
    await _clone_queue.put(job_id)
    return {"id": job_id, "status": "queued"}


@router.get("/clone/jobs")
async def clone_jobs(user=Depends(require_jwt)):
    if not _clone_jobs and CLONE_JOBS_FILE.exists():
        _load_clone_jobs()
    return {"jobs": sorted(_clone_jobs.values(), key=lambda x: x["ts"], reverse=True)}


@router.get("/library")
async def library(user=Depends(require_jwt)):
    """Cloned media available for download/share."""
    if not _clone_jobs and CLONE_JOBS_FILE.exists():
        _load_clone_jobs()
    items = [j for j in _clone_jobs.values() if j.get("status") == "done" and j.get("file")]
    items.sort(key=lambda x: x["ts"], reverse=True)
    return {"library": items, "downloader": _downloader()}


@router.get("/download/{job_id}")
async def download(job_id: str, user=Depends(require_jwt)):
    if not _clone_jobs and CLONE_JOBS_FILE.exists():
        _load_clone_jobs()
    job = _clone_jobs.get(job_id)
    if not job or job.get("status") != "done" or not job.get("file"):
        raise HTTPException(404, "not found")
    fp = LIBRARY_DIR / job["file"]
    if not fp.exists():
        raise HTTPException(404, "file missing")
    return FileResponse(str(fp), filename=job["file"], media_type="application/octet-stream")


@router.delete("/library/{job_id}")
async def library_delete(job_id: str, user=Depends(require_jwt)):
    job = _clone_jobs.get(job_id)
    if job and job.get("file"):
        try:
            (LIBRARY_DIR / job["file"]).unlink(missing_ok=True)
        except Exception:
            pass
    _clone_jobs.pop(job_id, None)
    _save_clone_jobs()
    return {"ok": True}


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
