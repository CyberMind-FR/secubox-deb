"""secubox-crowdsec — status, metrics, overview, waf_status

Performance optimized with double-buffer pre-cache pattern.
Background task refreshes cache every 30s for instant responses.
"""
import subprocess
import shutil
import json
import time
import asyncio
import concurrent.futures
from pathlib import Path
from typing import Optional, Dict, Any

from fastapi import APIRouter, Depends
import httpx

from secubox_core.auth import require_jwt
from secubox_core.config import get_config
from secubox_core.logger import get_logger

router = APIRouter()
log = get_logger("crowdsec")

# ═══════════════════════════════════════════════════════════════════════
# Double-Buffer Cache
# ═══════════════════════════════════════════════════════════════════════
CACHE_DIR = Path("/var/cache/secubox/crowdsec")
STATUS_CACHE_FILE = CACHE_DIR / "status.json"
METRICS_CACHE_FILE = CACHE_DIR / "metrics.json"
HUB_CACHE_FILE = CACHE_DIR / "hub.json"
OVERVIEW_CACHE_FILE = CACHE_DIR / "overview.json"

_status_cache: Dict[str, Any] = {}
_metrics_cache: Dict[str, Any] = {}
_hub_cache: Dict[str, Any] = {}
_overview_cache: Dict[str, Any] = {}
_cache_lock = asyncio.Lock()
_refresh_task: Optional[asyncio.Task] = None


def _lapi() -> tuple:
    cfg = get_config("crowdsec")
    return cfg.get("lapi_url", "http://127.0.0.1:8080"), cfg.get("lapi_key", "")


async def _lapi_get(path: str, timeout: float = 5.0) -> dict | list:
    url, key = _lapi()
    async with httpx.AsyncClient(timeout=timeout) as c:
        r = await c.get(f"{url}{path}", headers={"X-Api-Key": key})
        r.raise_for_status()
        return r.json()


def _compute_status_sync() -> Dict[str, Any]:
    """Compute CrowdSec status (synchronous, for thread pool)."""
    running = subprocess.run(
        ["pgrep", "crowdsec"], capture_output=True, timeout=2
    ).returncode == 0

    version = ""
    if shutil.which("crowdsec"):
        try:
            r = subprocess.run(
                ["crowdsec", "-version"],
                capture_output=True, text=True, timeout=3
            )
            version = (r.stdout or r.stderr).strip().splitlines()[0] if (r.stdout or r.stderr) else ""
        except Exception:
            pass

    lapi_reachable = False
    capi_registered = False
    decisions_count = 0
    alerts_count = 0

    # Check LAPI via HTTP (sync with httpx)
    url, key = _lapi()
    try:
        import httpx as httpx_sync
        with httpx_sync.Client(timeout=3.0) as c:
            r = c.get(f"{url}/v1/decisions?limit=0", headers={"X-Api-Key": key})
            if r.status_code == 200:
                lapi_reachable = True
                data = r.json()
                decisions_count = len(data) if isinstance(data, list) else 0
    except Exception:
        pass

    # Check CAPI registration
    try:
        r = subprocess.run(
            ["cscli", "capi", "status"],
            capture_output=True, text=True, timeout=3
        )
        capi_registered = "registered" in r.stdout.lower() or r.returncode == 0
    except Exception:
        pass

    # Get alerts count
    try:
        import httpx as httpx_sync
        with httpx_sync.Client(timeout=3.0) as c:
            r = c.get(f"{url}/v1/alerts?limit=0", headers={"X-Api-Key": key})
            if r.status_code == 200:
                data = r.json()
                alerts_count = len(data) if isinstance(data, list) else 0
    except Exception:
        pass

    return {
        "running": running,
        "version": version,
        "lapi_reachable": lapi_reachable,
        "capi_registered": capi_registered,
        "lapi_url": url,
        "decisions_count": decisions_count,
        "alerts_count": alerts_count,
        "cached_at": time.time(),
    }


def _compute_metrics_sync() -> Dict[str, Any]:
    """Compute CrowdSec metrics (synchronous, for thread pool)."""
    try:
        r = subprocess.run(
            ["cscli", "metrics", "--output", "json"],
            capture_output=True, text=True, timeout=8
        )
        data = json.loads(r.stdout) if r.stdout else {}

        acquired = 0
        parsed = 0
        poured = 0
        buckets = 0

        if "acquisition" in data and isinstance(data["acquisition"], dict):
            for src in data["acquisition"].values():
                if isinstance(src, dict):
                    acquired += src.get("lines_read", 0)

        if "parser" in data and isinstance(data["parser"], dict):
            for p in data["parser"].values():
                if isinstance(p, dict):
                    parsed += p.get("hits", 0)

        if "bucket" in data and isinstance(data["bucket"], dict):
            buckets = len(data["bucket"])
            for b in data["bucket"].values():
                if isinstance(b, dict):
                    poured += b.get("poured", 0)

        return {
            "acquired": acquired,
            "parsed": parsed,
            "poured": poured,
            "buckets": buckets,
            "raw": data,
            "cached_at": time.time(),
        }
    except Exception as e:
        log.warning("metrics compute: %s", e)
        return {"acquired": 0, "parsed": 0, "poured": 0, "buckets": 0, "cached_at": time.time()}


def _compute_hub_sync() -> Dict[str, Any]:
    """Compute CrowdSec hub status (synchronous, for thread pool)."""
    try:
        r = subprocess.run(
            ["cscli", "hub", "list", "--output", "json"],
            capture_output=True, text=True, timeout=10
        )
        data = json.loads(r.stdout) if r.stdout else {}

        collections = []
        parsers = []
        scenarios = []

        for item in (data.get("collections") or []):
            if isinstance(item, dict):
                installed = item.get("status") == "enabled" or item.get("installed", False)
                collections.append({
                    "name": item.get("name", ""),
                    "installed": installed,
                    "version": item.get("local_version", "")
                })

        for item in (data.get("parsers") or []):
            if isinstance(item, dict):
                installed = item.get("status") == "enabled" or item.get("installed", False)
                parsers.append({
                    "name": item.get("name", ""),
                    "installed": installed,
                    "version": item.get("local_version", "")
                })

        for item in (data.get("scenarios") or []):
            if isinstance(item, dict):
                installed = item.get("status") == "enabled" or item.get("installed", False)
                scenarios.append({
                    "name": item.get("name", ""),
                    "installed": installed,
                    "version": item.get("local_version", "")
                })

        return {
            "collections": collections,
            "parsers": parsers,
            "scenarios": scenarios,
            "collections_count": len([c for c in collections if c["installed"]]),
            "parsers_count": len([p for p in parsers if p["installed"]]),
            "scenarios_count": len([s for s in scenarios if s["installed"]]),
            "cached_at": time.time(),
        }
    except Exception as e:
        log.warning("hub compute: %s", e)
        return {"collections": [], "parsers": [], "scenarios": [], "cached_at": time.time()}


async def _refresh_all_caches():
    """Background task to refresh all caches every 30s."""
    global _status_cache, _metrics_cache, _hub_cache, _overview_cache

    while True:
        try:
            loop = asyncio.get_event_loop()
            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
                # Run all computations in parallel
                status_future = loop.run_in_executor(pool, _compute_status_sync)
                metrics_future = loop.run_in_executor(pool, _compute_metrics_sync)
                hub_future = loop.run_in_executor(pool, _compute_hub_sync)

                status_data, metrics_data, hub_data = await asyncio.gather(
                    status_future, metrics_future, hub_future,
                    return_exceptions=True
                )

            # Update caches
            async with _cache_lock:
                if isinstance(status_data, dict):
                    _status_cache = status_data
                if isinstance(metrics_data, dict):
                    _metrics_cache = metrics_data
                if isinstance(hub_data, dict):
                    _hub_cache = hub_data

                # Compute overview from status data
                if isinstance(status_data, dict):
                    _overview_cache = {
                        "decisions_count": status_data.get("decisions_count", 0),
                        "alerts_count": status_data.get("alerts_count", 0),
                        "machines_count": 1 if status_data.get("running") else 0,
                        "cached_at": time.time(),
                    }

            # Persist to files for fast startup
            try:
                CACHE_DIR.mkdir(parents=True, exist_ok=True)
                if isinstance(status_data, dict):
                    STATUS_CACHE_FILE.write_text(json.dumps(status_data))
                if isinstance(metrics_data, dict):
                    METRICS_CACHE_FILE.write_text(json.dumps(metrics_data))
                if isinstance(hub_data, dict):
                    HUB_CACHE_FILE.write_text(json.dumps(hub_data))
            except Exception as e:
                log.debug("Cache file write failed: %s", e)

            log.debug("CrowdSec caches refreshed")

        except Exception as e:
            log.error("Cache refresh failed: %s", e)

        await asyncio.sleep(30)


def _load_cache_from_file(path: Path) -> Dict[str, Any]:
    """Load cache from file for fast startup."""
    if path.exists():
        try:
            return json.loads(path.read_text())
        except Exception:
            pass
    return {}


async def start_cache_refresh():
    """Start the background cache refresh task."""
    global _refresh_task, _status_cache, _metrics_cache, _hub_cache, _overview_cache

    # Load from file cache for instant availability
    _status_cache = _load_cache_from_file(STATUS_CACHE_FILE)
    _metrics_cache = _load_cache_from_file(METRICS_CACHE_FILE)
    _hub_cache = _load_cache_from_file(HUB_CACHE_FILE)
    _overview_cache = _load_cache_from_file(OVERVIEW_CACHE_FILE)

    if _status_cache:
        log.info("Loaded status cache from file")

    # Start background refresh
    _refresh_task = asyncio.create_task(_refresh_all_caches())


async def stop_cache_refresh():
    """Stop the background cache refresh task."""
    global _refresh_task
    if _refresh_task:
        _refresh_task.cancel()
        try:
            await _refresh_task
        except asyncio.CancelledError:
            pass


# ═══════════════════════════════════════════════════════════════════════
# Endpoints — Return cached data instantly
# ═══════════════════════════════════════════════════════════════════════

@router.get("/status")
async def status():
    """CrowdSec status for dashboard (public). Returns cached data instantly."""
    if _status_cache:
        return _status_cache

    # Fallback: file cache
    file_cache = _load_cache_from_file(STATUS_CACHE_FILE)
    if file_cache:
        return file_cache

    # Last resort: compute synchronously (only first request)
    log.warning("Status cache miss - computing synchronously")
    return _compute_status_sync()


@router.get("/metrics")
async def metrics():
    """CrowdSec metrics for dashboard (public). Returns cached data instantly."""
    if _metrics_cache:
        return _metrics_cache

    file_cache = _load_cache_from_file(METRICS_CACHE_FILE)
    if file_cache:
        return file_cache

    log.warning("Metrics cache miss - computing synchronously")
    return _compute_metrics_sync()


@router.get("/hub")
async def hub():
    """CrowdSec hub status for dashboard (public). Returns cached data instantly."""
    if _hub_cache:
        return _hub_cache

    file_cache = _load_cache_from_file(HUB_CACHE_FILE)
    if file_cache:
        return file_cache

    log.warning("Hub cache miss - computing synchronously")
    return _compute_hub_sync()


@router.get("/waf_status")
async def waf_status(user=Depends(require_jwt)):
    """WAF AppSec CrowdSec status. Uses cached decisions count."""
    if _status_cache:
        return {
            "active": _status_cache.get("lapi_reachable", False),
            "recent_bans": _status_cache.get("decisions_count", 0)
        }

    try:
        data = await _lapi_get("/v1/decisions?scope=Ip&type=ban&limit=5")
        return {"active": True, "recent_bans": len(data) if isinstance(data, list) else 0}
    except Exception as e:
        return {"active": False, "error": str(e)}


@router.get("/get_overview")
async def get_overview(user=Depends(require_jwt)):
    """Overview: decisions, alerts, machines count. Returns cached data instantly."""
    if _overview_cache:
        return _overview_cache

    if _status_cache:
        return {
            "decisions_count": _status_cache.get("decisions_count", 0),
            "alerts_count": _status_cache.get("alerts_count", 0),
            "machines_count": 1 if _status_cache.get("running") else 0,
        }

    # Fallback to direct API call
    try:
        decisions = await _lapi_get("/v1/decisions?limit=0")
        alerts = await _lapi_get("/v1/alerts?limit=0")
        machines = await _lapi_get("/v1/watchers")
        return {
            "decisions_count": len(decisions) if isinstance(decisions, list) else 0,
            "alerts_count": len(alerts) if isinstance(alerts, list) else 0,
            "machines_count": len(machines) if isinstance(machines, list) else 0,
        }
    except Exception as e:
        log.error("get_overview: %s", e)
        return {"error": str(e)}


@router.get("/cache_info")
async def cache_info():
    """Cache debug info (public)."""
    return {
        "status_cached": bool(_status_cache),
        "metrics_cached": bool(_metrics_cache),
        "hub_cached": bool(_hub_cache),
        "overview_cached": bool(_overview_cache),
        "status_cached_at": _status_cache.get("cached_at") if _status_cache else None,
        "metrics_cached_at": _metrics_cache.get("cached_at") if _metrics_cache else None,
        "hub_cached_at": _hub_cache.get("cached_at") if _hub_cache else None,
    }
