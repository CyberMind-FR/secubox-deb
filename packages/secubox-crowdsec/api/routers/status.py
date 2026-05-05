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
    """Compute CrowdSec status (synchronous)."""
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
    url, _ = _lapi()

    # Check LAPI via cscli (shell mode for service compatibility)
    try:
        r = subprocess.run(
            "sudo cscli lapi status 2>&1",
            shell=True, capture_output=True, text=True, timeout=10
        )
        output = r.stdout + r.stderr
        if "successfully interact" in output.lower() or r.returncode == 0:
            lapi_reachable = True
    except Exception:
        pass

    # Get decisions count
    try:
        r = subprocess.run(
            "sudo cscli decisions list -o json 2>/dev/null",
            shell=True, capture_output=True, text=True, timeout=10
        )
        if r.returncode == 0 and r.stdout.strip():
            data = json.loads(r.stdout)
            decisions_count = len(data) if isinstance(data, list) else 0
    except Exception:
        pass

    # Check CAPI registration
    try:
        r = subprocess.run(
            "sudo cscli capi status 2>&1",
            shell=True, capture_output=True, text=True, timeout=10
        )
        output = r.stdout + r.stderr
        if "enrolled" in output.lower() or "successfully interact" in output.lower() or r.returncode == 0:
            capi_registered = True
    except Exception:
        pass

    # Get alerts count
    try:
        r = subprocess.run(
            "sudo cscli alerts list -o json 2>/dev/null",
            shell=True, capture_output=True, text=True, timeout=10
        )
        if r.returncode == 0 and r.stdout.strip():
            data = json.loads(r.stdout)
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
    """Compute CrowdSec metrics."""
    try:
        r = subprocess.run(
            "sudo cscli metrics --output json 2>/dev/null",
            shell=True, capture_output=True, text=True, timeout=15
        )
        data = json.loads(r.stdout) if r.stdout else {}

        acquired = parsed = poured = buckets = 0

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
            "acquired": acquired, "parsed": parsed, "poured": poured,
            "buckets": buckets, "raw": data, "cached_at": time.time()
        }
    except Exception as e:
        log.warning("metrics compute: %s", e)
        return {"acquired": 0, "parsed": 0, "poured": 0, "buckets": 0, "cached_at": time.time()}


def _compute_hub_sync() -> Dict[str, Any]:
    """Compute CrowdSec hub status."""
    try:
        r = subprocess.run(
            "sudo cscli hub list --output json 2>/dev/null",
            shell=True, capture_output=True, text=True, timeout=15
        )
        data = json.loads(r.stdout) if r.stdout else {}

        collections = []
        parsers = []
        scenarios = []

        for item in (data.get("collections") or []):
            if isinstance(item, dict):
                installed = "enabled" in (item.get("status") or "") or item.get("installed", False)
                collections.append({
                    "name": item.get("name", ""),
                    "installed": installed,
                    "version": item.get("local_version", "")
                })

        for item in (data.get("parsers") or []):
            if isinstance(item, dict):
                installed = "enabled" in (item.get("status") or "") or item.get("installed", False)
                parsers.append({
                    "name": item.get("name", ""),
                    "installed": installed,
                    "version": item.get("local_version", "")
                })

        for item in (data.get("scenarios") or []):
            if isinstance(item, dict):
                installed = "enabled" in (item.get("status") or "") or item.get("installed", False)
                scenarios.append({
                    "name": item.get("name", ""),
                    "installed": installed,
                    "version": item.get("local_version", "")
                })

        return {
            "collections": collections, "parsers": parsers, "scenarios": scenarios,
            "collections_count": len([c for c in collections if c["installed"]]),
            "parsers_count": len([p for p in parsers if p["installed"]]),
            "scenarios_count": len([s for s in scenarios if s["installed"]]),
            "cached_at": time.time()
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
                status_future = loop.run_in_executor(pool, _compute_status_sync)
                metrics_future = loop.run_in_executor(pool, _compute_metrics_sync)
                hub_future = loop.run_in_executor(pool, _compute_hub_sync)

                status_data, metrics_data, hub_data = await asyncio.gather(
                    status_future, metrics_future, hub_future, return_exceptions=True
                )

            async with _cache_lock:
                if isinstance(status_data, dict):
                    _status_cache = status_data
                if isinstance(metrics_data, dict):
                    _metrics_cache = metrics_data
                if isinstance(hub_data, dict):
                    _hub_cache = hub_data
                if isinstance(status_data, dict):
                    _overview_cache = {
                        "decisions_count": status_data.get("decisions_count", 0),
                        "alerts_count": status_data.get("alerts_count", 0),
                        "machines_count": 1 if status_data.get("running") else 0,
                        "cached_at": time.time()
                    }

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

        except Exception as e:
            log.error("Cache refresh failed: %s", e)

        await asyncio.sleep(30)


def _load_cache_from_file(path: Path) -> Dict[str, Any]:
    if path.exists():
        try:
            return json.loads(path.read_text())
        except Exception:
            pass
    return {}


async def start_cache_refresh():
    global _refresh_task, _status_cache, _metrics_cache, _hub_cache, _overview_cache
    _status_cache = _load_cache_from_file(STATUS_CACHE_FILE)
    _metrics_cache = _load_cache_from_file(METRICS_CACHE_FILE)
    _hub_cache = _load_cache_from_file(HUB_CACHE_FILE)
    _overview_cache = _load_cache_from_file(OVERVIEW_CACHE_FILE)
    if _status_cache:
        log.info("Loaded status cache from file")
    _refresh_task = asyncio.create_task(_refresh_all_caches())


async def stop_cache_refresh():
    global _refresh_task
    if _refresh_task:
        _refresh_task.cancel()
        try:
            await _refresh_task
        except asyncio.CancelledError:
            pass


@router.get("/status")
async def status():
    if _status_cache:
        return _status_cache
    file_cache = _load_cache_from_file(STATUS_CACHE_FILE)
    if file_cache:
        return file_cache
    return _compute_status_sync()


@router.get("/metrics")
async def metrics():
    if _metrics_cache:
        return _metrics_cache
    file_cache = _load_cache_from_file(METRICS_CACHE_FILE)
    if file_cache:
        return file_cache
    return _compute_metrics_sync()


@router.get("/hub")
async def hub():
    if _hub_cache:
        return _hub_cache
    file_cache = _load_cache_from_file(HUB_CACHE_FILE)
    if file_cache:
        return file_cache
    return _compute_hub_sync()


@router.get("/waf_status")
async def waf_status(user=Depends(require_jwt)):
    if _status_cache:
        return {"active": _status_cache.get("lapi_reachable", False), "recent_bans": _status_cache.get("decisions_count", 0)}
    try:
        data = await _lapi_get("/v1/decisions?scope=Ip&type=ban&limit=5")
        return {"active": True, "recent_bans": len(data) if isinstance(data, list) else 0}
    except Exception as e:
        return {"active": False, "error": str(e)}


@router.get("/get_overview")
async def get_overview(user=Depends(require_jwt)):
    if _overview_cache:
        return _overview_cache
    if _status_cache:
        return {
            "decisions_count": _status_cache.get("decisions_count", 0),
            "alerts_count": _status_cache.get("alerts_count", 0),
            "machines_count": 1 if _status_cache.get("running") else 0
        }
    return {"error": "Cache not ready"}


@router.get("/cache_info")
async def cache_info():
    return {
        "status_cached": bool(_status_cache),
        "metrics_cached": bool(_metrics_cache),
        "hub_cached": bool(_hub_cache),
        "overview_cached": bool(_overview_cache),
        "status_cached_at": _status_cache.get("cached_at") if _status_cache else None
    }
