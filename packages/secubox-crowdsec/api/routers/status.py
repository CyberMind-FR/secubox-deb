"""secubox-crowdsec — status, metrics, overview, waf_status"""
import subprocess, shutil
from fastapi import APIRouter, Depends
import httpx

from secubox_core.auth   import require_jwt
from secubox_core.config import get_config
from secubox_core.logger import get_logger

router = APIRouter()
log    = get_logger("crowdsec")


def _lapi() -> tuple[str, str]:
    cfg = get_config("crowdsec")
    return cfg.get("lapi_url", "http://127.0.0.1:8080"), cfg.get("lapi_key", "")


async def _lapi_get(path: str) -> dict | list:
    url, key = _lapi()
    async with httpx.AsyncClient(timeout=10.0) as c:
        r = await c.get(f"{url}{path}", headers={"X-Api-Key": key})
        r.raise_for_status()
        return r.json()


@router.get("/status")
async def status():
    """CrowdSec status for dashboard (public)."""
    running = subprocess.run(["pgrep", "crowdsec"], capture_output=True).returncode == 0
    version = ""
    if shutil.which("crowdsec"):
        r = subprocess.run(["crowdsec", "-version"], capture_output=True, text=True)
        version = (r.stdout or r.stderr).strip().splitlines()[0] if (r.stdout or r.stderr) else ""

    lapi_reachable = False
    capi_registered = False
    try:
        await _lapi_get("/v1/decisions?limit=0")
        lapi_reachable = True
        # Check CAPI registration via cscli
        r = subprocess.run(["cscli", "capi", "status"], capture_output=True, text=True, timeout=5)
        capi_registered = "registered" in r.stdout.lower() or r.returncode == 0
    except Exception:
        pass

    return {
        "running": running,
        "version": version,
        "lapi_reachable": lapi_reachable,
        "capi_registered": capi_registered,
        "lapi_url": _lapi()[0],
    }


@router.get("/metrics")
async def metrics():
    """Métriques CrowdSec for dashboard (public)."""
    try:
        r = subprocess.run(
            ["cscli", "metrics", "--output", "json"],
            capture_output=True, text=True, timeout=10
        )
        import json
        data = json.loads(r.stdout) if r.stdout else {}
        # Extract key metrics for dashboard
        acquired = 0
        parsed = 0
        poured = 0
        buckets = 0
        if "acquisition" in data:
            for src in data["acquisition"].values() if isinstance(data["acquisition"], dict) else []:
                acquired += src.get("lines_read", 0) if isinstance(src, dict) else 0
        if "parser" in data:
            for p in data["parser"].values() if isinstance(data["parser"], dict) else []:
                parsed += p.get("hits", 0) if isinstance(p, dict) else 0
        if "bucket" in data:
            buckets = len(data["bucket"]) if isinstance(data["bucket"], dict) else 0
            for b in data["bucket"].values() if isinstance(data["bucket"], dict) else []:
                poured += b.get("poured", 0) if isinstance(b, dict) else 0
        return {"acquired": acquired, "parsed": parsed, "poured": poured, "buckets": buckets, "raw": data}
    except Exception as e:
        log.warning("metrics: %s", e)
        return {"acquired": 0, "parsed": 0, "poured": 0, "buckets": 0}


@router.get("/hub")
async def hub():
    """Statut du hub CrowdSec for dashboard (public)."""
    try:
        r = subprocess.run(
            ["cscli", "hub", "list", "--output", "json"],
            capture_output=True, text=True, timeout=15
        )
        import json
        data = json.loads(r.stdout) if r.stdout else {}
        # Format for dashboard - cscli returns array with status field
        collections = []
        parsers = []
        scenarios = []
        for item in (data.get("collections") or []):
            if isinstance(item, dict):
                installed = item.get("status") == "enabled" or item.get("installed", False)
                collections.append({"name": item.get("name", ""), "installed": installed, "version": item.get("local_version", "")})
        for item in (data.get("parsers") or []):
            if isinstance(item, dict):
                installed = item.get("status") == "enabled" or item.get("installed", False)
                parsers.append({"name": item.get("name", ""), "installed": installed, "version": item.get("local_version", "")})
        for item in (data.get("scenarios") or []):
            if isinstance(item, dict):
                installed = item.get("status") == "enabled" or item.get("installed", False)
                scenarios.append({"name": item.get("name", ""), "installed": installed, "version": item.get("local_version", "")})
        return {"collections": collections, "parsers": parsers, "scenarios": scenarios}
    except Exception as e:
        log.warning("hub: %s", e)
        return {"collections": [], "parsers": [], "scenarios": []}


@router.get("/waf_status")
async def waf_status(user=Depends(require_jwt)):
    """Statut du WAF AppSec CrowdSec."""
    try:
        data = await _lapi_get("/v1/decisions?scope=Ip&type=ban&limit=5")
        return {"active": True, "recent_bans": len(data) if isinstance(data, list) else 0}
    except Exception as e:
        return {"active": False, "error": str(e)}


@router.get("/get_overview")
async def get_overview(user=Depends(require_jwt)):
    """Vue synthétique : nb décisions, alertes, machines."""
    try:
        decisions = await _lapi_get("/v1/decisions?limit=0")
        alerts    = await _lapi_get("/v1/alerts?limit=0")
        machines  = await _lapi_get("/v1/watchers")
        return {
            "decisions_count": len(decisions) if isinstance(decisions, list) else 0,
            "alerts_count":    len(alerts)    if isinstance(alerts,    list) else 0,
            "machines_count":  len(machines)  if isinstance(machines,  list) else 0,
        }
    except Exception as e:
        log.error("get_overview: %s", e)
        return {"error": str(e)}
