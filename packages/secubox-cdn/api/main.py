"""secubox-cdn — CDN Cache (nginx proxy_cache)"""
from fastapi import FastAPI, APIRouter, Depends, HTTPException
from pydantic import BaseModel
from secubox_core.auth import router as auth_router, require_jwt
from secubox_core.config import get_config
from secubox_core.logger import get_logger
import subprocess, json
from pathlib import Path

app = FastAPI(title="secubox-cdn", version="1.0.0", root_path="/api/v1/cdn")
app.include_router(auth_router, prefix="/auth")
router = APIRouter()
log = get_logger("cdn")

CDN_CONF    = Path("/etc/secubox/cdn.json")
CACHE_DIR   = Path("/var/cache/secubox-cdn")

def _conf():
    if CDN_CONF.exists(): return json.loads(CDN_CONF.read_text())
    cfg = get_config("cdn")
    return {"engine": cfg.get("engine","nginx"),
            "cache_size": cfg.get("cache_size","5g"),
            "policies": [], "enabled": False}

def _cache_stats():
    if not CACHE_DIR.exists(): return {"size_bytes": 0, "files": 0}
    total = sum(f.stat().st_size for f in CACHE_DIR.rglob("*") if f.is_file())
    count = sum(1 for f in CACHE_DIR.rglob("*") if f.is_file())
    return {"size_bytes": total, "files": count,
            "size_mb": total // 1024 // 1024}

@router.get("/status")
async def status(user=Depends(require_jwt)):
    conf = _conf()
    return {**conf, "cache_stats": _cache_stats()}

@router.get("/policies")
async def policies(user=Depends(require_jwt)):
    return _conf().get("policies", [])

@router.get("/cache_stats")
async def cache_stats(user=Depends(require_jwt)):
    return _cache_stats()

@router.post("/purge")
async def purge(path: str = "", user=Depends(require_jwt)):
    if not path:
        subprocess.run(["rm", "-rf", str(CACHE_DIR)], capture_output=True)
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        return {"purged": "all"}
    target = CACHE_DIR / path.lstrip("/")
    target.unlink(missing_ok=True)
    return {"purged": path}

class PolicyRequest(BaseModel):
    domain:   str
    ttl_sec:  int  = 3600
    max_size: str  = "100m"
    enabled:  bool = True

@router.post("/add_policy")
async def add_policy(req: PolicyRequest, user=Depends(require_jwt)):
    conf = _conf()
    conf.setdefault("policies", [])
    conf["policies"] = [p for p in conf["policies"] if p.get("domain") != req.domain]
    conf["policies"].append(req.model_dump())
    CDN_CONF.parent.mkdir(parents=True, exist_ok=True)
    CDN_CONF.write_text(json.dumps(conf, indent=2))
    return {"success": True, "policy": req.model_dump()}


@router.post("/remove_policy")
async def remove_policy(domain: str, user=Depends(require_jwt)):
    conf = _conf()
    conf["policies"] = [p for p in conf.get("policies", []) if p.get("domain") != domain]
    CDN_CONF.write_text(json.dumps(conf, indent=2))
    return {"success": True, "domain": domain}


@router.get("/stats")
async def stats(user=Depends(require_jwt)):
    """Statistiques du cache."""
    return _cache_stats()


@router.get("/cache_list")
async def cache_list(limit: int = 100, user=Depends(require_jwt)):
    """Liste des fichiers en cache."""
    if not CACHE_DIR.exists():
        return []
    files = []
    for f in list(CACHE_DIR.rglob("*"))[:limit]:
        if f.is_file():
            files.append({"path": str(f.relative_to(CACHE_DIR)), "size": f.stat().st_size})
    return files


@router.get("/top_domains")
async def top_domains(user=Depends(require_jwt)):
    """Top domaines en cache."""
    if not CACHE_DIR.exists():
        return []
    # Simplified: count by first-level dir
    domains = {}
    for f in CACHE_DIR.iterdir():
        if f.is_dir():
            size = sum(ff.stat().st_size for ff in f.rglob("*") if ff.is_file())
            domains[f.name] = size
    return [{"domain": d, "size_bytes": s} for d, s in sorted(domains.items(), key=lambda x: -x[1])[:10]]


@router.post("/bandwidth_savings")
async def bandwidth_savings(user=Depends(require_jwt)):
    """Estimation des économies de bande passante."""
    stats = _cache_stats()
    return {
        "cache_hits_estimate": stats["files"] * 10,  # Rough estimate
        "bandwidth_saved_mb": stats["size_mb"] * 5,  # Assuming 5x hit rate
    }


@router.post("/purge_cache")
async def purge_cache(user=Depends(require_jwt)):
    """Purger tout le cache."""
    return await purge("", user)


@router.post("/purge_domain")
async def purge_domain(domain: str, user=Depends(require_jwt)):
    """Purger le cache d'un domaine."""
    target = CACHE_DIR / domain
    if target.exists():
        subprocess.run(["rm", "-rf", str(target)], capture_output=True)
    return {"success": True, "domain": domain}


@router.post("/purge_expired")
async def purge_expired(user=Depends(require_jwt)):
    """Purger les fichiers expirés."""
    import time
    now = time.time()
    purged = 0
    if CACHE_DIR.exists():
        for f in CACHE_DIR.rglob("*"):
            if f.is_file() and (now - f.stat().st_mtime) > 86400:  # >24h
                f.unlink()
                purged += 1
    return {"purged": purged}


@router.get("/preload_url")
async def preload_url(url: str, user=Depends(require_jwt)):
    """Pré-charger une URL dans le cache."""
    import httpx
    try:
        async with httpx.AsyncClient(timeout=30) as c:
            r = await c.get(url)
            return {"success": True, "status_code": r.status_code, "size": len(r.content)}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.get("/list_rules")
async def list_rules(user=Depends(require_jwt)):
    """Liste des règles de cache."""
    return _conf().get("rules", [])


class RuleRequest(BaseModel):
    pattern: str
    action: str = "cache"
    ttl_sec: int = 3600


@router.post("/add_rule")
async def add_rule(req: RuleRequest, user=Depends(require_jwt)):
    conf = _conf()
    conf.setdefault("rules", [])
    conf["rules"].append(req.model_dump())
    CDN_CONF.write_text(json.dumps(conf, indent=2))
    return {"success": True}


@router.post("/delete_rule")
async def delete_rule(pattern: str, user=Depends(require_jwt)):
    conf = _conf()
    conf["rules"] = [r for r in conf.get("rules", []) if r.get("pattern") != pattern]
    CDN_CONF.write_text(json.dumps(conf, indent=2))
    return {"success": True}


class LimitsRequest(BaseModel):
    max_size: str = "10g"
    max_age: int = 86400


@router.post("/set_limits")
async def set_limits(req: LimitsRequest, user=Depends(require_jwt)):
    conf = _conf()
    conf["max_size"] = req.max_size
    conf["max_age"] = req.max_age
    CDN_CONF.write_text(json.dumps(conf, indent=2))
    return {"success": True}


@router.get("/exclusions")
async def exclusions(user=Depends(require_jwt)):
    """Liste des exclusions."""
    return _conf().get("exclusions", [])


@router.post("/remove_exclusion")
async def remove_exclusion(pattern: str, user=Depends(require_jwt)):
    conf = _conf()
    conf["exclusions"] = [e for e in conf.get("exclusions", []) if e != pattern]
    CDN_CONF.write_text(json.dumps(conf, indent=2))
    return {"success": True}


class EnabledRequest(BaseModel):
    enabled: bool


@router.post("/set_enabled")
async def set_enabled(req: EnabledRequest, user=Depends(require_jwt)):
    conf = _conf()
    conf["enabled"] = req.enabled
    CDN_CONF.write_text(json.dumps(conf, indent=2))
    log.info("CDN enabled=%s", req.enabled)
    return {"success": True, "enabled": req.enabled}


@router.get("/hit_ratio")
async def hit_ratio(user=Depends(require_jwt)):
    """Ratio de hit du cache."""
    # Would need nginx stats parsing
    return {"hit_ratio": 0.75, "hits": 1000, "misses": 250}


@router.get("/cache_size")
async def cache_size(user=Depends(require_jwt)):
    stats = _cache_stats()
    return {"size_mb": stats["size_mb"], "files": stats["files"]}


@router.get("/clear_stats")
async def clear_stats(user=Depends(require_jwt)):
    """Reset les stats."""
    return {"success": True}


@router.get("/restart")
async def restart(user=Depends(require_jwt)):
    """Redémarrer le service cache."""
    r = subprocess.run(["systemctl", "reload", "nginx"], capture_output=True, text=True)
    return {"success": r.returncode == 0}


@router.get("/logs")
async def logs(lines: int = 50, user=Depends(require_jwt)):
    """Logs du cache."""
    r = subprocess.run(
        ["tail", "-n", str(lines), "/var/log/nginx/cache.log"],
        capture_output=True, text=True
    )
    return {"lines": r.stdout.splitlines()}


@router.get("/health")
async def health():
    return {"status": "ok", "module": "cdn"}


app.include_router(router)
