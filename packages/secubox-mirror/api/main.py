"""secubox-mirror -- Mirror/CDN Caching for APT Repositories

Features:
- nginx caching proxy configuration management
- APT repository mirror management
- Cache statistics (hit rate, size, requests)
- Mirror sync status monitoring
- Cache purge functionality
"""
from fastapi import FastAPI, APIRouter, Depends, HTTPException
from pydantic import BaseModel
from secubox_core.auth import router as auth_router, require_jwt
from secubox_core.config import get_config
from secubox_core.logger import get_logger
import subprocess
import json
import hashlib
import time
import asyncio
from pathlib import Path
from typing import List, Optional, Dict
from datetime import datetime

app = FastAPI(title="secubox-mirror", version="1.0.0", root_path="/api/v1/mirror")
app.include_router(auth_router, prefix="/auth")
router = APIRouter()
log = get_logger("mirror")

MIRROR_CONF = Path("/etc/secubox/mirror.json")
CACHE_DIR = Path("/var/cache/secubox-mirror")
MIRRORS_DIR = Path("/var/lib/secubox/mirrors")
SYNC_STATE = Path("/var/lib/secubox/mirror-sync.json")
NGINX_MIRROR_CONF = Path("/etc/nginx/secubox-mirror.d")

# In-memory state
_cache: Dict[str, dict] = {}
_sync_status: Dict[str, dict] = {}


def _load_conf() -> dict:
    """Load mirror configuration."""
    if MIRROR_CONF.exists():
        try:
            return json.loads(MIRROR_CONF.read_text())
        except Exception:
            pass
    cfg = get_config("mirror")
    return {
        "enabled": cfg.get("enabled", True),
        "cache_size": cfg.get("cache_size", "10g"),
        "cache_ttl": cfg.get("cache_ttl", 86400),
        "mirrors": cfg.get("mirrors", []),
    }


def _save_conf(conf: dict):
    """Save mirror configuration."""
    MIRROR_CONF.parent.mkdir(parents=True, exist_ok=True)
    MIRROR_CONF.write_text(json.dumps(conf, indent=2))


def _load_sync_state() -> dict:
    """Load sync state from disk."""
    if SYNC_STATE.exists():
        try:
            return json.loads(SYNC_STATE.read_text())
        except Exception:
            pass
    return {}


def _save_sync_state(state: dict):
    """Save sync state to disk."""
    SYNC_STATE.parent.mkdir(parents=True, exist_ok=True)
    SYNC_STATE.write_text(json.dumps(state, indent=2))


def _cache_stats() -> dict:
    """Calculate cache statistics."""
    if not CACHE_DIR.exists():
        return {"size_bytes": 0, "files": 0, "size_mb": 0}
    try:
        total = sum(f.stat().st_size for f in CACHE_DIR.rglob("*") if f.is_file())
        count = sum(1 for f in CACHE_DIR.rglob("*") if f.is_file())
        return {
            "size_bytes": total,
            "files": count,
            "size_mb": total // 1024 // 1024,
        }
    except Exception as e:
        log.warning("Failed to calculate cache stats: %s", e)
        return {"size_bytes": 0, "files": 0, "size_mb": 0}


def _nginx_cache_stats() -> dict:
    """Parse nginx cache status if available."""
    stats = {
        "hits": 0,
        "misses": 0,
        "hit_rate": 0.0,
        "requests": 0,
        "bandwidth_saved_mb": 0,
    }
    # Try reading nginx cache log for statistics
    cache_log = Path("/var/log/nginx/mirror-cache.log")
    if cache_log.exists():
        try:
            lines = cache_log.read_text().splitlines()[-1000:]  # Last 1000 lines
            for line in lines:
                if "HIT" in line:
                    stats["hits"] += 1
                elif "MISS" in line:
                    stats["misses"] += 1
            stats["requests"] = stats["hits"] + stats["misses"]
            if stats["requests"] > 0:
                stats["hit_rate"] = round(stats["hits"] / stats["requests"] * 100, 1)
        except Exception:
            pass
    return stats


# ============================================================================
# Health & Status Endpoints
# ============================================================================


@router.get("/health")
async def health():
    """Health check endpoint - no auth required."""
    return {"status": "ok", "module": "mirror"}


@router.get("/status")
async def status(user=Depends(require_jwt)):
    """Get mirror service status."""
    conf = _load_conf()
    cache = _cache_stats()
    nginx_stats = _nginx_cache_stats()
    sync_state = _load_sync_state()

    return {
        "enabled": conf.get("enabled", True),
        "cache_size_limit": conf.get("cache_size", "10g"),
        "cache_ttl": conf.get("cache_ttl", 86400),
        "mirror_count": len(conf.get("mirrors", [])),
        "cache_stats": cache,
        "nginx_stats": nginx_stats,
        "last_sync": sync_state.get("last_sync"),
    }


# ============================================================================
# Mirror Management Endpoints
# ============================================================================


@router.get("/mirrors")
async def list_mirrors(user=Depends(require_jwt)):
    """List all configured mirrors."""
    conf = _load_conf()
    sync_state = _load_sync_state()
    mirrors = conf.get("mirrors", [])

    # Enrich with sync status
    for m in mirrors:
        mid = m.get("id", m.get("name", ""))
        m["sync_status"] = sync_state.get(mid, {}).get("status", "unknown")
        m["last_sync"] = sync_state.get(mid, {}).get("last_sync")
        m["objects"] = sync_state.get(mid, {}).get("objects", 0)
        m["size_mb"] = sync_state.get(mid, {}).get("size_mb", 0)

    return {"mirrors": mirrors}


@router.get("/mirror/{name}")
async def get_mirror(name: str, user=Depends(require_jwt)):
    """Get details of a specific mirror."""
    conf = _load_conf()
    sync_state = _load_sync_state()

    for m in conf.get("mirrors", []):
        if m.get("name") == name or m.get("id") == name:
            mid = m.get("id", m.get("name", ""))
            m["sync_status"] = sync_state.get(mid, {}).get("status", "unknown")
            m["last_sync"] = sync_state.get(mid, {}).get("last_sync")
            m["objects"] = sync_state.get(mid, {}).get("objects", 0)
            m["size_mb"] = sync_state.get(mid, {}).get("size_mb", 0)
            return m

    raise HTTPException(status_code=404, detail="Mirror not found")


class MirrorAddRequest(BaseModel):
    name: str
    url: str
    type: str = "apt"  # apt, npm, pypi, docker, generic
    enabled: bool = True
    sync_interval: int = 3600  # seconds
    max_size: str = "5g"


@router.post("/mirror/add")
async def add_mirror(req: MirrorAddRequest, user=Depends(require_jwt)):
    """Add a new mirror."""
    conf = _load_conf()
    mirrors = conf.setdefault("mirrors", [])

    # Check for duplicate
    for m in mirrors:
        if m.get("name") == req.name:
            raise HTTPException(status_code=400, detail="Mirror with this name already exists")

    mirror_id = hashlib.sha256(f"{req.name}:{req.url}".encode()).hexdigest()[:12]
    new_mirror = {
        "id": mirror_id,
        "name": req.name,
        "url": req.url,
        "type": req.type,
        "enabled": req.enabled,
        "sync_interval": req.sync_interval,
        "max_size": req.max_size,
        "created": datetime.now().isoformat(),
    }
    mirrors.append(new_mirror)
    _save_conf(conf)

    # Generate nginx config for this mirror
    _generate_nginx_config(new_mirror)

    log.info("Added mirror: %s (%s)", req.name, req.url)
    return {"success": True, "mirror": new_mirror}


@router.post("/mirror/remove")
async def remove_mirror(name: str, user=Depends(require_jwt)):
    """Remove a mirror."""
    conf = _load_conf()
    mirrors = conf.get("mirrors", [])

    original_count = len(mirrors)
    conf["mirrors"] = [m for m in mirrors if m.get("name") != name and m.get("id") != name]

    if len(conf["mirrors"]) == original_count:
        raise HTTPException(status_code=404, detail="Mirror not found")

    _save_conf(conf)

    # Remove nginx config
    nginx_conf = NGINX_MIRROR_CONF / f"{name}.conf"
    if nginx_conf.exists():
        nginx_conf.unlink()
        _reload_nginx()

    log.info("Removed mirror: %s", name)
    return {"success": True, "name": name}


class MirrorUpdateRequest(BaseModel):
    enabled: Optional[bool] = None
    sync_interval: Optional[int] = None
    max_size: Optional[str] = None


@router.post("/mirror/{name}/update")
async def update_mirror(name: str, req: MirrorUpdateRequest, user=Depends(require_jwt)):
    """Update mirror configuration."""
    conf = _load_conf()
    updated = False

    for m in conf.get("mirrors", []):
        if m.get("name") == name or m.get("id") == name:
            if req.enabled is not None:
                m["enabled"] = req.enabled
            if req.sync_interval is not None:
                m["sync_interval"] = req.sync_interval
            if req.max_size is not None:
                m["max_size"] = req.max_size
            m["updated"] = datetime.now().isoformat()
            updated = True
            break

    if not updated:
        raise HTTPException(status_code=404, detail="Mirror not found")

    _save_conf(conf)
    return {"success": True}


# ============================================================================
# Cache Management Endpoints
# ============================================================================


@router.get("/cache/stats")
async def cache_stats(user=Depends(require_jwt)):
    """Get detailed cache statistics."""
    cache = _cache_stats()
    nginx = _nginx_cache_stats()
    conf = _load_conf()

    return {
        "disk": cache,
        "nginx": nginx,
        "cache_size_limit": conf.get("cache_size", "10g"),
        "cache_ttl_seconds": conf.get("cache_ttl", 86400),
        "cache_path": str(CACHE_DIR),
    }


@router.post("/cache/purge")
async def cache_purge(path: str = "", user=Depends(require_jwt)):
    """Purge cache - all or specific path."""
    if not path:
        # Purge entire cache
        try:
            subprocess.run(["rm", "-rf", str(CACHE_DIR)], capture_output=True, timeout=60)
            CACHE_DIR.mkdir(parents=True, exist_ok=True)
            log.info("Purged entire mirror cache")
            return {"success": True, "purged": "all"}
        except Exception as e:
            log.error("Failed to purge cache: %s", e)
            raise HTTPException(status_code=500, detail=str(e))
    else:
        # Purge specific path
        target = CACHE_DIR / path.lstrip("/")
        if target.exists():
            try:
                if target.is_dir():
                    subprocess.run(["rm", "-rf", str(target)], capture_output=True)
                else:
                    target.unlink()
                log.info("Purged cache path: %s", path)
                return {"success": True, "purged": path}
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        return {"success": False, "error": "Path not found"}


@router.post("/cache/purge_expired")
async def cache_purge_expired(user=Depends(require_jwt)):
    """Purge expired cache entries."""
    conf = _load_conf()
    ttl = conf.get("cache_ttl", 86400)
    now = time.time()
    purged = 0

    if CACHE_DIR.exists():
        for f in CACHE_DIR.rglob("*"):
            if f.is_file():
                try:
                    if (now - f.stat().st_mtime) > ttl:
                        f.unlink()
                        purged += 1
                except Exception:
                    pass

    log.info("Purged %d expired cache entries", purged)
    return {"success": True, "purged_count": purged}


@router.get("/cache/list")
async def cache_list(limit: int = 100, user=Depends(require_jwt)):
    """List cached objects."""
    if not CACHE_DIR.exists():
        return {"files": []}

    files = []
    for f in list(CACHE_DIR.rglob("*"))[:limit]:
        if f.is_file():
            try:
                stat = f.stat()
                files.append({
                    "path": str(f.relative_to(CACHE_DIR)),
                    "size": stat.st_size,
                    "mtime": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    "age_seconds": int(time.time() - stat.st_mtime),
                })
            except Exception:
                pass

    return {"files": files, "total_in_view": len(files)}


# ============================================================================
# Sync Endpoints
# ============================================================================


@router.post("/sync")
async def sync_all(user=Depends(require_jwt)):
    """Trigger sync for all enabled mirrors."""
    conf = _load_conf()
    sync_state = _load_sync_state()
    results = []

    for m in conf.get("mirrors", []):
        if not m.get("enabled", True):
            continue

        mid = m.get("id", m.get("name"))
        result = await _sync_mirror(m)
        sync_state[mid] = {
            "status": "ok" if result["success"] else "error",
            "last_sync": datetime.now().isoformat(),
            "error": result.get("error"),
            "objects": result.get("objects", 0),
            "size_mb": result.get("size_mb", 0),
        }
        results.append({"mirror": m.get("name"), **result})

    sync_state["last_sync"] = datetime.now().isoformat()
    _save_sync_state(sync_state)

    return {"success": True, "results": results}


@router.post("/sync/{name}")
async def sync_mirror_by_name(name: str, user=Depends(require_jwt)):
    """Trigger sync for a specific mirror."""
    conf = _load_conf()
    sync_state = _load_sync_state()

    mirror = None
    for m in conf.get("mirrors", []):
        if m.get("name") == name or m.get("id") == name:
            mirror = m
            break

    if not mirror:
        raise HTTPException(status_code=404, detail="Mirror not found")

    mid = mirror.get("id", mirror.get("name"))
    result = await _sync_mirror(mirror)

    sync_state[mid] = {
        "status": "ok" if result["success"] else "error",
        "last_sync": datetime.now().isoformat(),
        "error": result.get("error"),
        "objects": result.get("objects", 0),
        "size_mb": result.get("size_mb", 0),
    }
    _save_sync_state(sync_state)

    return result


async def _sync_mirror(mirror: dict) -> dict:
    """Perform sync for a mirror."""
    try:
        mtype = mirror.get("type", "generic")
        url = mirror.get("url")
        name = mirror.get("name", "unknown")

        # Validate required fields
        if not url:
            return {"success": False, "error": "Mirror URL not configured"}

        if mtype == "apt":
            # For APT mirrors, we just verify reachability
            # Actual mirroring happens via apt-mirror or nginx cache
            result = subprocess.run(
                ["curl", "-sI", "-o", "/dev/null", "-w", "%{http_code}", url],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.stdout.strip() in ("200", "301", "302"):
                return {"success": True, "message": f"APT mirror {name} is reachable"}
            else:
                return {"success": False, "error": f"Mirror returned {result.stdout.strip()}"}

        elif mtype == "docker":
            # Docker registry check - verify registry API v2
            registry_url = url.rstrip("/") + "/v2/"
            result = subprocess.run(
                ["curl", "-sI", "-o", "/dev/null", "-w", "%{http_code}", registry_url],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.stdout.strip() in ("200", "401"):  # 401 is OK for auth-required registries
                return {"success": True, "message": f"Docker registry {name} is reachable"}
            else:
                return {"success": False, "error": f"Registry returned {result.stdout.strip()}"}

        elif mtype == "npm":
            # NPM registry check - verify npm API
            npm_url = url.rstrip("/") + "/-/ping"
            result = subprocess.run(
                ["curl", "-sI", "-o", "/dev/null", "-w", "%{http_code}", npm_url],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.stdout.strip() in ("200", "204"):
                return {"success": True, "message": f"NPM registry {name} is reachable"}
            else:
                # Fallback: try root URL
                result = subprocess.run(
                    ["curl", "-sI", "-o", "/dev/null", "-w", "%{http_code}", url],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                return {"success": result.stdout.strip() in ("200", "301", "302")}

        elif mtype == "pypi":
            # PyPI registry check - verify simple API
            pypi_url = url.rstrip("/") + "/simple/"
            result = subprocess.run(
                ["curl", "-sI", "-o", "/dev/null", "-w", "%{http_code}", pypi_url],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.stdout.strip() in ("200", "301", "302"):
                return {"success": True, "message": f"PyPI registry {name} is reachable"}
            else:
                return {"success": False, "error": f"PyPI returned {result.stdout.strip()}"}

        elif mtype == "generic":
            # Generic URL check
            result = subprocess.run(
                ["curl", "-sI", "-o", "/dev/null", "-w", "%{http_code}", url],
                capture_output=True,
                text=True,
                timeout=30,
            )
            return {"success": result.stdout.strip() in ("200", "301", "302")}

        else:
            # Unknown type - try generic URL check
            result = subprocess.run(
                ["curl", "-sI", "-o", "/dev/null", "-w", "%{http_code}", url],
                capture_output=True,
                text=True,
                timeout=30,
            )
            return {
                "success": result.stdout.strip() in ("200", "301", "302"),
                "message": f"Unknown type '{mtype}', performed generic check"
            }

    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Sync timeout"}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ============================================================================
# Configuration Endpoints
# ============================================================================


class ConfigUpdateRequest(BaseModel):
    enabled: Optional[bool] = None
    cache_size: Optional[str] = None
    cache_ttl: Optional[int] = None


@router.post("/config")
async def update_config(req: ConfigUpdateRequest, user=Depends(require_jwt)):
    """Update global mirror configuration."""
    conf = _load_conf()

    if req.enabled is not None:
        conf["enabled"] = req.enabled
    if req.cache_size is not None:
        conf["cache_size"] = req.cache_size
    if req.cache_ttl is not None:
        conf["cache_ttl"] = req.cache_ttl

    _save_conf(conf)
    log.info("Updated mirror config")
    return {"success": True, "config": conf}


@router.get("/config")
async def get_config_endpoint(user=Depends(require_jwt)):
    """Get global mirror configuration."""
    return _load_conf()


# ============================================================================
# Nginx Helper Functions
# ============================================================================


def _generate_nginx_config(mirror: dict):
    """Generate nginx config for a mirror."""
    NGINX_MIRROR_CONF.mkdir(parents=True, exist_ok=True)

    name = mirror.get("name")
    url = mirror.get("url")
    max_size = mirror.get("max_size", "5g")

    config = f"""# Mirror: {name}
# Auto-generated by secubox-mirror
location /mirror/{name}/ {{
    proxy_pass {url}/;
    proxy_cache mirror_cache;
    proxy_cache_valid 200 301 302 1d;
    proxy_cache_valid 404 1m;
    proxy_cache_use_stale error timeout updating http_500 http_502 http_503 http_504;
    proxy_cache_lock on;
    proxy_cache_key $scheme$request_uri;
    add_header X-Cache-Status $upstream_cache_status;
    proxy_buffering on;
    proxy_buffer_size 4k;
    proxy_buffers 8 32k;
}}
"""
    conf_file = NGINX_MIRROR_CONF / f"{name}.conf"
    conf_file.write_text(config)
    _reload_nginx()


def _reload_nginx():
    """Reload nginx configuration."""
    try:
        subprocess.run(["systemctl", "reload", "nginx"], capture_output=True, timeout=10)
    except Exception as e:
        log.warning("Failed to reload nginx: %s", e)


# ============================================================================
# Application Setup
# ============================================================================


@app.on_event("startup")
async def startup():
    """Initialize on startup."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    MIRRORS_DIR.mkdir(parents=True, exist_ok=True)
    NGINX_MIRROR_CONF.mkdir(parents=True, exist_ok=True)
    log.info("secubox-mirror started")


app.include_router(router)
