"""secubox-droplet — File Publisher API

Enhanced features (v2.0.0):
- Upload history and statistics
- Storage usage tracking
- Droplet health monitoring
- Webhook notifications
- Cleanup scheduled tasks
- Export/import droplet configs
"""
import os
import subprocess
import uuid
import asyncio
import time
import threading
import json
import hashlib
import hmac
import httpx
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from enum import Enum

from fastapi import FastAPI, APIRouter, Depends, HTTPException, UploadFile, File, BackgroundTasks, Query
from pydantic import BaseModel, Field
from secubox_core.auth import router as auth_router, require_jwt
from secubox_core.config import get_config
from secubox_core.logger import get_logger

app = FastAPI(title="secubox-droplet", version="2.0.0", root_path="/api/v1/droplet")
app.include_router(auth_router, prefix="/auth")
router = APIRouter()
log = get_logger("droplet")

# Data paths
DATA_DIR = Path("/var/lib/secubox/droplet")
UPLOAD_HISTORY_FILE = DATA_DIR / "upload_history.json"
STATS_FILE = DATA_DIR / "stats.json"
WEBHOOKS_FILE = DATA_DIR / "webhooks.json"

DATA_DIR.mkdir(parents=True, exist_ok=True)

# Job storage (in-memory, could be Redis for production)
_jobs: dict = {}


# ═══════════════════════════════════════════════════════════════════════
# Models
# ═══════════════════════════════════════════════════════════════════════

class DropletType(str, Enum):
    STATIC = "static"
    STREAMLIT = "streamlit"
    UNKNOWN = "unknown"


class UploadRecord(BaseModel):
    id: str
    name: str
    domain: str
    type: DropletType
    timestamp: str
    size_bytes: int = 0
    status: str
    user: str = "unknown"


class WebhookConfig(BaseModel):
    id: str
    url: str
    events: List[str] = ["upload_complete", "droplet_removed", "cleanup_run"]
    secret: Optional[str] = None
    enabled: bool = True
    created_at: str


# ═══════════════════════════════════════════════════════════════════════
# Stats Cache
# ═══════════════════════════════════════════════════════════════════════

class StatsCache:
    """Thread-safe stats cache with TTL."""
    def __init__(self, ttl_seconds: int = 60):
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


stats_cache = StatsCache(ttl_seconds=60)


# ═══════════════════════════════════════════════════════════════════════
# Helper Functions
# ═══════════════════════════════════════════════════════════════════════

def _load_json(path: Path, default=None) -> Any:
    if default is None:
        default = {}
    try:
        if path.exists():
            return json.loads(path.read_text())
    except (json.JSONDecodeError, IOError):
        pass
    return default


def _save_json(path: Path, data: Any):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2))


def _human_bytes(b: int) -> str:
    """Convert bytes to human-readable format."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} PB"


def _record_upload(name: str, domain: str, size_bytes: int, status: str, user: str = "unknown"):
    """Record an upload in history."""
    history = _load_json(UPLOAD_HISTORY_FILE, {"records": []})
    history["records"].append({
        "id": hashlib.sha256(f"{name}{time.time()}".encode()).hexdigest()[:12],
        "name": name,
        "domain": domain,
        "timestamp": datetime.now().isoformat(),
        "size_bytes": size_bytes,
        "status": status,
        "user": user
    })
    # Keep last 500 records
    history["records"] = history["records"][-500:]
    _save_json(UPLOAD_HISTORY_FILE, history)


async def _trigger_webhooks(event: str, payload: dict):
    """Trigger webhooks for events."""
    webhooks = _load_json(WEBHOOKS_FILE, {"webhooks": []})

    for hook in webhooks.get("webhooks", []):
        if not hook.get("enabled", True):
            continue
        if event not in hook.get("events", []):
            continue

        try:
            data = {
                "event": event,
                "timestamp": datetime.now().isoformat(),
                "payload": payload,
                "source": "secubox-droplet"
            }

            headers = {"Content-Type": "application/json"}
            if hook.get("secret"):
                sig = hmac.new(
                    hook["secret"].encode(),
                    json.dumps(data).encode(),
                    hashlib.sha256
                ).hexdigest()
                headers["X-SecuBox-Signature"] = f"sha256={sig}"

            async with httpx.AsyncClient(timeout=10) as client:
                await client.post(hook["url"], json=data, headers=headers)
        except Exception:
            pass


def _cfg():
    cfg = get_config("droplet")
    return {
        "upload_dir": cfg.get("upload_dir", "/srv/droplet"),
        "default_domain": cfg.get("default_domain", "secubox.local"),
        "max_upload_mb": cfg.get("max_upload_mb", 100),
    }


# ── Status ────────────────────────────────────────────────────────

@router.get("/status")
async def status():
    """Droplet status for dashboard (public)."""
    cfg = _cfg()

    # Count sites from metablogizer and streamlit configs
    sites_count = 0
    apps_count = 0

    try:
        # Count metablogizer sites via config
        mb_cfg = get_config("metablogizer")
        if mb_cfg and "sites" in mb_cfg:
            sites_count = len(mb_cfg.get("sites", {}))
    except Exception:
        pass

    try:
        # Count streamlit apps via config
        st_cfg = get_config("streamlit")
        if st_cfg and "apps" in st_cfg:
            apps_count = len(st_cfg.get("apps", {}))
    except Exception:
        pass

    return {
        "upload_dir": cfg["upload_dir"],
        "default_domain": cfg["default_domain"],
        "sites_count": sites_count,
        "apps_count": apps_count,
    }


# ── List Droplets ─────────────────────────────────────────────────

@router.get("/list")
async def list_droplets():
    """List all droplets (sites + apps) for dashboard (public)."""
    droplets = []

    # Get metablogizer sites
    try:
        mb_cfg = get_config("metablogizer")
        sites = mb_cfg.get("sites", {}) if mb_cfg else {}
        for name, site in sites.items():
            if isinstance(site, dict):
                droplets.append({
                    "name": name,
                    "domain": site.get("domain", ""),
                    "type": "static",
                    "enabled": site.get("enabled", False),
                })
    except Exception as e:
        log.warning("list metablogizer: %s", e)

    # Get streamlit apps
    try:
        st_cfg = get_config("streamlit")
        apps = st_cfg.get("apps", {}) if st_cfg else {}
        for name, app in apps.items():
            if isinstance(app, dict):
                droplets.append({
                    "name": name,
                    "domain": app.get("domain", ""),
                    "type": "streamlit",
                    "enabled": app.get("enabled", False),
                })
    except Exception as e:
        log.warning("list streamlit: %s", e)

    return {"droplets": droplets}


# ── Upload & Publish ──────────────────────────────────────────────

class PublishRequest(BaseModel):
    name: str
    domain: Optional[str] = None


async def _run_publish(job_id: str, file_path: str, name: str, domain: str, file_size: int, user: str):
    """Background task to run dropletctl publish."""
    try:
        _jobs[job_id]["status"] = "running"

        result = subprocess.run(
            ["dropletctl", "publish", file_path, name, domain],
            capture_output=True,
            text=True,
            timeout=300,
        )

        if result.returncode == 0 and "[OK]" in result.stdout:
            # Extract vhost from output
            lines = result.stdout.strip().split("\n")
            vhost = lines[-1] if lines else domain
            _jobs[job_id] = {
                "status": "complete",
                "success": True,
                "vhost": vhost,
                "url": f"https://{vhost}/",
                "message": "Published successfully",
            }

            # Record success
            _record_upload(name, domain, file_size, "complete", user)

            # Trigger webhook
            await _trigger_webhooks("upload_complete", {
                "name": name,
                "domain": domain,
                "vhost": vhost,
                "size_bytes": file_size
            })
        else:
            _jobs[job_id] = {
                "status": "complete",
                "success": False,
                "error": result.stderr[:500] or result.stdout[:500],
            }

            # Record failure
            _record_upload(name, domain, file_size, "failed", user)

            # Trigger webhook
            await _trigger_webhooks("upload_failed", {
                "name": name,
                "domain": domain,
                "error": result.stderr[:200]
            })

    except subprocess.TimeoutExpired:
        _jobs[job_id] = {
            "status": "complete",
            "success": False,
            "error": "Publish timeout (300s)",
        }
        _record_upload(name, domain, file_size, "timeout", user)

    except Exception as e:
        _jobs[job_id] = {
            "status": "complete",
            "success": False,
            "error": str(e),
        }
        _record_upload(name, domain, file_size, "error", user)

    finally:
        # Clean up uploaded file
        try:
            os.remove(file_path)
        except Exception:
            pass


@router.post("/upload")
async def upload(
    file: UploadFile = File(...),
    name: str = "",
    domain: str = "",
    background_tasks: BackgroundTasks = None,
    user=Depends(require_jwt),
):
    """Upload and publish a file/archive."""
    cfg = _cfg()

    if not name:
        raise HTTPException(400, "Name required")

    if not domain:
        domain = cfg["default_domain"]

    # Ensure upload directory exists
    upload_dir = Path(cfg["upload_dir"])
    upload_dir.mkdir(parents=True, exist_ok=True)

    # Save uploaded file
    file_path = upload_dir / f"{uuid.uuid4().hex}_{file.filename}"
    try:
        content = await file.read()
        file_path.write_bytes(content)
    except Exception as e:
        raise HTTPException(500, f"Failed to save file: {e}")

    # Create job and start background publish
    job_id = f"{int(asyncio.get_event_loop().time())}_{uuid.uuid4().hex[:8]}"
    _jobs[job_id] = {
        "status": "started",
        "name": name,
        "domain": domain,
    }

    background_tasks.add_task(_run_publish, job_id, str(file_path), name, domain)

    log.info("Upload started: %s -> %s (job %s)", name, domain, job_id)

    return {
        "status": "started",
        "job_id": job_id,
        "name": name,
        "domain": domain,
    }


@router.get("/job/{job_id}")
async def job_status(job_id: str, user=Depends(require_jwt)):
    """Get status of a publish job."""
    if job_id not in _jobs:
        return {"status": "not_found"}
    return _jobs[job_id]


# ── Remove & Rename ───────────────────────────────────────────────

class RemoveRequest(BaseModel):
    name: str


class RenameRequest(BaseModel):
    old: str
    new: str


@router.post("/remove")
async def remove(req: RemoveRequest, user=Depends(require_jwt)):
    """Remove a droplet."""
    result = subprocess.run(
        ["dropletctl", "remove", req.name],
        capture_output=True,
        text=True,
        timeout=30,
    )

    success = result.returncode == 0
    if success:
        log.info("Removed droplet: %s", req.name)
    else:
        log.warning("Failed to remove %s: %s", req.name, result.stderr[:200])

    return {
        "success": success,
        "message": f"Removed: {req.name}" if success else result.stderr[:200],
    }


@router.post("/rename")
async def rename(req: RenameRequest, user=Depends(require_jwt)):
    """Rename a droplet."""
    if not req.old or not req.new:
        raise HTTPException(400, "Old and new names required")

    result = subprocess.run(
        ["dropletctl", "rename", req.old, req.new],
        capture_output=True,
        text=True,
        timeout=30,
    )

    success = result.returncode == 0
    if success:
        log.info("Renamed droplet: %s -> %s", req.old, req.new)

    return {
        "success": success,
        "message": f"Renamed: {req.old} -> {req.new}" if success else result.stderr[:200],
    }


# ── Health ────────────────────────────────────────────────────────

@router.get("/health")
async def health():
    return {"status": "ok", "module": "droplet", "version": "2.0.0"}


# ═══════════════════════════════════════════════════════════════════════
# STORAGE STATISTICS
# ═══════════════════════════════════════════════════════════════════════

@router.get("/storage")
async def get_storage_stats(user=Depends(require_jwt)):
    """Get storage usage statistics."""
    cached = stats_cache.get("storage_stats")
    if cached:
        return cached

    cfg = _cfg()
    upload_dir = Path(cfg["upload_dir"])

    total_bytes = 0
    file_count = 0

    if upload_dir.exists():
        try:
            result = subprocess.run(
                ["du", "-sb", str(upload_dir)],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                total_bytes = int(result.stdout.split()[0])

            # Count files
            for f in upload_dir.rglob("*"):
                if f.is_file():
                    file_count += 1
        except Exception:
            pass

    # Get droplet counts
    droplets = await list_droplets()
    sites_count = sum(1 for d in droplets.get("droplets", []) if d.get("type") == "static")
    apps_count = sum(1 for d in droplets.get("droplets", []) if d.get("type") == "streamlit")

    stats = {
        "total_bytes": total_bytes,
        "total_human": _human_bytes(total_bytes),
        "file_count": file_count,
        "sites_count": sites_count,
        "apps_count": apps_count,
        "upload_dir": str(upload_dir),
        "max_upload_mb": cfg.get("max_upload_mb", 100),
        "timestamp": datetime.now().isoformat()
    }

    stats_cache.set("storage_stats", stats)
    return stats


# ═══════════════════════════════════════════════════════════════════════
# UPLOAD HISTORY
# ═══════════════════════════════════════════════════════════════════════

@router.get("/history")
async def get_upload_history(
    limit: int = Query(default=50, le=500),
    status: Optional[str] = None,
    user=Depends(require_jwt)
):
    """Get upload history."""
    history = _load_json(UPLOAD_HISTORY_FILE, {"records": []})
    records = history.get("records", [])

    if status:
        records = [r for r in records if r.get("status") == status]

    records = sorted(records, key=lambda x: x.get("timestamp", ""), reverse=True)

    return {
        "records": records[:limit],
        "total": len(records)
    }


@router.get("/stats")
async def get_upload_stats(user=Depends(require_jwt)):
    """Get upload statistics."""
    history = _load_json(UPLOAD_HISTORY_FILE, {"records": []})
    records = history.get("records", [])

    # Calculate stats
    total_uploads = len(records)
    successful = sum(1 for r in records if r.get("status") == "complete")
    failed = sum(1 for r in records if r.get("status") == "failed")
    total_bytes = sum(r.get("size_bytes", 0) for r in records)

    # Recent activity (last 24h)
    cutoff = datetime.now() - timedelta(hours=24)
    cutoff_str = cutoff.isoformat()
    recent = [r for r in records if r.get("timestamp", "") >= cutoff_str]

    return {
        "total_uploads": total_uploads,
        "successful": successful,
        "failed": failed,
        "success_rate": round((successful / max(total_uploads, 1)) * 100, 1),
        "total_bytes_uploaded": total_bytes,
        "total_human": _human_bytes(total_bytes),
        "uploads_24h": len(recent),
        "timestamp": datetime.now().isoformat()
    }


# ═══════════════════════════════════════════════════════════════════════
# DROPLET DETAILS
# ═══════════════════════════════════════════════════════════════════════

@router.get("/droplet/{name}")
async def get_droplet_details(name: str, user=Depends(require_jwt)):
    """Get detailed information about a droplet."""
    droplets = await list_droplets()

    droplet = next((d for d in droplets.get("droplets", []) if d.get("name") == name), None)
    if not droplet:
        raise HTTPException(404, f"Droplet '{name}' not found")

    # Get size if it's a static site
    size_bytes = 0
    cfg = _cfg()
    droplet_path = Path(cfg["upload_dir"]) / name

    if droplet_path.exists():
        try:
            result = subprocess.run(
                ["du", "-sb", str(droplet_path)],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                size_bytes = int(result.stdout.split()[0])
        except Exception:
            pass

    # Get upload history for this droplet
    history = _load_json(UPLOAD_HISTORY_FILE, {"records": []})
    droplet_history = [r for r in history.get("records", []) if r.get("name") == name]

    return {
        **droplet,
        "size_bytes": size_bytes,
        "size_human": _human_bytes(size_bytes),
        "path": str(droplet_path) if droplet_path.exists() else None,
        "upload_count": len(droplet_history),
        "last_upload": droplet_history[-1]["timestamp"] if droplet_history else None
    }


# ═══════════════════════════════════════════════════════════════════════
# DROPLET HEALTH CHECK
# ═══════════════════════════════════════════════════════════════════════

@router.get("/droplet/{name}/health")
async def check_droplet_health(name: str, user=Depends(require_jwt)):
    """Check health of a specific droplet."""
    droplets = await list_droplets()

    droplet = next((d for d in droplets.get("droplets", []) if d.get("name") == name), None)
    if not droplet:
        raise HTTPException(404, f"Droplet '{name}' not found")

    domain = droplet.get("domain", "")
    health_status = "unknown"
    response_time = None
    error = None

    if domain:
        try:
            start = time.time()
            async with httpx.AsyncClient(timeout=10, verify=False) as client:
                resp = await client.get(f"https://{domain}/", follow_redirects=True)
                response_time = round((time.time() - start) * 1000, 2)

                if resp.status_code < 400:
                    health_status = "healthy"
                elif resp.status_code < 500:
                    health_status = "degraded"
                else:
                    health_status = "unhealthy"
        except Exception as e:
            health_status = "unhealthy"
            error = str(e)

    return {
        "name": name,
        "domain": domain,
        "status": health_status,
        "response_time_ms": response_time,
        "error": error,
        "checked_at": datetime.now().isoformat()
    }


# ═══════════════════════════════════════════════════════════════════════
# WEBHOOKS
# ═══════════════════════════════════════════════════════════════════════

@router.get("/webhooks")
async def list_webhooks(user=Depends(require_jwt)):
    """List configured webhooks."""
    data = _load_json(WEBHOOKS_FILE, {"webhooks": []})
    return {
        "webhooks": data.get("webhooks", []),
        "available_events": [
            "upload_complete", "upload_failed", "droplet_removed",
            "droplet_renamed", "cleanup_run"
        ]
    }


class WebhookCreate(BaseModel):
    url: str
    events: List[str] = ["upload_complete", "droplet_removed"]
    secret: Optional[str] = None
    enabled: bool = True


@router.post("/webhooks")
async def add_webhook(config: WebhookCreate, user=Depends(require_jwt)):
    """Add a webhook."""
    data = _load_json(WEBHOOKS_FILE, {"webhooks": []})

    webhook_id = hashlib.sha256(f"{config.url}{time.time()}".encode()).hexdigest()[:12]

    webhook = {
        "id": webhook_id,
        "url": config.url,
        "events": config.events,
        "secret": config.secret,
        "enabled": config.enabled,
        "created_at": datetime.now().isoformat()
    }

    data["webhooks"].append(webhook)
    _save_json(WEBHOOKS_FILE, data)

    return {"status": "success", "webhook": webhook}


@router.delete("/webhooks/{webhook_id}")
async def delete_webhook(webhook_id: str, user=Depends(require_jwt)):
    """Delete a webhook."""
    data = _load_json(WEBHOOKS_FILE, {"webhooks": []})

    original_len = len(data["webhooks"])
    data["webhooks"] = [w for w in data["webhooks"] if w.get("id") != webhook_id]

    if len(data["webhooks"]) == original_len:
        raise HTTPException(status_code=404, detail="Webhook not found")

    _save_json(WEBHOOKS_FILE, data)
    return {"status": "success"}


# ═══════════════════════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════════════════════

@router.get("/summary")
async def get_droplet_summary(user=Depends(require_jwt)):
    """Get comprehensive droplet summary."""
    cfg = _cfg()

    # Get droplets
    droplets = await list_droplets()
    droplet_list = droplets.get("droplets", [])

    # Get storage
    storage = await get_storage_stats(user)

    # Get stats
    stats = await get_upload_stats(user)

    # Count by type
    by_type = {
        "static": sum(1 for d in droplet_list if d.get("type") == "static"),
        "streamlit": sum(1 for d in droplet_list if d.get("type") == "streamlit")
    }

    # Count enabled
    enabled = sum(1 for d in droplet_list if d.get("enabled", False))

    return {
        "droplets": {
            "total": len(droplet_list),
            "enabled": enabled,
            "disabled": len(droplet_list) - enabled,
            "by_type": by_type
        },
        "storage": {
            "total_bytes": storage["total_bytes"],
            "total_human": storage["total_human"],
            "file_count": storage["file_count"]
        },
        "uploads": {
            "total": stats["total_uploads"],
            "success_rate": stats["success_rate"],
            "last_24h": stats["uploads_24h"]
        },
        "config": {
            "upload_dir": cfg["upload_dir"],
            "default_domain": cfg["default_domain"],
            "max_upload_mb": cfg.get("max_upload_mb", 100)
        },
        "timestamp": datetime.now().isoformat()
    }


# ═══════════════════════════════════════════════════════════════════════
# EXPORT
# ═══════════════════════════════════════════════════════════════════════

@router.get("/export")
async def export_droplets(user=Depends(require_jwt)):
    """Export droplet configurations."""
    droplets = await list_droplets()

    return {
        "exported_at": datetime.now().isoformat(),
        "droplets": droplets.get("droplets", [])
    }


app.include_router(router)
