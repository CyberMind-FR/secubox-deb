"""secubox-droplet — File Publisher API"""
import os
import subprocess
import uuid
import asyncio
from pathlib import Path
from typing import Optional
from fastapi import FastAPI, APIRouter, Depends, HTTPException, UploadFile, File, BackgroundTasks
from pydantic import BaseModel
from secubox_core.auth import router as auth_router, require_jwt
from secubox_core.config import get_config
from secubox_core.logger import get_logger

app = FastAPI(title="secubox-droplet", version="1.0.0", root_path="/api/v1/droplet")
app.include_router(auth_router, prefix="/auth")
router = APIRouter()
log = get_logger("droplet")

# Job storage (in-memory, could be Redis for production)
_jobs: dict = {}

def _cfg():
    cfg = get_config("droplet")
    return {
        "upload_dir": cfg.get("upload_dir", "/tmp/droplet-upload"),
        "default_domain": cfg.get("default_domain", "secubox.local"),
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


async def _run_publish(job_id: str, file_path: str, name: str, domain: str):
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
        else:
            _jobs[job_id] = {
                "status": "complete",
                "success": False,
                "error": result.stderr[:500] or result.stdout[:500],
            }
    except subprocess.TimeoutExpired:
        _jobs[job_id] = {
            "status": "complete",
            "success": False,
            "error": "Publish timeout (300s)",
        }
    except Exception as e:
        _jobs[job_id] = {
            "status": "complete",
            "success": False,
            "error": str(e),
        }
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
    return {"status": "ok", "module": "droplet"}


app.include_router(router)
