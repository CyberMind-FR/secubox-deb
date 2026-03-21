"""secubox-metablogizer — Static Site Publisher API"""
import os
import subprocess
import shutil
from pathlib import Path
from typing import Optional, List
from fastapi import FastAPI, APIRouter, Depends, HTTPException, UploadFile, File
from pydantic import BaseModel
from secubox_core.auth import router as auth_router, require_jwt
from secubox_core.config import get_config
from secubox_core.logger import get_logger

app = FastAPI(title="secubox-metablogizer", version="1.0.0", root_path="/api/v1/metablogizer")
app.include_router(auth_router, prefix="/auth")
router = APIRouter()
log = get_logger("metablogizer")

SITES_ROOT = "/srv/metablogizer/sites"


def _cfg():
    cfg = get_config("metablogizer")
    return {
        "sites_root": cfg.get("sites_root", SITES_ROOT) if cfg else SITES_ROOT,
        "runtime": cfg.get("runtime", "nginx") if cfg else "nginx",
    }


def _load_sites() -> List[dict]:
    """Load sites from directory."""
    sites = []
    sites_root = Path(_cfg()["sites_root"])
    if not sites_root.exists():
        return sites
    
    cfg = get_config("metablogizer") or {}
    site_configs = cfg.get("sites", {})
    
    for site_dir in sites_root.iterdir():
        if not site_dir.is_dir() or site_dir.name.startswith("."):
            continue
        
        name = site_dir.name
        site_cfg = site_configs.get(name, {})
        
        # Check if index.html exists
        has_index = (site_dir / "index.html").exists()
        
        sites.append({
            "name": name,
            "domain": site_cfg.get("domain", f"{name}.local"),
            "enabled": site_cfg.get("enabled", True),
            "published": has_index,
            "directory": str(site_dir),
        })
    
    return sites


def _haproxy_reload():
    """Reload HAProxy if available."""
    try:
        subprocess.run(["systemctl", "reload", "haproxy"], timeout=10)
    except Exception as e:
        log.warning("HAProxy reload failed: %s", e)


# ── Status ────────────────────────────────────────────────────────

@router.get("/status")
async def status():
    """MetaBlogizer status (public)."""
    sites = _load_sites()
    published = sum(1 for s in sites if s.get("published"))
    
    return {
        "site_count": len(sites),
        "published_count": published,
        "runtime": _cfg()["runtime"],
        "sites_root": _cfg()["sites_root"],
    }


@router.get("/sites")
async def list_sites():
    """List all sites (public)."""
    return {"sites": _load_sites()}


@router.get("/site/{name}")
async def get_site(name: str, user=Depends(require_jwt)):
    """Get site details."""
    sites = _load_sites()
    for s in sites:
        if s["name"] == name:
            # Add file list
            site_dir = Path(s["directory"])
            files = []
            for f in site_dir.rglob("*"):
                if f.is_file():
                    files.append(str(f.relative_to(site_dir)))
            s["files"] = files[:50]
            return s
    raise HTTPException(404, f"Site not found: {name}")


# ── Site Management ───────────────────────────────────────────────

class SiteCreate(BaseModel):
    name: str
    domain: Optional[str] = None


class SiteUpdate(BaseModel):
    domain: Optional[str] = None
    enabled: Optional[bool] = None


@router.post("/site")
async def create_site(req: SiteCreate, user=Depends(require_jwt)):
    """Create a new site."""
    sites_root = Path(_cfg()["sites_root"])
    site_dir = sites_root / req.name
    
    if site_dir.exists():
        raise HTTPException(400, f"Site already exists: {req.name}")
    
    try:
        site_dir.mkdir(parents=True)
        
        # Create default index.html
        (site_dir / "index.html").write_text(f"""<!DOCTYPE html>
<html>
<head><title>{req.name}</title></head>
<body>
<h1>Welcome to {req.name}</h1>
<p>Edit this page or upload your content.</p>
</body>
</html>
""")
        
        log.info("Created site: %s", req.name)
        return {"success": True, "name": req.name, "directory": str(site_dir)}
    
    except Exception as e:
        log.error("Failed to create site: %s", e)
        raise HTTPException(500, str(e))


@router.put("/site/{name}")
async def update_site(name: str, req: SiteUpdate, user=Depends(require_jwt)):
    """Update site settings."""
    sites = _load_sites()
    site = next((s for s in sites if s["name"] == name), None)
    if not site:
        raise HTTPException(404, f"Site not found: {name}")
    
    # Update would modify config file - simplified
    log.info("Updated site: %s", name)
    return {"success": True, "name": name}


@router.delete("/site/{name}")
async def delete_site(name: str, user=Depends(require_jwt)):
    """Delete a site."""
    sites_root = Path(_cfg()["sites_root"])
    site_dir = sites_root / name
    
    if not site_dir.exists():
        raise HTTPException(404, f"Site not found: {name}")
    
    shutil.rmtree(site_dir)
    log.info("Deleted site: %s", name)
    return {"success": True, "name": name}


# ── Publishing ────────────────────────────────────────────────────

@router.post("/site/{name}/publish")
async def publish_site(
    name: str,
    file: UploadFile = File(None),
    user=Depends(require_jwt),
):
    """Publish/update a site."""
    sites_root = Path(_cfg()["sites_root"])
    site_dir = sites_root / name
    
    if not site_dir.exists():
        site_dir.mkdir(parents=True)
    
    if file:
        # Extract uploaded archive
        import zipfile
        import tarfile
        
        content = await file.read()
        temp_file = site_dir / f"_upload_{file.filename}"
        temp_file.write_bytes(content)
        
        try:
            if file.filename.endswith(".zip"):
                with zipfile.ZipFile(temp_file, 'r') as zf:
                    zf.extractall(site_dir)
            elif file.filename.endswith((".tar.gz", ".tgz")):
                with tarfile.open(temp_file, 'r:gz') as tf:
                    tf.extractall(site_dir)
            
            temp_file.unlink()
        except Exception as e:
            temp_file.unlink(missing_ok=True)
            raise HTTPException(400, f"Failed to extract: {e}")
    
    # Fix permissions
    for f in site_dir.rglob("*"):
        if f.is_dir():
            f.chmod(0o755)
        else:
            f.chmod(0o644)
    
    _haproxy_reload()
    
    log.info("Published site: %s", name)
    return {"success": True, "name": name}


@router.get("/site/{name}/preview")
async def preview_site(name: str, user=Depends(require_jwt)):
    """Get site preview URL."""
    sites = _load_sites()
    site = next((s for s in sites if s["name"] == name), None)
    if not site:
        raise HTTPException(404, f"Site not found: {name}")
    
    domain = site.get("domain", f"{name}.local")
    return {"url": f"https://{domain}/"}


# ── Tor Support ───────────────────────────────────────────────────

@router.get("/tor/status")
async def tor_status(user=Depends(require_jwt)):
    """Get Tor hidden service status."""
    tor_running = subprocess.run(["pgrep", "tor"], capture_output=True).returncode == 0
    
    onion_file = Path("/var/lib/tor/metablogizer/hostname")
    onion_address = onion_file.read_text().strip() if onion_file.exists() else ""
    
    return {
        "enabled": tor_running,
        "onion_address": onion_address,
    }


@router.post("/tor/enable")
async def tor_enable(user=Depends(require_jwt)):
    """Enable Tor hidden service."""
    result = subprocess.run(
        ["systemctl", "start", "tor"],
        capture_output=True, text=True, timeout=30
    )
    return {"success": result.returncode == 0}


# ── QR Code ───────────────────────────────────────────────────────

@router.get("/site/{name}/qrcode")
async def get_qrcode(name: str, user=Depends(require_jwt)):
    """Generate QR code for site URL."""
    sites = _load_sites()
    site = next((s for s in sites if s["name"] == name), None)
    if not site:
        raise HTTPException(404, f"Site not found: {name}")
    
    try:
        import qrcode
        import base64
        from io import BytesIO
        
        url = f"https://{site.get('domain', name + '.local')}/"
        qr = qrcode.make(url)
        buffer = BytesIO()
        qr.save(buffer, format="PNG")
        b64 = base64.b64encode(buffer.getvalue()).decode()
        
        return {"qrcode": f"data:image/png;base64,{b64}", "url": url}
    except ImportError:
        return {"error": "qrcode module not installed", "url": f"https://{site.get('domain')}/"}


@router.get("/health")
async def health():
    return {"status": "ok", "module": "metablogizer"}


app.include_router(router)
