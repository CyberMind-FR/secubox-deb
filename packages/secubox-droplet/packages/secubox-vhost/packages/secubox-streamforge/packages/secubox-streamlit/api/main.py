"""secubox-streamlit — Streamlit Platform API"""
import os
import subprocess
import shutil
import zipfile
from pathlib import Path
from typing import Optional, List
from fastapi import FastAPI, APIRouter, Depends, HTTPException, UploadFile, File, BackgroundTasks
from pydantic import BaseModel
from secubox_core.auth import router as auth_router, require_jwt
from secubox_core.config import get_config
from secubox_core.logger import get_logger

app = FastAPI(title="secubox-streamlit", version="1.0.0", root_path="/api/v1/streamlit")
app.include_router(auth_router, prefix="/auth")
router = APIRouter()
log = get_logger("streamlit")

APPS_DIR = "/srv/streamlit/apps"
LXC_NAME = "streamlit"


def _cfg():
    cfg = get_config("streamlit")
    return {
        "apps_dir": cfg.get("apps_dir", APPS_DIR) if cfg else APPS_DIR,
        "default_port": cfg.get("default_port", 8501) if cfg else 8501,
        "use_lxc": cfg.get("use_lxc", False) if cfg else False,
    }


def _lxc_running() -> bool:
    """Check if LXC container is running."""
    result = subprocess.run(
        ["lxc-info", "-n", LXC_NAME, "-s"],
        capture_output=True, text=True
    )
    return "RUNNING" in result.stdout


def _lxc_exists() -> bool:
    """Check if LXC container exists."""
    return Path(f"/var/lib/lxc/{LXC_NAME}").exists()


def _get_app_port(name: str) -> int:
    """Get port for an app."""
    cfg = get_config("streamlit") or {}
    apps = cfg.get("apps", {})
    return apps.get(name, {}).get("port", 0)


def _is_app_running(name: str) -> bool:
    """Check if app process is running."""
    port = _get_app_port(name)
    if not port:
        return False
    result = subprocess.run(
        ["ss", "-tln", f"sport = :{port}"],
        capture_output=True, text=True
    )
    return str(port) in result.stdout


def _load_apps() -> List[dict]:
    """Load apps from directory."""
    apps = []
    apps_dir = Path(_cfg()["apps_dir"])
    if not apps_dir.exists():
        return apps
    
    cfg = get_config("streamlit") or {}
    app_configs = cfg.get("apps", {})
    
    for app_dir in apps_dir.iterdir():
        if not app_dir.is_dir() or app_dir.name.startswith("."):
            continue
        
        name = app_dir.name
        app_cfg = app_configs.get(name, {})
        port = app_cfg.get("port", 0)
        
        apps.append({
            "name": name,
            "enabled": app_cfg.get("enabled", False),
            "port": port,
            "domain": app_cfg.get("domain", ""),
            "status": "running" if _is_app_running(name) else "stopped",
        })
    
    return apps


# ── Status ────────────────────────────────────────────────────────

@router.get("/status")
async def status():
    """Streamlit platform status (public)."""
    apps = _load_apps()
    cfg = _cfg()
    
    container_status = "not_configured"
    if cfg["use_lxc"]:
        if _lxc_exists():
            container_status = "running" if _lxc_running() else "stopped"
        else:
            container_status = "not_installed"
    
    return {
        "app_count": len(apps),
        "running_count": sum(1 for a in apps if a["status"] == "running"),
        "container_status": container_status,
        "use_lxc": cfg["use_lxc"],
        "default_port": cfg["default_port"],
    }


@router.get("/apps")
async def list_apps():
    """List all apps (public)."""
    return {"apps": _load_apps()}


@router.get("/app/{name}")
async def get_app(name: str, user=Depends(require_jwt)):
    """Get app details."""
    apps = _load_apps()
    for a in apps:
        if a["name"] == name:
            return a
    raise HTTPException(404, f"App not found: {name}")


# ── Deploy ────────────────────────────────────────────────────────

@router.post("/deploy")
async def deploy(
    file: UploadFile = File(...),
    name: str = "",
    port: int = 0,
    user=Depends(require_jwt),
):
    """Deploy a Streamlit app from ZIP."""
    if not name:
        name = file.filename.replace(".zip", "").replace(" ", "_")
    
    apps_dir = Path(_cfg()["apps_dir"])
    app_dir = apps_dir / name
    
    if app_dir.exists():
        shutil.rmtree(app_dir)
    
    app_dir.mkdir(parents=True)
    
    # Save and extract ZIP
    zip_path = app_dir / "upload.zip"
    content = await file.read()
    zip_path.write_bytes(content)
    
    try:
        with zipfile.ZipFile(zip_path, 'r') as zf:
            # Extract flattening single root directory
            names = zf.namelist()
            root_dirs = set(n.split('/')[0] for n in names if '/' in n)
            
            if len(root_dirs) == 1:
                # Single root dir - extract and flatten
                root = list(root_dirs)[0]
                for member in zf.namelist():
                    if member.startswith(root + '/'):
                        target = app_dir / member[len(root)+1:]
                        if member.endswith('/'):
                            target.mkdir(parents=True, exist_ok=True)
                        else:
                            target.parent.mkdir(parents=True, exist_ok=True)
                            target.write_bytes(zf.read(member))
            else:
                zf.extractall(app_dir)
        
        zip_path.unlink()
        
        # Install requirements if present
        req_file = app_dir / "requirements.txt"
        if req_file.exists():
            subprocess.run(
                ["pip3", "install", "-r", str(req_file)],
                capture_output=True, timeout=120
            )
        
        log.info("Deployed app: %s", name)
        return {"success": True, "name": name, "directory": str(app_dir)}
    
    except Exception as e:
        log.error("Deploy failed: %s", e)
        raise HTTPException(500, str(e))


# ── App Control ───────────────────────────────────────────────────

@router.post("/app/{name}/start")
async def start_app(name: str, user=Depends(require_jwt)):
    """Start an app."""
    apps_dir = Path(_cfg()["apps_dir"])
    app_dir = apps_dir / name
    
    if not app_dir.exists():
        raise HTTPException(404, f"App not found: {name}")
    
    port = _get_app_port(name) or _cfg()["default_port"]
    
    # Find entrypoint
    entrypoint = None
    for candidate in ["app.py", "main.py", "streamlit_app.py"]:
        if (app_dir / candidate).exists():
            entrypoint = candidate
            break
    
    if not entrypoint:
        raise HTTPException(400, "No entrypoint found (app.py, main.py)")
    
    # Start app
    subprocess.Popen(
        ["streamlit", "run", entrypoint,
         "--server.port", str(port),
         "--server.headless", "true"],
        cwd=str(app_dir),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    
    log.info("Started app: %s on port %d", name, port)
    return {"success": True, "name": name, "port": port}


@router.post("/app/{name}/stop")
async def stop_app(name: str, user=Depends(require_jwt)):
    """Stop an app."""
    subprocess.run(["pkill", "-f", f"streamlit.*{name}"], timeout=5)
    log.info("Stopped app: %s", name)
    return {"success": True, "name": name}


@router.get("/app/{name}/logs")
async def get_logs(name: str, lines: int = 100, user=Depends(require_jwt)):
    """Get app logs."""
    result = subprocess.run(
        ["journalctl", "-u", f"streamlit-app@{name}", "-n", str(lines), "--no-pager"],
        capture_output=True, text=True, timeout=10
    )
    return {"logs": result.stdout.splitlines()}


# ── Container Control ─────────────────────────────────────────────

@router.get("/container/status")
async def container_status(user=Depends(require_jwt)):
    """Get LXC container status."""
    if not _cfg()["use_lxc"]:
        return {"enabled": False}
    
    return {
        "enabled": True,
        "exists": _lxc_exists(),
        "running": _lxc_running(),
    }


@router.post("/container/start")
async def container_start(user=Depends(require_jwt)):
    """Start LXC container."""
    result = subprocess.run(
        ["lxc-start", "-n", LXC_NAME],
        capture_output=True, text=True, timeout=30
    )
    return {"success": result.returncode == 0}


@router.post("/container/stop")
async def container_stop(user=Depends(require_jwt)):
    """Stop LXC container."""
    result = subprocess.run(
        ["lxc-stop", "-n", LXC_NAME],
        capture_output=True, text=True, timeout=30
    )
    return {"success": result.returncode == 0}


@router.get("/health")
async def health():
    return {"status": "ok", "module": "streamlit"}


app.include_router(router)
