"""secubox-streamforge — Streamlit App Builder API"""
import os
import subprocess
import shutil
from pathlib import Path
from typing import Optional, List
from fastapi import FastAPI, APIRouter, Depends, HTTPException
from pydantic import BaseModel
from secubox_core.auth import router as auth_router, require_jwt
from secubox_core.config import get_config
from secubox_core.logger import get_logger

app = FastAPI(title="secubox-streamforge", version="1.0.0", root_path="/api/v1/streamforge")
app.include_router(auth_router, prefix="/auth")
router = APIRouter()
log = get_logger("streamforge")

APPS_DIR = "/srv/streamlit/apps"
TEMPLATES_DIR = "/usr/share/secubox/streamforge/templates"


def _cfg():
    cfg = get_config("streamforge")
    return {
        "apps_dir": cfg.get("apps_dir", APPS_DIR) if cfg else APPS_DIR,
        "templates_dir": cfg.get("templates_dir", TEMPLATES_DIR) if cfg else TEMPLATES_DIR,
    }


def _get_app_status(name: str, port: int) -> str:
    """Check if app is running by port."""
    if not port:
        return "stopped"
    result = subprocess.run(
        ["ss", "-tln", f"sport = :{port}"],
        capture_output=True, text=True
    )
    return "running" if str(port) in result.stdout else "stopped"


def _load_apps() -> List[dict]:
    """Load apps from apps directory."""
    apps = []
    apps_dir = Path(_cfg()["apps_dir"])
    if not apps_dir.exists():
        return apps

    cfg = get_config("streamforge") or {}
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
            "entrypoint": app_cfg.get("entrypoint", "app.py"),
            "memory": app_cfg.get("memory", "512M"),
            "status": _get_app_status(name, port),
            "directory": str(app_dir),
        })
    
    return apps


# ── Status & List ─────────────────────────────────────────────────

@router.get("/status")
async def status():
    """StreamForge status (public)."""
    apps = _load_apps()
    running = sum(1 for a in apps if a["status"] == "running")
    return {
        "app_count": len(apps),
        "running_count": running,
        "apps_dir": _cfg()["apps_dir"],
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
            # Add file list
            app_dir = Path(a["directory"])
            files = []
            src_dir = app_dir / "src"
            if src_dir.exists():
                files = [f.name for f in src_dir.iterdir() if f.is_file()][:20]
            a["files"] = files
            return a
    raise HTTPException(404, f"App not found: {name}")


@router.get("/templates")
async def list_templates():
    """List available templates (public)."""
    templates = []
    tpl_dir = Path(_cfg()["templates_dir"])
    if tpl_dir.exists():
        for tpl in tpl_dir.iterdir():
            if tpl.is_dir():
                readme = tpl / "README.md"
                desc = readme.read_text()[:200] if readme.exists() else ""
                templates.append({"name": tpl.name, "description": desc})
    return {"templates": templates}


# ── App Management ────────────────────────────────────────────────

class AppCreate(BaseModel):
    name: str
    template: Optional[str] = "basic"
    port: Optional[int] = None
    domain: Optional[str] = None


class AppControl(BaseModel):
    name: str


@router.post("/app")
async def create_app(req: AppCreate, user=Depends(require_jwt)):
    """Create a new app."""
    apps_dir = Path(_cfg()["apps_dir"])
    app_dir = apps_dir / req.name
    
    if app_dir.exists():
        raise HTTPException(400, f"App already exists: {req.name}")
    
    try:
        app_dir.mkdir(parents=True)
        src_dir = app_dir / "src"
        src_dir.mkdir()
        
        # Copy template or create basic app.py
        tpl_dir = Path(_cfg()["templates_dir"]) / (req.template or "basic")
        if tpl_dir.exists():
            shutil.copytree(tpl_dir, src_dir, dirs_exist_ok=True)
        else:
            # Create basic app
            (src_dir / "app.py").write_text('''import streamlit as st

st.set_page_config(page_title="My App", layout="wide")
st.title("Welcome to Streamlit!")
st.write("Edit src/app.py to customize this app.")
''')
            (src_dir / "requirements.txt").write_text("streamlit\n")
        
        log.info("Created app: %s", req.name)
        return {"success": True, "name": req.name, "directory": str(app_dir)}
    
    except Exception as e:
        log.error("Failed to create app %s: %s", req.name, e)
        raise HTTPException(500, str(e))


@router.post("/app/{name}/start")
async def start_app(name: str, user=Depends(require_jwt)):
    """Start an app."""
    apps = _load_apps()
    app = next((a for a in apps if a["name"] == name), None)
    if not app:
        raise HTTPException(404, f"App not found: {name}")
    
    port = app.get("port") or 8501
    app_dir = Path(app["directory"]) / "src"
    entrypoint = app.get("entrypoint", "app.py")
    
    # Start streamlit in background
    result = subprocess.run(
        ["systemctl", "start", f"streamlit-app@{name}"],
        capture_output=True, text=True, timeout=10
    )
    
    if result.returncode != 0:
        # Fallback: direct start
        subprocess.Popen(
            ["streamlit", "run", str(app_dir / entrypoint), "--server.port", str(port)],
            cwd=str(app_dir),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    
    log.info("Started app: %s on port %d", name, port)
    return {"success": True, "name": name, "port": port}


@router.post("/app/{name}/stop")
async def stop_app(name: str, user=Depends(require_jwt)):
    """Stop an app."""
    result = subprocess.run(
        ["systemctl", "stop", f"streamlit-app@{name}"],
        capture_output=True, text=True, timeout=10
    )
    
    if result.returncode != 0:
        # Fallback: pkill
        subprocess.run(["pkill", "-f", f"streamlit.*{name}"], timeout=5)
    
    log.info("Stopped app: %s", name)
    return {"success": True, "name": name}


@router.delete("/app/{name}")
async def delete_app(name: str, user=Depends(require_jwt)):
    """Delete an app."""
    apps_dir = Path(_cfg()["apps_dir"])
    app_dir = apps_dir / name
    
    if not app_dir.exists():
        raise HTTPException(404, f"App not found: {name}")
    
    # Stop first
    subprocess.run(["systemctl", "stop", f"streamlit-app@{name}"], timeout=5)
    
    shutil.rmtree(app_dir)
    log.info("Deleted app: %s", name)
    return {"success": True, "name": name}


# ── File Operations ───────────────────────────────────────────────

@router.get("/app/{name}/file/{path:path}")
async def read_file(name: str, path: str, user=Depends(require_jwt)):
    """Read a file from app."""
    apps_dir = Path(_cfg()["apps_dir"])
    file_path = apps_dir / name / "src" / path
    
    if not file_path.exists():
        raise HTTPException(404, "File not found")
    if not file_path.is_file():
        raise HTTPException(400, "Not a file")
    
    # Security: ensure path is within app dir
    try:
        file_path.resolve().relative_to((apps_dir / name).resolve())
    except ValueError:
        raise HTTPException(403, "Access denied")
    
    return {"content": file_path.read_text()[:50000], "path": path}


class FileWrite(BaseModel):
    content: str


@router.put("/app/{name}/file/{path:path}")
async def write_file(name: str, path: str, req: FileWrite, user=Depends(require_jwt)):
    """Write a file to app."""
    apps_dir = Path(_cfg()["apps_dir"])
    file_path = apps_dir / name / "src" / path
    
    # Security check
    try:
        file_path.resolve().relative_to((apps_dir / name).resolve())
    except ValueError:
        raise HTTPException(403, "Access denied")
    
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text(req.content)
    
    log.info("Wrote file: %s/%s", name, path)
    return {"success": True, "path": path}


@router.get("/health")
async def health():
    return {"status": "ok", "module": "streamforge"}


app.include_router(router)
