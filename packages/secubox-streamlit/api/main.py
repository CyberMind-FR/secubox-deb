"""secubox-streamlit — Streamlit Platform API (Three-Fold Architecture)"""
import os
import json
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
CTL = "/usr/sbin/streamlitctl"


def _cfg():
    cfg = get_config("streamlit")
    return {
        "apps_dir": cfg.get("apps_dir", APPS_DIR) if cfg else APPS_DIR,
        "default_port": cfg.get("default_port", 8501) if cfg else 8501,
        "use_lxc": cfg.get("use_lxc", True) if cfg else True,
    }


def _run_ctl(*args, timeout: int = 30) -> dict:
    """Run streamlitctl and return parsed JSON or error."""
    try:
        result = subprocess.run(
            [CTL, *args],
            capture_output=True, text=True, timeout=timeout
        )
        if result.stdout.strip().startswith("{"):
            return json.loads(result.stdout)
        return {"output": result.stdout, "error": result.stderr, "code": result.returncode}
    except subprocess.TimeoutExpired:
        return {"error": "timeout", "success": False}
    except Exception as e:
        return {"error": str(e), "success": False}


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


def _get_apps() -> List[dict]:
    """Get list of apps from streamlitctl."""
    result = _run_ctl("app", "list")
    return result.get("apps", [])


def _get_instances() -> List[dict]:
    """Get list of instances from streamlitctl."""
    result = _run_ctl("instance", "list")
    return result.get("instances", [])


# ═══════════════════════════════════════════════════════════════════════
# THREE-FOLD ARCHITECTURE
# ═══════════════════════════════════════════════════════════════════════

# ── COMPONENTS ─────────────────────────────────────────────────────────
# What makes up the system

@router.get("/components")
async def components():
    """List system components (public)."""
    cfg = _cfg()
    lxc_installed = _lxc_exists()

    return {
        "components": [
            {
                "name": "Streamlit LXC Container",
                "type": "container",
                "description": "Alpine-based LXC container running Streamlit",
                "installed": lxc_installed,
                "config_path": "/etc/secubox/streamlit.toml"
            },
            {
                "name": "Application Directory",
                "type": "storage",
                "description": "Directory containing deployed apps",
                "path": cfg["apps_dir"],
                "exists": Path(cfg["apps_dir"]).exists()
            },
            {
                "name": "streamlitctl",
                "type": "cli",
                "description": "Control script for container and app management",
                "path": CTL,
                "installed": Path(CTL).exists()
            }
        ],
        "use_lxc": cfg["use_lxc"]
    }


# ── STATUS ─────────────────────────────────────────────────────────────
# Health and runtime state

@router.get("/status")
async def status():
    """Get platform status (public)."""
    apps = _get_apps()
    instances = _get_instances()
    cfg = _cfg()

    container_status = "not_configured"
    if cfg["use_lxc"]:
        if _lxc_exists():
            container_status = "running" if _lxc_running() else "stopped"
        else:
            container_status = "not_installed"

    running_apps = sum(1 for a in apps if a.get("running"))
    running_instances = sum(1 for i in instances if i.get("running"))

    return {
        "app_count": len(apps),
        "running_apps": running_apps,
        "instance_count": len(instances),
        "running_instances": running_instances,
        "container_status": container_status,
        "use_lxc": cfg["use_lxc"],
        "default_port": cfg["default_port"]
    }


@router.get("/health")
async def health():
    """Health check endpoint (public)."""
    checks = {
        "api": "ok",
        "streamlitctl": "ok" if Path(CTL).exists() else "missing",
        "apps_dir": "ok" if Path(_cfg()["apps_dir"]).exists() else "missing"
    }

    if _cfg()["use_lxc"]:
        if _lxc_exists():
            checks["container"] = "running" if _lxc_running() else "stopped"
        else:
            checks["container"] = "not_installed"

    overall = "healthy" if all(v in ["ok", "running"] for v in checks.values()) else "degraded"

    return {
        "status": overall,
        "module": "streamlit",
        "checks": checks
    }


# ── ACCESS ─────────────────────────────────────────────────────────────
# How to connect to services

@router.get("/access")
async def access():
    """Get access information for running apps (public)."""
    apps = _get_apps()
    instances = _get_instances()
    cfg = _cfg()

    access_points = []

    # Add running apps
    for app in apps:
        if app.get("running") and app.get("port"):
            access_points.append({
                "name": app["name"],
                "type": "app",
                "port": app["port"],
                "url": f"http://{{{{hostname}}}}:{app['port']}",
                "status": "running"
            })

    # Add running instances
    for inst in instances:
        if inst.get("running") and inst.get("port"):
            access_points.append({
                "name": inst.get("id", inst.get("name", "unknown")),
                "type": "instance",
                "app": inst.get("app"),
                "port": inst["port"],
                "url": f"http://{{{{hostname}}}}:{inst['port']}",
                "domain": inst.get("domain"),
                "status": "running"
            })

    return {
        "access": access_points,
        "default_port": cfg["default_port"]
    }


# ═══════════════════════════════════════════════════════════════════════
# APPS
# ═══════════════════════════════════════════════════════════════════════

@router.get("/apps")
async def list_apps():
    """List all apps (public)."""
    return {"apps": _get_apps()}


@router.get("/app/{name}")
async def get_app(name: str, user=Depends(require_jwt)):
    """Get app details."""
    apps = _get_apps()
    for a in apps:
        if a.get("name") == name:
            # Add extra details
            app_dir = Path(_cfg()["apps_dir"]) / name
            a["path"] = str(app_dir)
            a["has_requirements"] = (app_dir / "requirements.txt").exists()
            return a
    raise HTTPException(404, f"App not found: {name}")


@router.post("/deploy")
async def deploy(
    file: UploadFile = File(...),
    name: str = "",
    port: int = 0,
    user=Depends(require_jwt),
):
    """Deploy a Streamlit app from ZIP."""
    if not name:
        name = file.filename.replace(".zip", "").replace(" ", "_").lower()

    # Save uploaded file
    tmp_path = f"/tmp/streamlit_upload_{name}.zip"
    content = await file.read()
    Path(tmp_path).write_bytes(content)

    # Deploy via streamlitctl
    result = _run_ctl("app", "deploy", tmp_path, name, timeout=120)

    # Cleanup
    Path(tmp_path).unlink(missing_ok=True)

    if result.get("success"):
        log.info("Deployed app: %s", name)
        return result
    else:
        log.error("Deploy failed: %s", result.get("error", "unknown"))
        raise HTTPException(500, result.get("error", "Deploy failed"))


@router.post("/app/{name}/start")
async def start_app(name: str, port: int = 0, user=Depends(require_jwt)):
    """Start an app."""
    cfg = _cfg()
    port = port or cfg["default_port"]

    result = _run_ctl("app", "start", name, str(port))

    if "error" not in result or result.get("code", 0) == 0:
        log.info("Started app: %s on port %d", name, port)
        return {"success": True, "name": name, "port": port}
    else:
        raise HTTPException(500, result.get("error", "Failed to start"))


@router.post("/app/{name}/stop")
async def stop_app(name: str, user=Depends(require_jwt)):
    """Stop an app."""
    result = _run_ctl("app", "stop", name)
    log.info("Stopped app: %s", name)
    return {"success": True, "name": name}


@router.delete("/app/{name}")
async def delete_app(name: str, user=Depends(require_jwt)):
    """Delete an app."""
    result = _run_ctl("app", "remove", name)
    log.info("Removed app: %s", name)
    return {"success": True, "name": name}


@router.get("/app/{name}/logs")
async def get_logs(name: str, lines: int = 100, user=Depends(require_jwt)):
    """Get app logs."""
    result = _run_ctl("app", "logs", name, str(lines))
    return {"logs": result.get("output", "").splitlines()}


# ═══════════════════════════════════════════════════════════════════════
# INSTANCES
# ═══════════════════════════════════════════════════════════════════════

@router.get("/instances")
async def list_instances(user=Depends(require_jwt)):
    """List all instances."""
    return {"instances": _get_instances()}


@router.post("/instance/{id}/start")
async def start_instance(id: str, user=Depends(require_jwt)):
    """Start an instance."""
    result = _run_ctl("instance", "start", id)
    return {"success": True, "id": id}


@router.post("/instance/{id}/stop")
async def stop_instance(id: str, user=Depends(require_jwt)):
    """Stop an instance."""
    result = _run_ctl("instance", "stop", id)
    return {"success": True, "id": id}


# ═══════════════════════════════════════════════════════════════════════
# CONTAINER CONTROL
# ═══════════════════════════════════════════════════════════════════════

@router.get("/container/status")
async def container_status(user=Depends(require_jwt)):
    """Get LXC container status."""
    if not _cfg()["use_lxc"]:
        return {"enabled": False}

    return {
        "enabled": True,
        "exists": _lxc_exists(),
        "running": _lxc_running()
    }


@router.post("/container/install")
async def container_install(background_tasks: BackgroundTasks, user=Depends(require_jwt)):
    """Install LXC container (background)."""
    def do_install():
        subprocess.run([CTL, "install"], timeout=600)

    background_tasks.add_task(do_install)
    return {"success": True, "message": "Installation started in background"}


@router.post("/container/start")
async def container_start(user=Depends(require_jwt)):
    """Start LXC container."""
    result = _run_ctl("start", timeout=60)
    return {"success": "error" not in result}


@router.post("/container/stop")
async def container_stop(user=Depends(require_jwt)):
    """Stop LXC container."""
    result = _run_ctl("stop", timeout=60)
    return {"success": "error" not in result}


# ═══════════════════════════════════════════════════════════════════════
# MIGRATION
# ═══════════════════════════════════════════════════════════════════════

class MigrateRequest(BaseModel):
    source: str = "192.168.255.1"


@router.post("/migrate")
async def migrate(req: MigrateRequest, background_tasks: BackgroundTasks, user=Depends(require_jwt)):
    """Migrate apps from OpenWrt SecuBox."""
    def do_migrate():
        subprocess.run([CTL, "migrate", req.source], timeout=600)

    background_tasks.add_task(do_migrate)
    log.info("Migration started from %s", req.source)
    return {"success": True, "message": f"Migration from {req.source} started"}


# ═══════════════════════════════════════════════════════════════════════
# GITEA INTEGRATION
# ═══════════════════════════════════════════════════════════════════════

@router.post("/gitea/push/{name}")
async def gitea_push(name: str, user=Depends(require_jwt)):
    """Push app to Gitea repository."""
    result = _run_ctl("gitea", "push", name, timeout=60)
    return {"success": "error" not in result, "name": name}


class GiteaCloneRequest(BaseModel):
    repo: str


@router.post("/gitea/clone/{name}")
async def gitea_clone(name: str, req: GiteaCloneRequest, user=Depends(require_jwt)):
    """Clone app from Gitea repository."""
    result = _run_ctl("gitea", "clone", name, req.repo, timeout=120)
    return {"success": "error" not in result, "name": name}


app.include_router(router)
