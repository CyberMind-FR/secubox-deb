"""secubox-streamlit — Streamlit Platform API (Three-Fold Architecture)"""
import os
import json
import subprocess
import shutil
import zipfile
import asyncio
import threading
import time
from pathlib import Path
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, APIRouter, Depends, HTTPException, UploadFile, File, BackgroundTasks
from pydantic import BaseModel
from secubox_core.auth import router as auth_router, require_jwt
from secubox_core.config import get_config
from secubox_core.logger import get_logger

app = FastAPI(title="secubox-streamlit", version="1.0.0", root_path="/api/v1/streamlit")

# ════════════════════════��════════════════════════���════════════════
# DOUBLE PRE-CACHE BUFFERING (instant + details)
# ═══════════════════════════════��═════════════════════���════════════

class DoubleBufferCache:
    """Thread-safe double-buffer cache for instant and detailed stats.

    - instant: Quick stats for dashboard cards, refreshed every 5s
    - details: Full detailed data, refreshed every 30s
    """

    def __init__(self):
        self._instant: Dict[str, Any] = {}
        self._details: Dict[str, Any] = {}
        self._instant_ts: float = 0
        self._details_ts: float = 0
        self._lock = threading.Lock()
        self.INSTANT_TTL = 5  # seconds
        self.DETAILS_TTL = 30  # seconds

    def get_instant(self) -> Dict[str, Any]:
        """Get instant cache (quick stats)."""
        with self._lock:
            return self._instant.copy()

    def get_details(self) -> Dict[str, Any]:
        """Get details cache (full data)."""
        with self._lock:
            return self._details.copy()

    def set_instant(self, data: Dict[str, Any]):
        """Update instant cache."""
        with self._lock:
            self._instant = data
            self._instant_ts = time.time()

    def set_details(self, data: Dict[str, Any]):
        """Update details cache."""
        with self._lock:
            self._details = data
            self._details_ts = time.time()

    def instant_stale(self) -> bool:
        """Check if instant cache is stale."""
        return time.time() - self._instant_ts > self.INSTANT_TTL

    def details_stale(self) -> bool:
        """Check if details cache is stale."""
        return time.time() - self._details_ts > self.DETAILS_TTL

    def age(self) -> Dict[str, float]:
        """Get cache ages."""
        now = time.time()
        return {
            "instant_age": round(now - self._instant_ts, 1) if self._instant_ts else None,
            "details_age": round(now - self._details_ts, 1) if self._details_ts else None,
        }


_cache = DoubleBufferCache()
_cache_task: Optional[asyncio.Task] = None

# ══════════════════════════════════════════════════════════════════
# Health Check Endpoint (public, no auth)
# ══════════════════════════════════════════════════════════════════

@app.get("/health")
async def health_check():
    """Public health check endpoint for sidebar status."""
    return {"status": "ok", "module": "deb"}

app.include_router(auth_router, prefix="/auth")
router = APIRouter()
log = get_logger("streamlit")

APPS_DIR = "/srv/streamlit/apps"
LXC_NAME = "streamlit"
CTL = "/usr/sbin/streamlitctl"


def _cfg():
    cfg = get_config("streamlit")
    power_cfg = cfg.get("power", {}) if cfg else {}
    return {
        "apps_dir": cfg.get("apps_dir", APPS_DIR) if cfg else APPS_DIR,
        "default_port": cfg.get("default_port", 8501) if cfg else 8501,
        "use_lxc": cfg.get("use_lxc", True) if cfg else True,
        "auto_pause": power_cfg.get("auto_pause", False),
        "auto_pause_minutes": power_cfg.get("auto_pause_minutes", 30),
        "presence_events": power_cfg.get("presence_events", True),
        "metoblizer_log": power_cfg.get("metoblizer_log", False),
        "metoblizer_endpoint": power_cfg.get("metoblizer_endpoint", "http://localhost:9300/api/v1/metoblizer/ingest"),
    }


def _run_ctl(*args, timeout: int = 30) -> dict:
    """Run streamlitctl and return parsed JSON or error.

    Uses sudo -n for non-interactive sudo (requires sudoers config).
    """
    try:
        result = subprocess.run(
            ["sudo", "-n", CTL, *args],
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
    """Check if LXC container is running.

    Uses sudo -n for non-interactive sudo (requires sudoers config).
    """
    result = subprocess.run(
        ["sudo", "-n", "lxc-info", "-n", LXC_NAME, "-s"],
        capture_output=True, text=True
    )
    return "RUNNING" in result.stdout


def _lxc_exists() -> bool:
    """Check if LXC container exists."""
    return Path(f"/var/lib/lxc/{LXC_NAME}").exists()


APPS_PATH = "/srv/streamlit/apps"


def _read_deploy_metadata(app_name: str) -> dict:
    """Read .deploy.json for an app; return empty dict if absent or invalid."""
    path = Path(APPS_PATH) / app_name / ".deploy.json"
    try:
        with path.open() as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, PermissionError, OSError):
        return {}


def _git_describe_tag(app_name: str) -> str | None:
    """Fallback: read the current tag via `git describe --tags --exact-match`."""
    app_dir = Path(APPS_PATH) / app_name
    if not (app_dir / ".git").exists():
        return None
    try:
        out = subprocess.run(
            ["git", "-C", str(app_dir), "describe", "--tags", "--exact-match"],
            capture_output=True, text=True, timeout=5,
        )
        if out.returncode == 0:
            return out.stdout.strip() or None
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return None


def _get_apps() -> List[dict]:
    """Get list of apps from streamlitctl, enriched with current_tag + deployed_at."""
    result = _run_ctl("app", "list")
    apps = result.get("apps", [])
    for app in apps:
        name = app.get("name")
        if not name:
            continue
        meta = _read_deploy_metadata(name)
        app["current_tag"] = meta.get("tag") or _git_describe_tag(name)
        app["deployed_at"] = meta.get("deployed_at")
    return apps


def _get_instances() -> List[dict]:
    """Get list of instances from streamlitctl."""
    result = _run_ctl("instance", "list")
    return result.get("instances", [])


def _refresh_instant_cache():
    """Refresh instant cache with quick stats."""
    cfg = _cfg()
    container_status = "not_configured"
    if cfg["use_lxc"]:
        if _lxc_exists():
            container_status = "running" if _lxc_running() else "stopped"
        else:
            container_status = "not_installed"

    _cache.set_instant({
        "container_status": container_status,
        "lxc_exists": _lxc_exists(),
        "lxc_running": _lxc_running() if cfg["use_lxc"] else False,
        "use_lxc": cfg["use_lxc"],
        "default_port": cfg["default_port"],
        "ts": time.time(),
    })


def _refresh_details_cache():
    """Refresh details cache with full data."""
    apps = _get_apps()
    instances = _get_instances()
    cfg = _cfg()

    container_status = "not_configured"
    if cfg["use_lxc"]:
        if _lxc_exists():
            container_status = "running" if _lxc_running() else "stopped"
        else:
            container_status = "not_installed"

    _cache.set_details({
        "apps": apps,
        "instances": instances,
        "app_count": len(apps),
        "running_apps": sum(1 for a in apps if a.get("running")),
        "instance_count": len(instances),
        "running_instances": sum(1 for i in instances if i.get("running")),
        "container_status": container_status,
        "use_lxc": cfg["use_lxc"],
        "default_port": cfg["default_port"],
        "ts": time.time(),
    })


async def _cache_refresh_loop():
    """Background task to refresh caches."""
    while True:
        try:
            if _cache.instant_stale():
                _refresh_instant_cache()
            if _cache.details_stale():
                _refresh_details_cache()
        except Exception as e:
            log.warning("cache refresh error: %s", e)
        await asyncio.sleep(2)


@app.on_event("startup")
async def startup_cache():
    """Start cache refresh loop on startup."""
    global _cache_task
    _refresh_instant_cache()
    _refresh_details_cache()
    _cache_task = asyncio.create_task(_cache_refresh_loop())


@app.on_event("shutdown")
async def shutdown_cache():
    """Stop cache refresh loop on shutdown."""
    global _cache_task
    if _cache_task:
        _cache_task.cancel()


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

@router.get("/instant")
async def instant():
    """Get instant stats from pre-cache (public, fast)."""
    data = _cache.get_instant()
    data["cache_age"] = _cache.age()
    return data


@router.get("/details")
async def details():
    """Get detailed stats from pre-cache (public)."""
    data = _cache.get_details()
    data["cache_age"] = _cache.age()
    return data


@router.get("/status")
async def status():
    """Get platform status from cache (public)."""
    # Use cached details for fast response
    cached = _cache.get_details()
    if cached and cached.get("app_count") is not None:
        return {
            "app_count": cached.get("app_count", 0),
            "running_apps": cached.get("running_apps", 0),
            "instance_count": cached.get("instance_count", 0),
            "running_instances": cached.get("running_instances", 0),
            "container_status": cached.get("container_status", "unknown"),
            "use_lxc": cached.get("use_lxc", True),
            "default_port": cached.get("default_port", 8501),
            "cached": True,
            "cache_age": _cache.age(),
        }

    # Fallback to direct fetch if cache not ready
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
        "default_port": cfg["default_port"],
        "cached": False,
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


APPS_AUDIT_CACHE = Path("/var/cache/secubox/streamlit/audit.json")


@router.get("/apps/audit")
async def apps_audit():
    """Inventaire croisé disque / déclarations / processus (public, lecture seule).

    Servi depuis le cache écrit par streamlit-audit.timer (root, disque +
    TOML + lxc-attach ps, ~11s en direct / ~31s à travers l'agrégateur). Le
    chemin de requête est une lecture de fichier : ne JAMAIS retomber sur
    `streamlitctl app audit` en direct ici, ce serait réintroduire le délai
    que ce cache existe pour supprimer (#956).
    """
    try:
        raw = json.loads(APPS_AUDIT_CACHE.read_text())
        if not isinstance(raw, dict):
            raise ValueError("cache content is not a JSON object")
    except FileNotFoundError:
        return {"available": False, "reason": "cache not written yet",
                "apps": [], "summary": {}}
    except (OSError, ValueError) as exc:
        log.warning("apps audit cache unreadable: %s", exc)
        return {"available": False, "reason": "cache unreadable",
                "apps": [], "summary": {}}

    age = None
    try:
        age = int(time.time() - APPS_AUDIT_CACHE.stat().st_mtime)
    except OSError:
        pass

    return {
        "available": True,
        "apps": raw.get("apps", []),
        "summary": raw.get("summary", {}),
        "cache_age_seconds": age,
    }


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
        if not file.filename:
            raise HTTPException(400, "Filename required")
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


# ── WAKE ───────────────────────────────────────────────────────────────
# Lazy restart an idle-stopped streamlit app (ref #331)

class WakeResult(BaseModel):
    name: str
    status: str  # "running" | "started"
    duration_ms: int


@router.post("/apps/{name}/wake", response_model=WakeResult)
def wake_app(name: str, user=Depends(require_jwt)) -> WakeResult:
    """Wake an idle-stopped streamlit app.

    Blocks until the port comes up or 30 s elapse. Idempotent — returns
    immediately with status="running" if the app is already up.

    Status codes:
      - 200: app is up (status="running" or "started")
      - 404: app does not exist (streamlitctl found no resolvable entrypoint
        for it — directory or flat script, ref #959)
      - 502: streamlitctl binary missing
      - 504: wake failed or timed out

    Existence is delegated entirely to `streamlitctl app wake` rather than
    re-checked here: this endpoint used to require `APPS_PATH/{name}` to be
    a directory, which 404'd every flat-script app (most of the fleet) even
    though streamlitctl itself already knew how to resolve them. Keeping a
    second, narrower existence check here is exactly what let the two
    diverge (#959) — the ctl is the single source of truth.
    """
    if not Path(CTL).exists():
        raise HTTPException(502, "streamlitctl missing")

    start = time.monotonic()
    try:
        result = subprocess.run(
            ["sudo", "-n", CTL, "app", "wake", name, "30"],
            capture_output=True, timeout=35, check=False,
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(504, "wake exceeded 35s wall-clock")

    duration_ms = int((time.monotonic() - start) * 1000)
    if result.returncode == 0:
        status = "running" if b"already running" in result.stderr else "started"
        log.info("wake: %s status=%s duration_ms=%d", name, status, duration_ms)
        return WakeResult(name=name, status=status, duration_ms=duration_ms)

    if result.returncode == 2:
        raise HTTPException(404, f"app not found: {name}")

    stderr_snippet = result.stderr.decode(errors="replace")[:200]
    log.warning("wake: %s failed rc=%d stderr=%s", name, result.returncode, stderr_snippet)
    raise HTTPException(504, f"wake failed: {stderr_snippet}")


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
# POWER MANAGEMENT (Sleep/Wake)
# ═══════════════════════════════════════════════════════════════════════

import time
from datetime import datetime

POWER_STATE_FILE = Path("/var/lib/secubox/streamlit-power.json")
_last_activity: float = time.time()

def _load_power_state() -> dict:
    """Load power state from file."""
    if POWER_STATE_FILE.exists():
        try:
            return json.loads(POWER_STATE_FILE.read_text())
        except:
            pass
    return {"state": "running", "paused_at": None, "last_activity": time.time()}

def _save_power_state(state: dict):
    """Save power state to file."""
    POWER_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    POWER_STATE_FILE.write_text(json.dumps(state, indent=2))

def _update_activity():
    """Update last activity timestamp."""
    global _last_activity
    _last_activity = time.time()
    state = _load_power_state()
    state["last_activity"] = _last_activity
    _save_power_state(state)

def _get_idle_seconds() -> float:
    """Get seconds since last activity."""
    state = _load_power_state()
    last = state.get("last_activity", time.time())
    return time.time() - last

def _emit_presence_event(event: str, details: Optional[Dict[str, Any]] = None):
    """Emit presence event for banner injection and metoblizer logging.

    Events: 'wake', 'sleep', 'activity'
    """
    cfg = _cfg()
    event_data = {
        "timestamp": datetime.now().isoformat(),
        "module": "streamlit",
        "event": event,
        "details": details if details is not None else {},
    }

    # Log presence event for banner system
    if cfg.get("presence_events"):
        presence_file = Path("/var/lib/secubox/presence/streamlit.json")
        presence_file.parent.mkdir(parents=True, exist_ok=True)
        presence_file.write_text(json.dumps(event_data, indent=2))
        log.info("Presence event: %s", event)

    # Send to metoblizer if configured
    if cfg.get("metoblizer_log"):
        try:
            import urllib.request

            endpoint = cfg.get("metoblizer_endpoint")
            if endpoint:
                req = urllib.request.Request(
                    endpoint,
                    data=json.dumps(event_data).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST"
                )
                urllib.request.urlopen(req, timeout=5)
                log.debug("Metoblizer log sent: %s", event)
        except Exception as e:
            log.warning("Metoblizer log failed: %s", e)


def _load_streamlit_config() -> dict:
    """Load streamlit config from TOML file."""
    config_path = Path("/etc/secubox/streamlit.toml")
    if config_path.exists():
        try:
            import tomllib
            with open(config_path, "rb") as f:
                return tomllib.load(f)
        except Exception as e:
            log.warning("Failed to load config: %s", e)
    return {}


def _start_autostart_instances():
    """Start all instances with autostart=true."""
    cfg = _load_streamlit_config()
    if not cfg:
        return []

    started = []
    instances = cfg.get("instances", {})
    for name, inst in instances.items():
        if inst.get("autostart") and inst.get("enabled"):
            port = inst.get("port", 0)
            app = inst.get("app", name)
            if port:
                result = _run_ctl("instance", "start", name, str(port), timeout=30)
                if result.get("success") or "running" in str(result.get("output", "")).lower():
                    started.append({"name": name, "app": app, "port": port})
                    log.info("Autostarted instance: %s on port %s", name, port)
    return started

@router.get("/power/status")
async def power_status():
    """Get power state and idle time (public endpoint for dashboard)."""
    state = _load_power_state()
    running = _lxc_running()
    idle_secs = _get_idle_seconds()

    # Determine effective state
    if state.get("state") == "paused" and not running:
        effective_state = "paused"
    elif running:
        effective_state = "running"
    else:
        effective_state = "stopped"

    return {
        "state": effective_state,
        "container_running": running,
        "idle_seconds": int(idle_secs),
        "idle_formatted": _format_duration(int(idle_secs)),
        "paused_at": state.get("paused_at"),
        "auto_pause_enabled": _cfg().get("auto_pause", False),
        "auto_pause_minutes": _cfg().get("auto_pause_minutes", 30)
    }

def _format_duration(seconds: int) -> str:
    """Format seconds to human readable."""
    if seconds < 60:
        return f"{seconds}s"
    elif seconds < 3600:
        return f"{seconds // 60}m {seconds % 60}s"
    else:
        hours = seconds // 3600
        mins = (seconds % 3600) // 60
        return f"{hours}h {mins}m"

@router.post("/power/pause")
async def power_pause(user=Depends(require_jwt)):
    """Pause (sleep) the Streamlit container to save resources.

    Container is stopped but state is preserved. Use /power/wake to resume.
    """
    if not _lxc_running():
        return {"success": True, "message": "Already paused/stopped"}

    # Stop the container
    result = _run_ctl("stop", timeout=60)
    if "error" in result:
        raise HTTPException(500, f"Failed to pause: {result.get('error')}")

    # Save paused state
    state = _load_power_state()
    state["state"] = "paused"
    state["paused_at"] = datetime.now().isoformat()
    _save_power_state(state)

    # Emit presence event for banner injection
    _emit_presence_event("sleep", {"idle_seconds": int(_get_idle_seconds())})

    log.info("Streamlit container paused (sleep mode)")
    return {"success": True, "state": "paused"}

@router.post("/power/wake")
async def power_wake(user=Depends(require_jwt)):
    """Wake (resume) the Streamlit container from sleep.

    Restarts the container and all previously running apps.
    """
    if _lxc_running():
        _update_activity()
        return {"success": True, "message": "Already running"}

    # Start the container
    result = _run_ctl("start", timeout=60)
    if "error" in result:
        raise HTTPException(500, f"Failed to wake: {result.get('error')}")

    # Update state
    state = _load_power_state()
    paused_duration = None
    if state.get("paused_at"):
        try:
            paused_at = datetime.fromisoformat(state["paused_at"])
            paused_duration = int((datetime.now() - paused_at).total_seconds())
        except:
            pass
    state["state"] = "running"
    state["paused_at"] = None
    _update_activity()
    _save_power_state(state)

    # Emit presence event for banner injection
    _emit_presence_event("wake", {"paused_duration": paused_duration})

    # Start autostart instances
    autostarted = _start_autostart_instances()

    log.info("Streamlit container woken from sleep, autostarted %d instances", len(autostarted))
    return {"success": True, "state": "running", "autostarted": autostarted}

@router.post("/power/toggle")
async def power_toggle(user=Depends(require_jwt)):
    """Toggle between pause and running states."""
    if _lxc_running():
        return await power_pause(user)
    else:
        return await power_wake(user)


@router.get("/autostart")
async def list_autostart():
    """List instances configured for autostart (public)."""
    cfg = _load_streamlit_config()
    if not cfg:
        return {"autostart": [], "vhost_suffix": "gk2.secubox.in"}

    autostart_list = []
    instances = cfg.get("instances", {})
    for name, inst in instances.items():
        if inst.get("autostart") and inst.get("enabled"):
            autostart_list.append({
                "name": name,
                "app": inst.get("app", name),
                "port": inst.get("port"),
                "domain": inst.get("domain", f"{name}.gk2.secubox.in"),
                "emancipated": inst.get("emancipated", False),
            })

    return {
        "autostart": autostart_list,
        "count": len(autostart_list),
        "vhost_suffix": "gk2.secubox.in",
    }


@router.post("/autostart/run")
async def run_autostart(user=Depends(require_jwt)):
    """Manually trigger autostart for all configured instances."""
    if not _lxc_running():
        raise HTTPException(400, "Container not running. Wake it first.")

    started = _start_autostart_instances()
    return {
        "success": True,
        "started": started,
        "count": len(started),
    }


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
