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
from fastapi.responses import FileResponse
from pydantic import BaseModel
from secubox_core.auth import router as auth_router, require_jwt
from secubox_core.config import get_config
from secubox_core.logger import get_logger
# secubox_core.screenshots ne fait QUE lire/servir un PNG déjà produit
# (voir app_screenshot ci-dessous) — jamais de capture in-process : celle-
# ci vit exclusivement dans le processus détaché `streamlit-shotter`
# (api/shots.py), lancé via `_spawn_shotter`, jamais importé ici. C'est ce
# qui garantit qu'un chromium enlisé ne peut jamais affecter la boucle
# d'événements partagée par l'agrégateur (#958).
from secubox_core import screenshots as _screenshots

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

# Vignettes capturées (#958) — répertoire de cache DÉDIÉ, jamais à
# l'intérieur de APPS_PATH : la moitié du parc est constituée de scripts
# .py à plat (#959), qui n'ont aucun répertoire où poser "une image à côté
# de l'appli", et pour les applis-répertoire ça polluerait potentiellement
# un dépôt git source. Même schéma de stockage que secubox-metablogizer
# (secubox_core.screenshots), sous sa propre clé de module.
SHOTS_CACHE_DIR = Path(os.environ.get("SECUBOX_STREAMLIT_SHOTS_CACHE",
                                       "/var/cache/secubox/streamlit/shots"))
# Le binaire qui pilote réellement chromium (api/shots.py). Toujours lancé
# en process DÉTACHÉ (voir _spawn_shotter) — jamais importé/appelé
# in-process ici, précisément pour que la capture (jusqu'à ~240s,
# secubox_core.shotter) ne puisse jamais geler la boucle d'événements
# partagée par tous les modules quand l'agrégateur les sert en process
# unique (#958 — incident récurrent de ce projet, cf. mémoire "aggregator
# wedge SPOF").
SHOTTER_BIN = os.environ.get("SECUBOX_STREAMLIT_SHOTTER_BIN",
                              "/usr/sbin/streamlit-shotter")


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


def _spawn_shotter(name: str, *, force: bool) -> None:
    """Lance `streamlit-shotter` en tâche DÉTACHÉE et rend la main
    immédiatement (#958).

    `subprocess.Popen(...)` retourne dès le fork+exec (millisecondes) — il
    n'attend JAMAIS l'issue du processus fils. Toute la résolution de
    cible (l'appli tourne-t-elle ? sur quel port ? IP du conteneur ?) et la
    capture elle-même (jusqu'à ~240s, chromium piloté par CDP) se déroulent
    dans ce processus fils, entièrement hors de ce service et de sa boucle
    d'événements : même un chromium qui s'enliserait ne peut affecter que
    ce processus détaché, jamais l'agrégateur qui sert ce module (et ~110
    autres) en process unique.

    Ne lève jamais : appelée après un réveil déjà réussi ou un clic
    "recapturer" déjà validé, un échec de lancement ne doit dégrader ni
    l'un ni l'autre — seulement finir au journal.
    """
    args = [SHOTTER_BIN, name] + (["--force"] if force else [])
    try:
        subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                          start_new_session=True)
    except OSError as exc:
        log.warning("shotter spawn failed for %s: %s", name, exc)


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


# ═══════════════════════════════════════════════════════════════════════
# SCREENSHOTS — Mosaic tile thumbnails (#958)
# ═══════════════════════════════════════════════════════════════════════

@router.get("/apps/{name}/screenshot")
def app_screenshot(name: str):
    """Sert la vignette conservée. PUBLIC — sans JWT : un `<img src>` ne
    porte pas d'en-tête Authorization, et le mur affiche 56 vignettes sans
    session ouverte vers quoi que ce soit (même choix, déjà réglé, que la
    route équivalente de secubox-metablogizer).

    Route de LECTURE SEULE : ne déclenche jamais de capture, quel que soit
    le nombre de requêtes reçues — la vignette est déjà là ou elle ne l'est
    pas (`sync def` : FastAPI la sert depuis le threadpool, un simple accès
    fichier, jamais de subprocess ici).

    `Cache-Control: public, max-age=604800, immutable` — délibérément PAS
    `no-cache` : le panneau ajoute déjà `?t=<captured_at>` à l'URL (voir
    `www/streamlit/index.html`), donc l'URL elle-même change quand le
    contenu change. Tant que `captured_at` ne bouge pas, c'est
    STRICTEMENT le même contenu — laisser le navigateur servir sa copie
    locale sans même revalider est exactement ce qui évite de retélécharger
    56 PNG à chaque rafraîchissement de 60s (#958 point 5).
    """
    try:
        p = _screenshots.png_path(SHOTS_CACHE_DIR, name)
    except ValueError:
        raise HTTPException(404, "unknown app")
    if not p.exists():
        raise HTTPException(404, "no screenshot yet")
    meta = _screenshots.read_meta(SHOTS_CACHE_DIR, name)
    return FileResponse(p, media_type="image/png", headers={
        "Cache-Control": "public, max-age=604800, immutable",
        "X-Captured-At": str(meta.get("captured_at", "")),
    })


@router.post("/apps/{name}/recapture")
def app_recapture(name: str, user=Depends(require_jwt)):
    """Déclencheur MANUEL (spec §3.1) — le bouton "recapturer" d'une tuile.

    Valide la cible ICI (rapide : entrypoint + port + `lxc-info`, pas de
    chromium) pour donner un retour immédiat et exact au bouton — 404 si
    l'appli est inconnue, 409 si elle est endormie ou sans cible
    exploitable. Ce pré-check n'est PAS fait sur le chemin de réveil (voir
    `wake_app`) : là, l'appli vient déjà de se réveiller avec succès, le
    coût d'une seconde résolution serait payé pour rien.

    Rend la main dès le lancement du processus détaché — jamais après la
    capture elle-même (~240s), voir `_spawn_shotter`.
    """
    target = _run_ctl("app", "shot-target", name)
    if not target.get("ok"):
        reason = str(target.get("error") or "capture impossible")
        raise HTTPException(404 if "not found" in reason else 409, reason)
    _spawn_shotter(name, force=True)
    return {"ok": True, "triggered": True, "name": name}


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
# Lazy restart an idle-stopped streamlit app (ref #331, budget/blocking
# fix ref #958).

class WakeResult(BaseModel):
    name: str
    status: str  # "running" (already up) | "waking" (just triggered, or
                 # already in flight — poll POST .../wake again, or the
                 # live GET /apps / GET /app/{name} the wall already
                 # consumes, until "running")
    duration_ms: int  # cost of resolving THIS response (the fast liveness
                       # check below) — never the wake itself, which may
                       # still be running long after this response ships.


# Réveils actuellement en vol, par nom d'appli (#958 follow-up). Même
# motif que le verrou par-module de secubox-waker
# (packages/secubox-profiles/api/waker.py::_locks/_lock) : dédier UN
# réveil à la fois par nom, jamais une seconde tentative concurrente tant
# que la première n'a pas fini — la libération se fait dans le `finally`
# de `_do_wake_in_background`, jamais par le handler HTTP lui-même (qui
# rend la main bien avant que le réveil ne se termine). Un vrai
# `threading.Lock`, pas seulement l'atomicité du GIL sur `set` : la prise
# se fait sur le thread de la boucle d'événements, la libération sur un
# thread du threadpool (voir plus bas) — deux threads différents touchent
# le même ensemble.
_wake_claim_mutex = threading.Lock()
_WAKE_IN_PROGRESS: set = set()


def _wake_try_claim(name: str) -> bool:
    """Réclame `name` pour un nouveau réveil en fond, ou refuse si un
    réveil est déjà en vol pour cette appli."""
    with _wake_claim_mutex:
        if name in _WAKE_IN_PROGRESS:
            return False
        _WAKE_IN_PROGRESS.add(name)
        return True


def _wake_release(name: str) -> None:
    with _wake_claim_mutex:
        _WAKE_IN_PROGRESS.discard(name)


def _do_wake_in_background(name: str) -> None:
    """Exécute le réveil RÉEL (`streamlitctl app wake <name>`) — jusqu'à
    [wake].budget_seconds (300s par défaut, /etc/secubox/streamlit.toml,
    cf. `cmd_app_wake`) sur une board chargée, mesuré 26 à 78s, parfois
    plus.

    Tourne dans le threadpool que Starlette utilise pour toute
    `BackgroundTasks.add_task` d'une fonction SYNCHRONE (voir son appel
    dans `wake_app` ci-dessous) — jamais sur la boucle d'événements que
    l'agrégateur partage avec ~110 autres modules. C'est la même
    discipline déjà appliquée à `container_install` ci-dessus (`install`,
    jusqu'à 600s, même mécanisme) : un `subprocess.run` synchrone est sans
    risque ICI précisément parce qu'il tourne hors de la boucle
    d'événements — c'est un `subprocess.run` exécuté DIRECTEMENT dans un
    handler `async def`, comme le faisait l'ancienne version de cette
    route, qui gelait l'agrégateur pour tout le monde pendant la durée du
    réveil.

    AUCUN argument de secondes n'est passé à `streamlitctl app wake` ici :
    le budget vit dans un seul endroit, [wake].budget_seconds, résolu par
    `cmd_app_wake` lui-même. Dupliquer ce nombre ici — même comme timeout
    Python — recréerait exactement le défaut que ce correctif referme :
    deux constantes qui finissent par diverger.
    """
    try:
        result = subprocess.run(
            ["sudo", "-n", CTL, "app", "wake", name],
            capture_output=True, check=False,
        )
        if result.returncode == 0:
            log.info("wake: %s woke successfully (background)", name)
            # Capture paresseuse (#958, spec §3.1/§3.5) : SI la vignette
            # est périmée. On n'arrive ici qu'APRÈS un réveil qui vient de
            # réussir pour sa propre raison — jamais un réveil déclenché
            # pour photographier. `_spawn_shotter` rend la main tout de
            # suite : ce thread de fond n'attend jamais les ~240s d'une
            # capture en plus des ~300s déjà passées à réveiller.
            _spawn_shotter(name, force=False)
        else:
            stderr_snippet = result.stderr.decode(errors="replace")[:200]
            log.warning("wake: %s failed rc=%d stderr=%s", name, result.returncode, stderr_snippet)
    except OSError as exc:
        log.warning("wake: %s failed to launch: %s", name, exc)
    finally:
        _wake_release(name)


@router.post("/apps/{name}/wake", response_model=WakeResult)
async def wake_app(name: str, background_tasks: BackgroundTasks, user=Depends(require_jwt)) -> WakeResult:
    """Wake an idle-stopped streamlit app — never blocks on the wake itself.

    The actual wake (`streamlitctl app wake <name>`) can take up to
    [wake].budget_seconds on a loaded board (300s default, measured 26 to
    78s, sometimes more) — this handler never awaits it. It only:

      1. Runs a FAST, bounded liveness check (`streamlitctl app list` — one
         `lxc-attach ps` scan for the whole fleet, same cost class as
         `app_recapture`'s own pre-check just above, NOT the specifically
         unbounded wait-loop `cmd_app_wake` used to run in-request). If the
         app is already running, returns immediately with status="running"
         — no background task needed.
      2. Otherwise, claims the per-app in-flight lock (`_wake_try_claim`)
         and hands the real wake off to `_do_wake_in_background` via
         `BackgroundTasks` — which Starlette runs in its threadpool, off
         the shared event loop (see that function's docstring) — and
         returns status="waking" immediately.

    A caller polling this same route again for an app still waking gets
    status="waking" again (the lock refuses a second background task);
    once the wake completes, the very next fast liveness check (here, or
    via the existing GET /apps / GET /app/{name} the wall already
    consumes) reports "running". No new state channel was invented for
    this — see the docstring above and the follow-up report for #958.

    Status codes:
      - 200: status="running" (already up) or "waking" (just triggered, or
        a wake for this app was already in flight)
      - 404: app does not exist (per the same `app list` used for the
        liveness check — unified with `cmd_app_wake`'s own notion of
        "exists" since #958's `_app_entrypoint`/`_scan_running_apps`
        unification; the #959 "two existence checks that diverge" trap
        this route used to avoid by delegating everything to
        `streamlitctl app wake` no longer applies, because `app list` and
        `app wake` now share the exact same resolution helpers)
      - 502: streamlitctl binary missing

    Concurrency with `secubox-waker`/`secubox-wakectl` (packages/
    secubox-profiles): that pair wakes a whole MODULE (the secubox-streamlit
    LXC/service itself) on external vhost access, a coarser granularity
    than this route (one app process inside an already-running module) —
    see the #958 follow-up report for what was verified about this from
    the repo and what could not be.
    """
    if not Path(CTL).exists():
        raise HTTPException(502, "streamlitctl missing")

    start = time.monotonic()
    apps_by_name = {a.get("name"): a for a in _get_apps()}
    app_row = apps_by_name.get(name)
    duration_ms = int((time.monotonic() - start) * 1000)

    if app_row is None:
        raise HTTPException(404, f"app not found: {name}")

    if app_row.get("running"):
        _spawn_shotter(name, force=False)
        return WakeResult(name=name, status="running", duration_ms=duration_ms)

    if not _wake_try_claim(name):
        log.info("wake: %s already in flight, not triggering a second one", name)
        return WakeResult(name=name, status="waking", duration_ms=duration_ms)

    background_tasks.add_task(_do_wake_in_background, name)
    log.info("wake: %s triggered in background, duration_ms=%d (liveness check only)", name, duration_ms)
    return WakeResult(name=name, status="waking", duration_ms=duration_ms)


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
    """Emit presence event for banner injection.

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
