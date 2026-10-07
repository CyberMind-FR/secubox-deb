# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""secubox-photoprism — FastAPI application for PhotoPrism photo management.

Provides native PhotoPrism (LXC) management with library indexing,
face recognition, album management, and storage configuration.
"""
import asyncio
import subprocess
import json
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any

from fastapi import FastAPI, APIRouter, Depends, HTTPException
from pydantic import BaseModel

from secubox_core.auth import router as auth_router, require_jwt
from secubox_core.logger import get_logger
from secubox_core.auth import require_lecture
from secubox_core.auth import hote_box

app = FastAPI(title="secubox-photoprism", version="1.0.0", root_path="/api/v1/photoprism")

# ══════════════════════════════════════════════════════════════════
# Health Check Endpoint (public, no auth)
# ══════════════════════════════════════════════════════════════════

@app.get("/health")
async def health_check():
    """Public health check endpoint for sidebar status."""
    return {"status": "ok", "module": "deb"}

app.include_router(auth_router, prefix="/auth")
router = APIRouter()
log = get_logger("photoprism")

# Configuration
CONFIG_FILE = Path("/etc/secubox/photoprism.toml")
INSTALL_LIB = "/usr/share/secubox/lib/photoprism/install-lxc.sh"
PHOTOPRISMCTL = "/usr/sbin/photoprismctl"
# PhotoPrism runs NATIVELY inside the photoprism LXC (official Linux build,
# systemd unit — lib/photoprism/install-lxc.sh). LXC ONLY: never podman/docker
# (.claude/PATTERNS.md Pattern 11, #1742, #1743).
CONTAINER_NAME = "photoprism"
DEFAULT_CONFIG = {
    # LXC
    "name": "photoprism",
    "ip": "10.100.0.130",
    "path": "/data/lxc",
    # PhotoPrism (inside the LXC)
    "enabled": False,
    "port": 2342,
    "http_port": 2342,
    "data_path": "/data/photoprism",
    "originals_path": "/data/shared/photos",   # shared with Nextcloud "PhotoLibrary"
    "import_path": "/data/photoprism/import",
    "timezone": "Europe/Paris",
    # Dérivés du domaine de CETTE box (#1723) — jamais celui de gk2.
    "domain": hote_box("photoprism"),
    "public_hostname": hote_box("photoprism"),
    "haproxy": False,
    "face_recognition": True,
    "experimental": False,
    "readonly": False,
    "public": False,
    "admin_password": "",
}


# ============================================================================
# Models
# ============================================================================

class AlbumCreate(BaseModel):
    title: str
    description: str = ""


class UserCreate(BaseModel):
    username: str
    password: str
    role: str = "viewer"  # admin, viewer


# ============================================================================
# Helpers
# ============================================================================

def get_config() -> dict:
    """Load + flatten photoprism.toml ([lxc]/[photoprism]/[exposure]) over defaults."""
    cfg = DEFAULT_CONFIG.copy()
    if CONFIG_FILE.exists():
        try:
            import tomllib
            raw = tomllib.loads(CONFIG_FILE.read_text())
            for section in ("lxc", "photoprism", "exposure"):
                for k, v in (raw.get(section) or {}).items():
                    cfg[k] = v
            for k, v in raw.items():        # tolerate flat keys too
                if not isinstance(v, dict):
                    cfg[k] = v
        except Exception:
            pass
    return cfg


# Mesures coûteuses (rglob, du) : servies depuis un cache (#1747). Une valeur
# périmée est rendue aussitôt et recalculée en tâche de fond — jamais un `du`
# de 30 s par requête derrière la coupure d'HAProxy à 30 s d'inactivité.
_MESURES_TTL = 600.0
_mesures: dict = {}
_mesures_verrou = threading.Lock()


def _mesure(cle: str, calcul):
    with _mesures_verrou:
        m = _mesures.get(cle)
        frais = m is not None and time.monotonic() - m["t"] < _MESURES_TTL
        if m is not None and not frais and not m.get("en_cours"):
            m["en_cours"] = True

            def _rafraichir():
                try:
                    v = calcul()
                    with _mesures_verrou:
                        _mesures[cle] = {"t": time.monotonic(), "v": v}
                except Exception:
                    with _mesures_verrou:
                        m["en_cours"] = False
            threading.Thread(target=_rafraichir, daemon=True).start()
    if m is not None:
        return m["v"]
    v = calcul()
    with _mesures_verrou:
        _mesures[cle] = {"t": time.monotonic(), "v": v}
    return v


def http_reachable() -> bool:
    """True if PhotoPrism answers on <ip>:<http_port> (inside its LXC)."""
    cfg = get_config()
    ip = cfg.get("ip", "10.100.0.130")
    port = cfg.get("http_port", cfg.get("port", 2342))
    try:
        r = subprocess.run(
            ["curl", "-fsS", "-o", "/dev/null", "--max-time", "3", f"http://{ip}:{port}/"],
            capture_output=True, timeout=5,
        )
        return r.returncode == 0
    except Exception:
        return False


def lxc_state() -> str:
    """LXC container state (best-effort; the dashboard user may lack access)."""
    cfg = get_config()
    try:
        r = subprocess.run(
            ["lxc-info", "-n", cfg.get("name", "photoprism"), "-P", cfg.get("path", "/data/lxc")],
            capture_output=True, text=True, timeout=5,
        )
        for line in r.stdout.splitlines():
            if line.strip().lower().startswith("state:"):
                return line.split(":", 1)[1].strip().lower()
    except Exception:
        pass
    return "unknown"


def get_container_status() -> dict:
    """PhotoPrism status — primary signal is HTTP reachability of the LXC
    instance (the dashboard runs unprivileged and can't always read lxc-info)."""
    if http_reachable():
        return {"status": "running", "uptime": ""}
    state = lxc_state()
    if state in ("stopped", "frozen"):
        return {"status": "stopped", "uptime": ""}
    return {"status": "not_installed", "uptime": ""}


def is_running() -> bool:
    """Check if PhotoPrism is reachable."""
    return http_reachable()


def _ctl(verb: str) -> List[str]:
    """photoprismctl est root (lxc-start, lxc-attach) ; l'API tourne en
    `secubox`. Le seul passage est `sudo -n`, limité par
    /etc/sudoers.d/secubox-photoprism aux verbes nommés, sans argument (#1745)."""
    return ["sudo", "-n", PHOTOPRISMCTL, verb]


def _photoprismctl_detache(verb: str) -> dict:
    """Long verb (install/update/index/import: minutes) run detached, logged.

    HAProxy cuts an idle request after 30 s: waiting for it here would only
    turn a working job into a client-side error.
    """
    journal = f"/var/log/secubox/photoprism-{verb}.log"
    try:
        subprocess.Popen(
            _ctl(verb),
            stdout=open(journal, "a"), stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        return {"success": True, "message": f"{verb} started (several minutes). Follow {journal}."}
    except Exception as e:
        return {"success": False, "error": str(e)}


def _photoprismctl(verb: str, timeout: int = 60) -> dict:
    try:
        r = subprocess.run(_ctl(verb), capture_output=True, text=True, timeout=timeout)
        return {"success": r.returncode == 0, "stdout": r.stdout, "stderr": r.stderr}
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "timeout"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def get_library_stats() -> dict:
    """Get library statistics from PhotoPrism."""
    cfg = get_config()
    originals_path = Path(cfg.get("originals_path", "/srv/photoprism/originals"))
    import_path = Path(cfg.get("import_path", "/srv/photoprism/import"))

    stats = {
        "total_photos": 0,
        "total_videos": 0,
        "total_albums": 0,
        "storage_used": "0",
        "import_pending": 0,
    }

    # Count files in originals
    if originals_path.exists():
        try:
            photo_exts = {'.jpg', '.jpeg', '.png', '.gif', '.webp', '.heic', '.heif', '.raw', '.cr2', '.nef', '.arw'}
            video_exts = {'.mp4', '.mov', '.avi', '.mkv', '.webm', '.m4v'}

            for f in originals_path.rglob('*'):
                if f.is_file():
                    ext = f.suffix.lower()
                    if ext in photo_exts:
                        stats["total_photos"] += 1
                    elif ext in video_exts:
                        stats["total_videos"] += 1

            # Get storage size
            result = subprocess.run(
                ["du", "-sh", str(originals_path)],
                capture_output=True, text=True, timeout=30
            )
            if result.stdout:
                stats["storage_used"] = result.stdout.split()[0]
        except Exception:
            pass

    # Count pending imports
    if import_path.exists():
        try:
            stats["import_pending"] = sum(1 for f in import_path.rglob('*') if f.is_file())
        except Exception:
            pass

    # Count albums from sidecar files (simplified)
    albums_file = Path(cfg.get("data_path", "/srv/photoprism")) / "albums.json"
    if albums_file.exists():
        try:
            albums = json.loads(albums_file.read_text())
            stats["total_albums"] = len(albums)
        except Exception:
            pass

    return stats


# Le comptage de la photothèque (rglob + du sur tous les originaux) coûte, et /status est lu chaque minute par la carte du Hall :
# on le mesure EN ARRIÈRE-PLAN, au plus une fois par STATS_DELAI_S, et on rend le dernier chiffre en attendant. Premier appel : des
# zéros marqués `mesure_en_cours`, jamais un blocage.
STATS_DELAI_S = 600
_STATS = {"valeur": None, "date": 0.0, "en_cours": False}
_STATS_VERROU = threading.Lock()
_STATS_VIDE = {"total_photos": 0, "total_videos": 0, "total_albums": 0, "storage_used": "0", "import_pending": 0}


def _mesure_stats() -> None:
    try:
        v = get_library_stats()
    except Exception:  # noqa: BLE001
        v = None
    with _STATS_VERROU:
        if v is not None:
            _STATS["valeur"] = v
        _STATS["date"] = time.time()   # même un échec attend le prochain délai : pas de boucle de recomptage
        _STATS["en_cours"] = False


def stats_bibliotheque() -> dict:
    """Dernier comptage connu de la photothèque ; lance la mesure en arrière-plan si elle est périmée."""
    with _STATS_VERROU:
        perime = (time.time() - _STATS["date"]) > STATS_DELAI_S
        if perime and not _STATS["en_cours"]:
            _STATS["en_cours"] = True
            threading.Thread(target=_mesure_stats, name="photoprism-stats", daemon=True).start()
        valeur = _STATS["valeur"]
    if valeur is None:
        return {**_STATS_VIDE, "mesure_en_cours": True}
    return {**valeur, "mesure_en_cours": False}


def get_albums() -> List[dict]:
    """Get list of albums."""
    cfg = get_config()
    albums_file = Path(cfg.get("data_path", "/srv/photoprism")) / "albums.json"
    if albums_file.exists():
        try:
            return json.loads(albums_file.read_text())
        except Exception:
            pass
    return []


def save_albums(albums: List[dict]):
    """Save albums list."""
    cfg = get_config()
    albums_file = Path(cfg.get("data_path", "/srv/photoprism")) / "albums.json"
    albums_file.parent.mkdir(parents=True, exist_ok=True)
    albums_file.write_text(json.dumps(albums, indent=2))


def get_users() -> List[dict]:
    """Get list of users (simplified - stored locally)."""
    cfg = get_config()
    users_file = Path(cfg.get("data_path", "/srv/photoprism")) / "users.json"
    if users_file.exists():
        try:
            return json.loads(users_file.read_text())
        except Exception:
            pass
    return [{"username": "admin", "role": "admin", "created": "system"}]


def save_users(users: List[dict]):
    """Save users list."""
    cfg = get_config()
    users_file = Path(cfg.get("data_path", "/srv/photoprism")) / "users.json"
    users_file.parent.mkdir(parents=True, exist_ok=True)
    users_file.write_text(json.dumps(users, indent=2))


# ============================================================================
# Public Endpoints
# ============================================================================

@router.get("/health")
async def health():
    """Health check."""
    return {"status": "ok", "module": "photoprism"}


@router.get("/status", dependencies=[Depends(require_lecture)])
def status():
    """Get PhotoPrism service status (native-LXC)."""
    cfg = get_config()
    container = get_container_status()
    lib_stats = stats_bibliotheque()
    hostname = cfg.get("public_hostname") or cfg.get("domain") or hote_box("photoprism")  # #1723

    return {
        "deployment": "lxc-native",
        "enabled": cfg.get("enabled", False),
        "build": "native — dl.photoprism.app (LXC uniquement)",
        "port": cfg.get("port", 2342),
        "lxc_name": cfg.get("name", "photoprism"),
        "lxc_ip": cfg.get("ip", "10.100.0.130"),
        "lxc_state": lxc_state(),
        "http_reachable": http_reachable(),
        "data_path": cfg.get("data_path", "/data/photoprism"),
        "originals_path": cfg.get("originals_path", "/data/shared/photos"),
        "import_path": cfg.get("import_path", "/data/photoprism/import"),
        "timezone": cfg.get("timezone", "Europe/Paris"),
        "domain": hostname,
        "public_url": f"https://{hostname}/",
        "haproxy": cfg.get("haproxy", False),
        "face_recognition": cfg.get("face_recognition", True),
        "experimental": cfg.get("experimental", False),
        "readonly": cfg.get("readonly", False),
        "public": cfg.get("public", False),
        # webui back-compat keys (was Docker; now native-LXC):
        "runtime": "lxc-native",
        "container_status": container["status"],
        "container_uptime": container["uptime"],
        "library_stats": lib_stats,
    }


# ============================================================================
# Protected Endpoints - Configuration
# ============================================================================

@router.get("/config")
async def get_photoprism_config(user=Depends(require_jwt)):
    """Get PhotoPrism configuration."""
    cfg = get_config()
    # Remove sensitive data
    cfg.pop("admin_password", None)
    return cfg


@router.post("/config")
async def set_photoprism_config(user=Depends(require_jwt)):
    """Ne réécrit plus /etc/secubox/photoprism.toml (#1747).

    L'ancienne version l'écrivait À PLAT : les sections [lxc], [photoprism] et
    [exposure] — adresse du conteneur, fichier du mot de passe, nom public —
    disparaissaient, et photoprismctl repartait sur ses défauts. Ses champs
    (chemins /srv, domaine, « public »…) n'étaient de toute façon lus par
    personne. Les réglages vivent dans le fichier, appliqués par photoprismctl.
    """
    return _reglage_tenu_par_le_fichier()


# ============================================================================
# Library Management
# ============================================================================

@router.get("/library/stats")
def get_library_statistics(user=Depends(require_jwt)):
    """Library statistics — cached (#1747) : a full rglob of the library per
    request was the cost of each page load."""
    return _mesure("stats", get_library_stats)


@router.post("/library/index")
def start_indexing(user=Depends(require_jwt)):
    """Start library indexing."""
    if not is_running():
        return {"success": False, "error": "PhotoPrism is not running"}

    log.info(f"Starting index by {user.get('sub', 'unknown')}")
    # Via photoprismctl (lxc-attach exige root) → photoprism-cli dans le LXC ;
    # détaché : une bibliothèque réelle dépasse les 30 s d'HAProxy.
    return _photoprismctl_detache("index")


@router.post("/library/import")
def import_photos(user=Depends(require_jwt)):
    """Import photos from import folder."""
    if not is_running():
        return {"success": False, "error": "PhotoPrism is not running"}

    log.info(f"Starting import by {user.get('sub', 'unknown')}")
    return _photoprismctl_detache("import")


# ============================================================================
# Album Management
# ============================================================================

@router.get("/albums")
async def list_albums(user=Depends(require_jwt)):
    """List all albums."""
    return {"albums": get_albums()}


@router.post("/album/create")
async def create_album(album: AlbumCreate, user=Depends(require_jwt)):
    """Create a new album."""
    albums = get_albums()

    # Check for duplicate
    for a in albums:
        if a.get("title", "").lower() == album.title.lower():
            return {"success": False, "error": "Album already exists"}

    new_album = {
        "id": f"album_{len(albums)+1}_{int(datetime.now().timestamp())}",
        "title": album.title,
        "description": album.description,
        "created": datetime.now().isoformat(),
        "photo_count": 0,
    }
    albums.append(new_album)
    save_albums(albums)

    log.info(f"Album created: {album.title} by {user.get('sub', 'unknown')}")
    return {"success": True, "album": new_album}


@router.delete("/album/{album_id}")
async def delete_album(album_id: str, user=Depends(require_jwt)):
    """Delete an album."""
    albums = get_albums()
    new_albums = [a for a in albums if a.get("id") != album_id]

    if len(new_albums) == len(albums):
        return {"success": False, "error": "Album not found"}

    save_albums(new_albums)
    log.info(f"Album deleted: {album_id} by {user.get('sub', 'unknown')}")
    return {"success": True}


# ============================================================================
# Face Recognition
# ============================================================================

@router.get("/faces")
async def get_face_status(user=Depends(require_jwt)):
    """Get face recognition status."""
    cfg = get_config()
    return {
        "enabled": cfg.get("face_recognition", True),
        "status": "active" if cfg.get("face_recognition", True) and is_running() else "inactive",
    }


def _reglage_tenu_par_le_fichier() -> dict:
    return {"success": False,
            "error": "Réglages tenus par /etc/secubox/photoprism.toml "
                     "([lxc], [photoprism], [exposure]) et appliqués par "
                     "photoprismctl — rien n'a été modifié."}


@router.post("/faces/enable")
async def enable_face_recognition(user=Depends(require_jwt)):
    """Ne réécrit plus la configuration (#1747) : `face_recognition` n'est lu
    par aucun outil, et l'écriture à plat détruisait les sections du fichier."""
    return _reglage_tenu_par_le_fichier()


@router.post("/faces/disable")
async def disable_face_recognition(user=Depends(require_jwt)):
    """Voir /faces/enable (#1747)."""
    return _reglage_tenu_par_le_fichier()


# ============================================================================
# Storage
# ============================================================================

@router.get("/storage")
def get_storage_info(user=Depends(require_jwt)):
    """Storage information — cached (#1747) : up to three `du` of 30 s each."""
    return _mesure("stockage", _mesurer_stockage)


def _mesurer_stockage() -> dict:
    cfg = get_config()
    data_path = Path(cfg.get("data_path", "/srv/photoprism"))
    originals_path = Path(cfg.get("originals_path", "/srv/photoprism/originals"))
    import_path = Path(cfg.get("import_path", "/srv/photoprism/import"))

    storage = {
        "data_path": str(data_path),
        "originals_path": str(originals_path),
        "import_path": str(import_path),
        "data_size": "0",
        "originals_size": "0",
        "import_size": "0",
        "disk_free": "0",
        "disk_total": "0",
        "disk_used_percent": 0,
    }

    try:
        # Get sizes
        for path_key, path in [("data", data_path), ("originals", originals_path), ("import", import_path)]:
            if path.exists():
                result = subprocess.run(
                    ["du", "-sh", str(path)],
                    capture_output=True, text=True, timeout=30
                )
                if result.stdout:
                    storage[f"{path_key}_size"] = result.stdout.split()[0]

        # Get disk space
        if data_path.exists():
            result = subprocess.run(
                ["df", "-h", str(data_path)],
                capture_output=True, text=True, timeout=10
            )
            if result.stdout:
                lines = result.stdout.strip().split('\n')
                if len(lines) > 1:
                    parts = lines[1].split()
                    if len(parts) >= 5:
                        storage["disk_total"] = parts[1]
                        storage["disk_free"] = parts[3]
                        storage["disk_used_percent"] = int(parts[4].rstrip('%'))
    except Exception:
        pass

    return storage


# ============================================================================
# User Management
# ============================================================================

@router.get("/users")
async def list_users(user=Depends(require_jwt)):
    """List users."""
    users = get_users()
    # Remove sensitive data
    return {"users": [{"username": u["username"], "role": u["role"]} for u in users]}


@router.post("/user")
async def create_user(new_user: UserCreate, user=Depends(require_jwt)):
    """Create a new user."""
    users = get_users()

    # Jamais de mot de passe écrit par cette API (#1745) : l'ancienne version le
    # rangeait EN CLAIR dans <data_path>/users.json, une liste que PhotoPrism
    # ne lit même pas. Les comptes naissent à la première connexion SecuBox
    # (OIDC, OIDCRegister) ou par secubox-user-sync (photoprismctl
    # user-provision, mot de passe par stdin).
    log.info(f"User creation refused (SSO only): {new_user.username} by {user.get('sub', 'unknown')}")
    return {"success": False,
            "error": "Comptes PhotoPrism : connexion SecuBox (SSO) ou synchronisation "
                     "des comptes — l'interface ne crée pas de mot de passe."}


@router.delete("/user/{username}")
async def delete_user(username: str, user=Depends(require_jwt)):
    """Delete a user."""
    if username.lower() == "admin":
        return {"success": False, "error": "Cannot delete admin user"}

    users = get_users()
    new_users = [u for u in users if u["username"].lower() != username.lower()]

    if len(new_users) == len(users):
        return {"success": False, "error": "User not found"}

    save_users(new_users)
    log.info(f"User deleted: {username} by {user.get('sub', 'unknown')}")
    return {"success": True}


# ============================================================================
# Container Management
# ============================================================================

@router.get("/container/status")
async def container_status(user=Depends(require_jwt)):
    """LXC + reachability status (kept under /container/* for webui back-compat)."""
    container = get_container_status()
    return {
        "runtime": "lxc-native",
        "runtime_available": True,
        "container_name": CONTAINER_NAME,
        "lxc_state": lxc_state(),
        "http_reachable": http_reachable(),
        "status": container["status"],
        "uptime": container["uptime"],
    }


@router.post("/container/install")
def install_photoprism(user=Depends(require_jwt)):
    """Provision the LXC + native PhotoPrism. Long-running → detached."""
    if not Path(INSTALL_LIB).exists():
        return {"success": False, "error": f"install script missing at {INSTALL_LIB}"}
    log.info(f"Launching native-LXC PhotoPrism install by {user.get('sub', 'unknown')}")
    # Par photoprismctl, pas install-lxc.sh en direct : c'est lui qui
    # transmet le toml (nom public, port, auto_index, workers).
    return _photoprismctl_detache("install")


@router.post("/container/start")
async def start_photoprism(user=Depends(require_jwt)):
    """Start PhotoPrism (LXC)."""
    log.info(f"Starting PhotoPrism LXC by {user.get('sub', 'unknown')}")
    r = _photoprismctl("start")
    return {"success": r.get("success", False), "output": r.get("stdout", r.get("error", ""))}


@router.post("/container/stop")
async def stop_photoprism(user=Depends(require_jwt)):
    """Stop PhotoPrism (LXC)."""
    log.info(f"Stopping PhotoPrism LXC by {user.get('sub', 'unknown')}")
    r = _photoprismctl("stop")
    return {"success": r.get("success", False), "output": r.get("stdout", r.get("error", ""))}


@router.post("/container/restart")
async def restart_photoprism(user=Depends(require_jwt)):
    """Restart PhotoPrism (LXC)."""
    log.info(f"Restarting PhotoPrism LXC by {user.get('sub', 'unknown')}")
    r = _photoprismctl("restart")
    return {"success": r.get("success", False), "output": r.get("stdout", r.get("error", ""))}


@router.post("/container/uninstall")
async def uninstall_photoprism(user=Depends(require_jwt)):
    """Stop the LXC (data on /data/photoprism + /data/shared/photos preserved)."""
    log.info(f"Stopping PhotoPrism LXC (data preserved) by {user.get('sub', 'unknown')}")
    r = _photoprismctl("stop")
    return {"success": r.get("success", False), "message": "LXC stopped, data preserved"}


@router.post("/container/update")
def update_photoprism(user=Depends(require_jwt)):
    """Re-download the official native build inside the LXC + restart."""
    log.info(f"Updating PhotoPrism (native build) by {user.get('sub', 'unknown')}")
    return _photoprismctl_detache("update")


# ============================================================================
# Logs
# ============================================================================

@router.get("/logs")
def get_logs(lines: int = 50, user=Depends(require_jwt)):
    """Tail photoprism.service journal inside the LXC (photoprismctl logs).

    lxc-attach exige root : on passe par le verbe `logs` (50 lignes, sans
    argument — sudoers n'en admet aucun) et on tronque ici si on en veut moins."""
    r = _photoprismctl("logs", timeout=15)
    texte = (r.get("stdout") or "") + (r.get("stderr") or r.get("error") or "")
    garde = texte.splitlines()[-max(1, min(lines, 50)):]
    return {"logs": "\n".join(garde) or "No logs available"}


# ============================================================================
# Backup/Restore
# ============================================================================

@router.post("/backup")
def backup_photoprism(user=Depends(require_jwt)):
    """Archive storage/ (instantané SQLite, sans le cache) dans
    /var/backups/secubox/photoprism par `photoprismctl backup` (#1747).

    Destination fixe, choisie par le verbe root — jamais par l'appelant. Avant :
    un tar en `secubox` dans /tmp (PrivateTmp : invisible et effacé au
    redémarrage), qui ne pouvait pas lire la base du conteneur. Détaché : une
    archive de plusieurs centaines de Mo dépasse la coupure d'HAProxy (30 s).
    """
    log.info(f"Backup requested by {user.get('sub', 'unknown')}")
    r = _photoprismctl_detache("backup")
    if r.get("success"):
        r["path"] = "/var/backups/secubox/photoprism/"
    return r


# /restore retiré (#1747) : il extrayait une archive désignée par un CHEMIN
# LIBRE du client dans data_path, sans contrôle du contenu, et aucune page ne
# l'appelait. Une restauration est un geste d'opérateur sur la box.


app.include_router(router)
