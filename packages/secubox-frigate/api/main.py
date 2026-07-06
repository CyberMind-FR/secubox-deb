# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""SecuBox-Deb :: secubox-frigate :: /api/v1/frigate/* shim (Foundation, #821)."""
import json, os, shutil, threading, time, urllib.request
from pathlib import Path
from fastapi import APIRouter, Depends, FastAPI

try:
    from secubox_core.auth import require_jwt
except ImportError:  # test/offline fallback — only when the lib is absent
    def require_jwt():  # noqa: D401
        return {"sub": "anon"}

FRIGATE_URL = os.environ.get("SECUBOX_FRIGATE_URL", "http://10.100.0.140:5000")
DATA_DIR = os.environ.get("SECUBOX_FRIGATE_DATA", "/data/frigate")
CACHE_FILE = Path("/var/cache/secubox/frigate/stats.json")
EVENTS_LIMIT = 50

app = FastAPI(title="secubox-frigate")
router = APIRouter(prefix="/api/v1/frigate")
_cache: dict = {}
_storage_cache: dict = {}
_lock = threading.Lock()


def _frigate_get(path: str):
    """GET Frigate's HTTP API. Returns (json, True) or (None, False). Never raises."""
    try:
        with urllib.request.urlopen(FRIGATE_URL + path, timeout=3) as r:
            return json.loads(r.read().decode("utf-8")), True
    except Exception:
        return None, False


def _compute_status(fetched=None) -> dict:
    """fetched: optional pre-fetched (data, ok) tuple from `_frigate_get("/api/stats")`,
    to avoid a redundant round-trip when the caller already has it (see _compute_stats)."""
    data, ok = fetched if fetched is not None else _frigate_get("/api/stats")
    if not ok or not data:
        return {"up": False, "version": None, "uptime": None, "detector_fps": None}
    svc = data.get("service", {})
    det = next(iter(data.get("detectors", {}).values()), {})
    return {"up": True, "version": svc.get("version"), "uptime": svc.get("uptime"),
            "detector_fps": det.get("inference_speed")}


def _compute_cameras(fetched=None) -> list:
    """fetched: optional pre-fetched (data, ok) tuple, see _compute_status."""
    data, ok = fetched if fetched is not None else _frigate_get("/api/stats")
    if not ok or not data:
        return []
    out = []
    for name, c in (data.get("cameras") or {}).items():
        out.append({"name": name, "online": (c.get("camera_fps", 0) or 0) > 0,
                    "camera_fps": c.get("camera_fps"), "detection_fps": c.get("detection_fps"),
                    "process_fps": c.get("process_fps")})
    return out


def _compute_events() -> list:
    data, ok = _frigate_get(f"/api/events?limit={EVENTS_LIMIT}")
    if not ok or not data:
        return []
    out = []
    for e in data[:EVENTS_LIMIT]:
        eid = e.get("id")
        out.append({"id": eid, "label": e.get("label"), "camera": e.get("camera"),
                    "start_time": e.get("start_time"), "zones": e.get("zones", []),
                    "snapshot": f"/api/v1/frigate/media/events/{eid}/snapshot.jpg" if eid else None})
    return out


def _compute_storage() -> dict:
    try:
        du = shutil.disk_usage(DATA_DIR)
        rec = Path(DATA_DIR) / "recordings"
        oldest = None
        if rec.is_dir():
            files = sorted(rec.rglob("*.mp4"))
            if files:
                oldest = int(files[0].stat().st_mtime)
        return {"path": DATA_DIR, "total": du.total, "used": du.used, "free": du.free,
                "pct_used": round(du.used / du.total * 100, 1) if du.total else 0, "oldest_recording": oldest}
    except Exception:
        return {"path": DATA_DIR, "total": None, "used": None, "free": None, "pct_used": None, "oldest_recording": None}


def _compute_stats() -> dict:
    fetched = _frigate_get("/api/stats")  # single round-trip, shared by cameras + status
    cams = _compute_cameras(fetched=fetched)
    evs = _compute_events()
    det = _compute_status(fetched=fetched).get("detector_fps")
    # TOP-LEVEL keys the sidebar reads directly (nac /stats contract).
    return {"cameras": len(cams), "events": len(evs), "fps": det,
            "by_camera": {c["name"]: c.get("detection_fps") for c in cams}}


def refresh_cache():
    while True:
        try:
            data = _compute_stats()
            CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
            CACHE_FILE.write_text(json.dumps(data))
            storage_data = _compute_storage()
            with _lock:
                _cache.update(data)
                _storage_cache.update(storage_data)
        except Exception:
            pass
        time.sleep(60)


@app.on_event("startup")
def _startup():
    threading.Thread(target=refresh_cache, daemon=True).start()


@router.get("/status")
def status(user=Depends(require_jwt)):
    return _compute_status()


@router.get("/cameras")
def cameras(user=Depends(require_jwt)):
    return {"cameras": _compute_cameras()}


@router.get("/events")
def events(user=Depends(require_jwt)):
    return {"events": _compute_events()}


@router.get("/storage")
def storage(user=Depends(require_jwt)):
    with _lock:
        if _storage_cache:
            return dict(_storage_cache)
    return _compute_storage()


@router.get("/stats")
def stats(user=Depends(require_jwt)):
    with _lock:
        if _cache:
            return dict(_cache)
    if CACHE_FILE.exists():
        try:
            return json.loads(CACHE_FILE.read_text())
        except Exception:
            pass
    return _compute_stats()


app.include_router(router)
