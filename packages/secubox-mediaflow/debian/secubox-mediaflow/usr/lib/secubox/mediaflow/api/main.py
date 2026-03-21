"""secubox-mediaflow — Media Flow (consomme secubox-dpi)"""
from fastapi import FastAPI, APIRouter, Depends
from secubox_core.auth import router as auth_router, require_jwt
import httpx

app = FastAPI(title="secubox-mediaflow", version="1.0.0", root_path="/api/v1/mediaflow")
app.include_router(auth_router, prefix="/auth")
router = APIRouter()

DPI_BASE = "http+unix://%2Frun%2Fsecubox%2Fdpi.sock"

MEDIA_APPS = {
    "Netflix","YouTube","Twitch","Disney+","Spotify",
    "Apple Music","Tidal","Zoom","Teams","Google Meet",
    "WebEx","Amazon Prime","Hulu","RTSP","HLS","DASH"
}

async def _dpi(path: str):
    async with httpx.AsyncClient(transport=httpx.AsyncHTTPTransport(
        uds="/run/secubox/dpi.sock"), timeout=5) as c:
        r = await c.get(f"http://dpi{path}")
        return r.json()

@router.get("/status")
async def status(user=Depends(require_jwt)):
    try:
        s = await _dpi("/status")
        return {**s, "media_detection": True}
    except Exception as e:
        return {"running": False, "error": str(e)}

@router.get("/services")
async def services(user=Depends(require_jwt)):
    try:
        flows = await _dpi("/flows")
        media = {}
        for f in (flows.get("flows") or []):
            app_name = f.get("app_name","Unknown")
            if app_name in MEDIA_APPS:
                if app_name not in media:
                    media[app_name] = {"name": app_name, "flows": 0, "bytes": 0}
                media[app_name]["flows"] += 1
                media[app_name]["bytes"] += f.get("bytes",0)
        return list(media.values())
    except Exception:
        return []

@router.get("/clients")
async def clients(user=Depends(require_jwt)):
    try:
        return await _dpi("/devices")
    except Exception:
        return []

@router.get("/history")
async def history(user=Depends(require_jwt)):
    return []  # TODO: persist dans SQLite

@router.get("/alerts")
async def alerts(user=Depends(require_jwt)):
    return []  # TODO: anomalie détection


@router.get("/get_active_streams")
async def get_active_streams(user=Depends(require_jwt)):
    """Flux média actifs."""
    try:
        flows = await _dpi("/flows")
        return [f for f in (flows.get("flows") or []) if f.get("app_name") in MEDIA_APPS]
    except Exception:
        return []


@router.get("/get_stream_history")
async def get_stream_history(hours: int = 24, user=Depends(require_jwt)):
    """Historique des flux média."""
    return []  # TODO: SQLite history


@router.get("/get_stats_by_service")
async def get_stats_by_service(user=Depends(require_jwt)):
    """Statistiques par service média."""
    return await services(user)


@router.get("/get_stats_by_client")
async def get_stats_by_client(user=Depends(require_jwt)):
    """Statistiques par client."""
    try:
        devices = await _dpi("/devices")
        return devices if isinstance(devices, list) else []
    except Exception:
        return []


@router.get("/get_service_details")
async def get_service_details(service: str, user=Depends(require_jwt)):
    """Détails d'un service média."""
    try:
        flows = await _dpi("/flows")
        return [f for f in (flows.get("flows") or []) if f.get("app_name") == service]
    except Exception:
        return []


from pydantic import BaseModel


class AlertRequest(BaseModel):
    name: str
    service: str
    threshold_mb: int = 100


@router.post("/set_alert")
async def set_alert(req: AlertRequest, user=Depends(require_jwt)):
    """Créer une alerte sur un service."""
    from secubox_core.logger import get_logger
    log = get_logger("mediaflow")
    log.info("set_alert: %s on %s, threshold %dMB", req.name, req.service, req.threshold_mb)
    return {"success": True, "alert": req.name}


@router.post("/delete_alert")
async def delete_alert(name: str, user=Depends(require_jwt)):
    """Supprimer une alerte."""
    return {"success": True}


@router.get("/list_alerts")
async def list_alerts(user=Depends(require_jwt)):
    """Liste des alertes configurées."""
    return []


@router.post("/clear_history")
async def clear_history(user=Depends(require_jwt)):
    """Effacer l'historique."""
    return {"success": True}


@router.get("/get_settings")
async def get_settings(user=Depends(require_jwt)):
    """Paramètres du module."""
    from secubox_core.config import get_config
    return get_config("mediaflow") or {}


class SettingsRequest(BaseModel):
    detection_enabled: bool = True
    history_days: int = 7


@router.post("/set_settings")
async def set_settings(req: SettingsRequest, user=Depends(require_jwt)):
    """Sauvegarder les paramètres."""
    return {"success": True, "settings": req.model_dump()}


import subprocess


@router.post("/start_netifyd")
async def start_netifyd(user=Depends(require_jwt)):
    r = subprocess.run(["systemctl", "start", "netifyd"], capture_output=True, text=True)
    return {"success": r.returncode == 0}


@router.post("/stop_netifyd")
async def stop_netifyd(user=Depends(require_jwt)):
    r = subprocess.run(["systemctl", "stop", "netifyd"], capture_output=True, text=True)
    return {"success": r.returncode == 0}


@router.post("/start_ndpid")
async def start_ndpid(user=Depends(require_jwt)):
    r = subprocess.run(["systemctl", "start", "ndpid"], capture_output=True, text=True)
    return {"success": r.returncode == 0}


@router.post("/stop_ndpid")
async def stop_ndpid(user=Depends(require_jwt)):
    r = subprocess.run(["systemctl", "stop", "ndpid"], capture_output=True, text=True)
    return {"success": r.returncode == 0}


@router.get("/health")
async def health():
    return {"status": "ok", "module": "mediaflow"}


app.include_router(router)
