"""secubox-crowdsec — Wizard, health check, CAPI, service control"""
import subprocess
import json
from pathlib import Path
from fastapi import APIRouter, Depends
from pydantic import BaseModel
import httpx
from secubox_core.auth import require_jwt
from secubox_core.config import get_config
from secubox_core.logger import get_logger

router = APIRouter()
log = get_logger("crowdsec.wizard")


def _lapi():
    cfg = get_config("crowdsec")
    return cfg.get("lapi_url", "http://127.0.0.1:8080"), cfg.get("lapi_key", "")


@router.get("/check_wizard_needed")
async def check_wizard_needed(user=Depends(require_jwt)):
    """Vérifie si le wizard initial est nécessaire."""
    # Check if LAPI is reachable and configured
    url, key = _lapi()
    try:
        async with httpx.AsyncClient(timeout=5) as c:
            r = await c.get(f"{url}/v1/decisions?limit=0", headers={"X-Api-Key": key})
            if r.status_code == 200:
                return {"wizard_needed": False, "reason": "LAPI OK"}
    except Exception:
        pass
    return {"wizard_needed": True, "reason": "LAPI not reachable or not configured"}


@router.get("/wizard_state")
async def wizard_state(user=Depends(require_jwt)):
    """État actuel de la configuration CrowdSec."""
    state = {
        "lapi_ok": False,
        "capi_enrolled": False,
        "firewall_bouncer": False,
        "collections_installed": 0,
    }

    # LAPI check
    url, key = _lapi()
    try:
        async with httpx.AsyncClient(timeout=5) as c:
            r = await c.get(f"{url}/v1/decisions?limit=0", headers={"X-Api-Key": key})
            state["lapi_ok"] = r.status_code == 200
    except Exception:
        pass

    # CAPI check
    r = subprocess.run(
        ["cscli", "capi", "status", "--output", "json"],
        capture_output=True, text=True, timeout=10
    )
    if r.returncode == 0 and "enrolled" in r.stdout.lower():
        state["capi_enrolled"] = True

    # Firewall bouncer
    r = subprocess.run(
        ["systemctl", "is-active", "crowdsec-firewall-bouncer"],
        capture_output=True, text=True
    )
    state["firewall_bouncer"] = r.stdout.strip() == "active"

    # Collections
    r = subprocess.run(
        ["cscli", "collections", "list", "--output", "json"],
        capture_output=True, text=True, timeout=10
    )
    if r.returncode == 0:
        try:
            data = json.loads(r.stdout)
            state["collections_installed"] = len(data) if isinstance(data, list) else 0
        except json.JSONDecodeError:
            pass

    return state


@router.post("/repair_lapi")
async def repair_lapi(user=Depends(require_jwt)):
    """Réparer/réinitialiser la connexion LAPI."""
    r = subprocess.run(
        ["cscli", "machines", "add", "-a", "--force"],
        capture_output=True, text=True, timeout=30
    )
    log.info("repair_lapi: %s", r.returncode)
    return {"success": r.returncode == 0, "output": (r.stdout + r.stderr)[:500]}


@router.post("/repair_capi")
async def repair_capi(user=Depends(require_jwt)):
    """Réparer/réenregistrer la connexion CAPI."""
    r = subprocess.run(
        ["cscli", "capi", "register", "--force"],
        capture_output=True, text=True, timeout=30
    )
    return {"success": r.returncode == 0, "output": (r.stdout + r.stderr)[:500]}


@router.post("/reset_wizard")
async def reset_wizard(user=Depends(require_jwt)):
    """Réinitialiser le flag wizard."""
    # This would clear any "wizard done" flags
    return {"success": True, "message": "Wizard reset"}


@router.get("/console_status")
async def console_status(user=Depends(require_jwt)):
    """Statut de l'enrôlement à la console CrowdSec."""
    r = subprocess.run(
        ["cscli", "console", "status", "--output", "json"],
        capture_output=True, text=True, timeout=10
    )
    if r.returncode == 0:
        try:
            return json.loads(r.stdout)
        except json.JSONDecodeError:
            return {"enrolled": "status" in r.stdout.lower()}
    return {"enrolled": False, "error": r.stderr[:200]}


class ConsoleEnrollRequest(BaseModel):
    key: str
    name: str = ""


@router.post("/console_enroll")
async def console_enroll(req: ConsoleEnrollRequest, user=Depends(require_jwt)):
    """Enrôler à la console CrowdSec."""
    cmd = ["cscli", "console", "enroll", req.key]
    if req.name:
        cmd.extend(["--name", req.name])
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    log.info("console_enroll: %s", r.returncode)
    return {"success": r.returncode == 0, "output": (r.stdout + r.stderr)[:500]}


@router.post("/console_disable")
async def console_disable(user=Depends(require_jwt)):
    """Désactiver l'enrôlement console."""
    r = subprocess.run(
        ["cscli", "console", "disable"],
        capture_output=True, text=True, timeout=15
    )
    return {"success": r.returncode == 0, "output": (r.stdout + r.stderr)[:300]}


class ServiceControlRequest(BaseModel):
    action: str  # start, stop, restart, reload


@router.post("/service_control")
async def service_control(req: ServiceControlRequest, user=Depends(require_jwt)):
    """Contrôler le service CrowdSec."""
    if req.action not in ("start", "stop", "restart", "reload"):
        return {"success": False, "error": f"Action invalide: {req.action}"}
    r = subprocess.run(
        ["systemctl", req.action, "crowdsec"],
        capture_output=True, text=True, timeout=30
    )
    log.info("service_control %s: %s", req.action, r.returncode)
    return {"success": r.returncode == 0, "output": r.stderr[:200]}


@router.get("/health_check")
async def health_check(user=Depends(require_jwt)):
    """Vérification de santé complète."""
    health = {
        "crowdsec_running": False,
        "lapi_reachable": False,
        "firewall_bouncer": False,
    }

    # CrowdSec service
    r = subprocess.run(["pgrep", "crowdsec"], capture_output=True)
    health["crowdsec_running"] = r.returncode == 0

    # LAPI
    url, key = _lapi()
    try:
        async with httpx.AsyncClient(timeout=3) as c:
            r = await c.get(f"{url}/v1/decisions?limit=0", headers={"X-Api-Key": key})
            health["lapi_reachable"] = r.status_code == 200
    except Exception:
        pass

    # Firewall bouncer
    r = subprocess.run(
        ["systemctl", "is-active", "crowdsec-firewall-bouncer"],
        capture_output=True, text=True
    )
    health["firewall_bouncer"] = r.stdout.strip() == "active"

    return health


@router.get("/capi_metrics")
async def capi_metrics(user=Depends(require_jwt)):
    """Métriques de la connexion CAPI."""
    r = subprocess.run(
        ["cscli", "capi", "status", "--output", "json"],
        capture_output=True, text=True, timeout=10
    )
    if r.returncode == 0:
        try:
            return json.loads(r.stdout)
        except json.JSONDecodeError:
            return {"output": r.stdout[:500]}
    return {"error": r.stderr[:200]}
