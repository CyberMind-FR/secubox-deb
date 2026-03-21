"""secubox-crowdsec — actions (ban/unban) — méthodes POST"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
import subprocess
from secubox_core.auth   import require_jwt
from secubox_core.logger import get_logger

router = APIRouter()
log    = get_logger("crowdsec.actions")


class BanRequest(BaseModel):
    ip:       str
    duration: str = "24h"
    reason:   str = "manual-secubox"


class UnbanRequest(BaseModel):
    ip: str


@router.post("/ban")
async def ban(req: BanRequest, user=Depends(require_jwt)):
    """Bannir une IP via cscli."""
    # Validation IPv4/IPv6 sommaire
    import ipaddress
    try:
        ipaddress.ip_address(req.ip)
    except ValueError:
        raise HTTPException(400, f"IP invalide: {req.ip}")

    r = subprocess.run(
        ["cscli", "decisions", "add",
         "--ip", req.ip,
         "--duration", req.duration,
         "--reason", req.reason],
        capture_output=True, text=True, timeout=10
    )
    ok = r.returncode == 0
    if ok:
        log.info("Ban appliqué: %s (%s)", req.ip, req.reason)
    else:
        log.warning("Échec ban %s: %s", req.ip, r.stderr[:200])
    return {"success": ok, "ip": req.ip, "output": (r.stdout + r.stderr).strip()[:500]}


@router.post("/unban")
async def unban(req: UnbanRequest, user=Depends(require_jwt)):
    """Lever le ban d'une IP via cscli."""
    r = subprocess.run(
        ["cscli", "decisions", "delete", "--ip", req.ip],
        capture_output=True, text=True, timeout=10
    )
    ok = r.returncode == 0
    if ok:
        log.info("Unban: %s", req.ip)
    return {"success": ok, "ip": req.ip, "output": (r.stdout + r.stderr).strip()[:500]}


@router.post("/collect_debug")
async def collect_debug(user=Depends(require_jwt)):
    """Collecte de debug anonymisée pour support."""
    r = subprocess.run(
        ["cscli", "support", "dump", "--output", "json"],
        capture_output=True, text=True, timeout=30
    )
    return {"success": r.returncode == 0, "output": r.stdout[:5000]}


@router.post("/reload")
async def reload(user=Depends(require_jwt)):
    """Reload CrowdSec engine."""
    r = subprocess.run(
        ["systemctl", "reload", "crowdsec"],
        capture_output=True, text=True, timeout=30
    )
    log.info("CrowdSec reload requested")
    return {"success": r.returncode == 0, "output": (r.stdout + r.stderr).strip()[:500]}


@router.post("/hub_update")
async def hub_update(user=Depends(require_jwt)):
    """Update CrowdSec hub."""
    r = subprocess.run(
        ["cscli", "hub", "update"],
        capture_output=True, text=True, timeout=60
    )
    log.info("CrowdSec hub update requested")
    return {"success": r.returncode == 0, "output": (r.stdout + r.stderr).strip()[:500]}


@router.post("/flush_decisions")
async def flush_decisions(user=Depends(require_jwt)):
    """Flush all CrowdSec decisions."""
    r = subprocess.run(
        ["cscli", "decisions", "delete", "--all"],
        capture_output=True, text=True, timeout=30
    )
    log.info("CrowdSec decisions flushed")
    return {"success": r.returncode == 0, "output": (r.stdout + r.stderr).strip()[:500]}


class CollectionRequest(BaseModel):
    name: str


@router.post("/install_collection")
async def install_collection(req: CollectionRequest, user=Depends(require_jwt)):
    """Install a CrowdSec collection."""
    r = subprocess.run(
        ["cscli", "collections", "install", req.name],
        capture_output=True, text=True, timeout=60
    )
    log.info("Collection install: %s", req.name)
    return {"success": r.returncode == 0, "name": req.name, "output": (r.stdout + r.stderr).strip()[:500]}
