"""secubox-crowdsec — Hub management (collections, parsers, scenarios)"""
import subprocess
import json
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from secubox_core.auth import require_jwt
from secubox_core.logger import get_logger

router = APIRouter()
log = get_logger("crowdsec.hub")


def _cscli(*args, timeout: int = 30) -> dict:
    """Execute cscli with JSON output."""
    cmd = ["cscli", *args, "--output", "json"]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if r.returncode != 0:
        return {"error": r.stderr.strip()[:500]}
    try:
        return json.loads(r.stdout) if r.stdout.strip() else {}
    except json.JSONDecodeError:
        return {"raw": r.stdout[:1000]}


@router.get("/collections")
async def collections(user=Depends(require_jwt)):
    """Liste des collections installées."""
    return _cscli("collections", "list")


@router.post("/install_collection")
async def install_collection(collection: str, user=Depends(require_jwt)):
    """Installer une collection du hub."""
    r = subprocess.run(
        ["cscli", "collections", "install", collection],
        capture_output=True, text=True, timeout=60
    )
    log.info("install_collection %s: %s", collection, r.returncode)
    return {"success": r.returncode == 0, "output": (r.stdout + r.stderr)[:500]}


@router.post("/remove_collection")
async def remove_collection(collection: str, user=Depends(require_jwt)):
    """Supprimer une collection."""
    r = subprocess.run(
        ["cscli", "collections", "remove", collection],
        capture_output=True, text=True, timeout=30
    )
    return {"success": r.returncode == 0, "output": (r.stdout + r.stderr)[:500]}


@router.post("/update_hub")
async def update_hub(user=Depends(require_jwt)):
    """Mettre à jour le hub CrowdSec."""
    r = subprocess.run(
        ["cscli", "hub", "update"],
        capture_output=True, text=True, timeout=120
    )
    return {"success": r.returncode == 0, "output": (r.stdout + r.stderr)[:1000]}


@router.get("/hub_available")
async def hub_available(user=Depends(require_jwt)):
    """Éléments disponibles dans le hub (non installés)."""
    return _cscli("hub", "list", "--all")


class HubItemRequest(BaseModel):
    item_type: str  # parsers, scenarios, collections, postoverflows
    item_name: str


@router.post("/install_hub_item")
async def install_hub_item(req: HubItemRequest, user=Depends(require_jwt)):
    """Installer un élément du hub."""
    if req.item_type not in ("parsers", "scenarios", "collections", "postoverflows"):
        raise HTTPException(400, f"Type invalide: {req.item_type}")
    r = subprocess.run(
        ["cscli", req.item_type, "install", req.item_name],
        capture_output=True, text=True, timeout=60
    )
    return {"success": r.returncode == 0, "output": (r.stdout + r.stderr)[:500]}


@router.post("/remove_hub_item")
async def remove_hub_item(req: HubItemRequest, user=Depends(require_jwt)):
    """Supprimer un élément du hub."""
    if req.item_type not in ("parsers", "scenarios", "collections", "postoverflows"):
        raise HTTPException(400, f"Type invalide: {req.item_type}")
    r = subprocess.run(
        ["cscli", req.item_type, "remove", req.item_name],
        capture_output=True, text=True, timeout=30
    )
    return {"success": r.returncode == 0, "output": (r.stdout + r.stderr)[:500]}
