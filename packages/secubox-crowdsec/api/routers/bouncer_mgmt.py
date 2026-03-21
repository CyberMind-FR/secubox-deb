"""secubox-crowdsec — Bouncer management (register, delete, firewall bouncer)"""
import subprocess
import json
from pathlib import Path
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from secubox_core.auth import require_jwt
from secubox_core.logger import get_logger

router = APIRouter()
log = get_logger("crowdsec.bouncer")

FW_BOUNCER_CONFIG = Path("/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml")


@router.post("/register_bouncer")
async def register_bouncer(bouncer_name: str, user=Depends(require_jwt)):
    """Enregistrer un nouveau bouncer."""
    r = subprocess.run(
        ["cscli", "bouncers", "add", bouncer_name, "--output", "json"],
        capture_output=True, text=True, timeout=15
    )
    if r.returncode == 0:
        try:
            data = json.loads(r.stdout)
            log.info("Bouncer registered: %s", bouncer_name)
            return {"success": True, "api_key": data.get("api_key", "")}
        except json.JSONDecodeError:
            return {"success": True, "output": r.stdout[:200]}
    return {"success": False, "error": r.stderr[:300]}


@router.post("/delete_bouncer")
async def delete_bouncer(bouncer_name: str, user=Depends(require_jwt)):
    """Supprimer un bouncer."""
    r = subprocess.run(
        ["cscli", "bouncers", "delete", bouncer_name],
        capture_output=True, text=True, timeout=15
    )
    log.info("delete_bouncer %s: %s", bouncer_name, r.returncode)
    return {"success": r.returncode == 0, "output": (r.stdout + r.stderr)[:300]}


@router.get("/firewall_bouncer_status")
async def firewall_bouncer_status(user=Depends(require_jwt)):
    """Statut du crowdsec-firewall-bouncer."""
    r = subprocess.run(
        ["systemctl", "is-active", "crowdsec-firewall-bouncer"],
        capture_output=True, text=True
    )
    active = r.stdout.strip() == "active"
    r2 = subprocess.run(
        ["systemctl", "is-enabled", "crowdsec-firewall-bouncer"],
        capture_output=True, text=True
    )
    enabled = r2.stdout.strip() == "enabled"
    return {"active": active, "enabled": enabled}


class BouncerControlRequest(BaseModel):
    action: str  # start, stop, restart, enable, disable


@router.post("/control_firewall_bouncer")
async def control_firewall_bouncer(req: BouncerControlRequest, user=Depends(require_jwt)):
    """Contrôler le service firewall-bouncer."""
    if req.action not in ("start", "stop", "restart", "enable", "disable"):
        return {"success": False, "error": f"Action invalide: {req.action}"}
    r = subprocess.run(
        ["systemctl", req.action, "crowdsec-firewall-bouncer"],
        capture_output=True, text=True, timeout=15
    )
    return {"success": r.returncode == 0, "output": r.stderr[:200]}


@router.get("/firewall_bouncer_config")
async def firewall_bouncer_config(user=Depends(require_jwt)):
    """Lire la config du firewall bouncer."""
    if not FW_BOUNCER_CONFIG.exists():
        return {"error": "Config not found"}
    try:
        import yaml
        with open(FW_BOUNCER_CONFIG) as f:
            return yaml.safe_load(f)
    except Exception as e:
        return {"error": str(e)}


class UpdateConfigRequest(BaseModel):
    key: str
    value: str


@router.post("/update_firewall_bouncer_config")
async def update_firewall_bouncer_config(req: UpdateConfigRequest, user=Depends(require_jwt)):
    """Modifier une clé de config du firewall bouncer."""
    # Simplification : log seulement, modification manuelle nécessaire
    log.info("update_firewall_bouncer_config: %s=%s", req.key, req.value)
    return {"success": False, "message": "Manual edit required for security"}


@router.get("/nftables_stats")
async def nftables_stats(user=Depends(require_jwt)):
    """Statistiques nftables (sets CrowdSec)."""
    r = subprocess.run(
        ["nft", "list", "set", "inet", "crowdsec", "crowdsec-blacklists"],
        capture_output=True, text=True, timeout=10
    )
    if r.returncode != 0:
        # Try alternate table name
        r = subprocess.run(
            ["nft", "list", "sets"],
            capture_output=True, text=True, timeout=10
        )
    return {"output": r.stdout[:2000], "error": r.stderr[:500] if r.returncode != 0 else None}
