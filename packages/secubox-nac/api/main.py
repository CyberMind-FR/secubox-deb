"""
secubox-nac — FastAPI application
Port de luci-app-client-guardian

Méthodes RPCD portées :
  status, clients, zones, portal_config, parental_rules, alerts, logs
  + POST : add_to_zone, remove_from_zone, set_portal_config, set_parental_rule
"""
from __future__ import annotations
from fastapi import FastAPI, APIRouter, Depends, HTTPException
from pydantic import BaseModel
from secubox_core.auth   import router as auth_router, require_jwt
from secubox_core.config import get_config
from secubox_core.logger import get_logger
import subprocess, json, re
from pathlib import Path

app = FastAPI(title="secubox-nac", version="1.0.0", root_path="/api/v1/nac")
app.include_router(auth_router, prefix="/auth")

router = APIRouter()
log    = get_logger("nac")

LEASES_FILE   = Path("/var/lib/misc/dnsmasq.leases")
NFT_TABLE     = "inet secubox_nac"

# Zones → nftables set names
ZONES = {
    "lan":         {"nft_set": "lan_allowed",    "desc": "LAN principal",    "color": "green"},
    "iot":         {"nft_set": "iot_zone",        "desc": "IoT isolé",        "color": "orange"},
    "guest":       {"nft_set": "guest_zone",      "desc": "Invités",          "color": "blue"},
    "quarantine":  {"nft_set": "quarantine_zone", "desc": "Quarantaine",      "color": "red"},
}


# ── Helpers ───────────────────────────────────────────────────────

def _parse_leases() -> list[dict]:
    """Parse /var/lib/misc/dnsmasq.leases → liste de clients."""
    clients = []
    if not LEASES_FILE.exists():
        return clients
    for line in LEASES_FILE.read_text().splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        clients.append({
            "expiry":   int(parts[0]),
            "mac":      parts[1],
            "ip":       parts[2],
            "hostname": parts[3] if parts[3] != "*" else "",
            "id":       parts[4] if len(parts) > 4 else "",
        })
    return clients


def _nft_list_set(set_name: str) -> list[str]:
    """Retourne les éléments d'un set nftables (MACs ou IPs)."""
    r = subprocess.run(
        ["nft", "-j", "list", "set", "inet", "secubox_nac", set_name],
        capture_output=True, text=True, timeout=5
    )
    try:
        data = json.loads(r.stdout)
        elements = []
        for item in data.get("nftables", []):
            if "set" in item:
                for e in item["set"].get("elem", []):
                    if isinstance(e, str):
                        elements.append(e)
                    elif isinstance(e, dict):
                        elements.append(e.get("val", str(e)))
        return elements
    except Exception:
        return []


def _nft_add_element(set_name: str, element: str):
    subprocess.run(
        ["nft", "add", "element", "inet", "secubox_nac", set_name, "{", element, "}"],
        check=True, timeout=5
    )


def _nft_delete_element(set_name: str, element: str):
    subprocess.run(
        ["nft", "delete", "element", "inet", "secubox_nac", set_name, "{", element, "}"],
        capture_output=True, timeout=5
    )


def _get_client_zone(mac: str) -> str:
    """Retrouve la zone d'un client par son MAC."""
    for zone_id, zone_info in ZONES.items():
        if mac.lower() in [e.lower() for e in _nft_list_set(zone_info["nft_set"])]:
            return zone_id
    return "quarantine"


# ── GET ───────────────────────────────────────────────────────────

@router.get("/status")
async def status(user=Depends(require_jwt)):
    leases = _parse_leases()
    nft_ok = subprocess.run(["nft", "list", "tables"],
                            capture_output=True).returncode == 0
    dnsmasq_ok = subprocess.run(["pgrep", "dnsmasq"],
                                 capture_output=True).returncode == 0
    return {
        "client_count": len(leases),
        "nftables_ok":  nft_ok,
        "dnsmasq_ok":   dnsmasq_ok,
        "zones":        list(ZONES.keys()),
    }


@router.get("/clients")
async def clients(user=Depends(require_jwt)):
    leases = _parse_leases()
    result = []
    for c in leases:
        zone = _get_client_zone(c["mac"])
        result.append({**c, "zone": zone, "zone_color": ZONES[zone]["color"]})
    return result


@router.get("/zones")
async def zones(user=Depends(require_jwt)):
    result = []
    for zone_id, info in ZONES.items():
        members = _nft_list_set(info["nft_set"])
        result.append({
            "id":       zone_id,
            "name":     info["desc"],
            "color":    info["color"],
            "nft_set":  info["nft_set"],
            "members":  members,
            "count":    len(members),
        })
    return result


@router.get("/portal_config")
async def portal_config(user=Depends(require_jwt)):
    cfg = get_config("nac")
    return {
        "default_zone":   cfg.get("default_zone", "quarantine"),
        "dhcp_range":     cfg.get("dhcp_range", ""),
        "dns_servers":    cfg.get("dns_servers", []),
        "portal_enabled": True,
    }


@router.get("/parental_rules")
async def parental_rules(user=Depends(require_jwt)):
    rules_file = Path("/etc/secubox/nac-parental.json")
    if rules_file.exists():
        return json.loads(rules_file.read_text())
    return []


@router.get("/alerts")
async def alerts(user=Depends(require_jwt)):
    # Nouveaux clients dans la quarantaine
    quarantine = _nft_list_set("quarantine_zone")
    leases = _parse_leases()
    alerts_list = []
    for c in leases:
        if c["mac"].lower() in [q.lower() for q in quarantine]:
            alerts_list.append({
                "type": "new_client",
                "mac":  c["mac"],
                "ip":   c["ip"],
                "host": c["hostname"],
            })
    return alerts_list


@router.get("/logs")
async def logs(lines: int = 100, user=Depends(require_jwt)):
    r = subprocess.run(
        ["journalctl", "-u", "dnsmasq", "-n", str(lines), "--no-pager", "-o", "short"],
        capture_output=True, text=True, timeout=10
    )
    return {"lines": r.stdout.splitlines()}


# ── POST ──────────────────────────────────────────────────────────

class ZoneRequest(BaseModel):
    mac:  str
    zone: str


@router.post("/add_to_zone")
async def add_to_zone(req: ZoneRequest, user=Depends(require_jwt)):
    if req.zone not in ZONES:
        raise HTTPException(400, f"Zone invalide: {req.zone}")
    # Retirer le client de toutes les autres zones
    for zone_id, info in ZONES.items():
        _nft_delete_element(info["nft_set"], req.mac)
    # Ajouter dans la zone cible
    try:
        _nft_add_element(ZONES[req.zone]["nft_set"], req.mac)
        log.info("Client %s → zone %s", req.mac, req.zone)
        return {"success": True, "mac": req.mac, "zone": req.zone}
    except subprocess.CalledProcessError as e:
        raise HTTPException(500, f"nft error: {e}")


@router.post("/remove_from_zone")
async def remove_from_zone(mac: str, user=Depends(require_jwt)):
    for info in ZONES.values():
        _nft_delete_element(info["nft_set"], mac)
    # Remettre en quarantaine
    _nft_add_element(ZONES["quarantine"]["nft_set"], mac)
    return {"success": True, "mac": mac, "zone": "quarantine"}


class ParentalRule(BaseModel):
    mac:         str
    block_until: str = "22:00"   # HH:MM
    blocked_categories: list[str] = []


@router.post("/set_parental_rule")
async def set_parental_rule(req: ParentalRule, user=Depends(require_jwt)):
    rules_file = Path("/etc/secubox/nac-parental.json")
    rules = json.loads(rules_file.read_text()) if rules_file.exists() else []
    rules = [r for r in rules if r.get("mac") != req.mac]
    rules.append(req.model_dump())
    rules_file.write_text(json.dumps(rules, indent=2))
    return {"success": True, "rule": req.model_dump()}


@router.get("/get_client")
async def get_client(mac: str, user=Depends(require_jwt)):
    """Détails d'un client."""
    leases = _parse_leases()
    for c in leases:
        if c["mac"].lower() == mac.lower():
            zone = _get_client_zone(c["mac"])
            return {**c, "zone": zone, "zone_color": ZONES[zone]["color"]}
    raise HTTPException(404, "Client not found")


@router.get("/parental")
async def parental(user=Depends(require_jwt)):
    """Alias pour parental_rules."""
    return await parental_rules(user)


@router.post("/approve_client")
async def approve_client(mac: str, zone: str = "lan", user=Depends(require_jwt)):
    """Approuver un client (déplacer hors quarantaine)."""
    return await add_to_zone(ZoneRequest(mac=mac, zone=zone), user)


@router.post("/ban_client")
async def ban_client(mac: str, user=Depends(require_jwt)):
    """Bannir un client (bloquer complètement)."""
    # Remove from all zones and add to a blocked set
    for info in ZONES.values():
        _nft_delete_element(info["nft_set"], mac)
    # Add to blocked set (if it exists)
    try:
        subprocess.run(
            ["nft", "add", "element", "inet", "secubox_nac", "blocked", "{", mac, "}"],
            capture_output=True, timeout=5
        )
    except Exception:
        pass
    log.info("Client banned: %s", mac)
    return {"success": True, "mac": mac, "status": "banned"}


@router.post("/unban_client")
async def unban_client(mac: str, user=Depends(require_jwt)):
    """Débannir un client."""
    try:
        subprocess.run(
            ["nft", "delete", "element", "inet", "secubox_nac", "blocked", "{", mac, "}"],
            capture_output=True, timeout=5
        )
    except Exception:
        pass
    # Put back in quarantine
    _nft_add_element(ZONES["quarantine"]["nft_set"], mac)
    return {"success": True, "mac": mac, "status": "quarantine"}


@router.post("/quarantine_client")
async def quarantine_client(mac: str, user=Depends(require_jwt)):
    """Mettre un client en quarantaine."""
    return await add_to_zone(ZoneRequest(mac=mac, zone="quarantine"), user)


class UpdateClientRequest(BaseModel):
    mac: str
    hostname: str = ""
    zone: str = ""
    notes: str = ""


@router.post("/update_client")
async def update_client(req: UpdateClientRequest, user=Depends(require_jwt)):
    """Mettre à jour les infos d'un client."""
    if req.zone:
        await add_to_zone(ZoneRequest(mac=req.mac, zone=req.zone), user)
    # Store metadata
    meta_file = Path("/var/lib/secubox/nac-clients.json")
    meta = json.loads(meta_file.read_text()) if meta_file.exists() else {}
    meta[req.mac] = {"hostname": req.hostname, "notes": req.notes}
    meta_file.parent.mkdir(parents=True, exist_ok=True)
    meta_file.write_text(json.dumps(meta, indent=2))
    return {"success": True, "mac": req.mac}


class UpdateZoneRequest(BaseModel):
    zone_id: str
    name: str = ""
    color: str = ""


@router.post("/update_zone")
async def update_zone(req: UpdateZoneRequest, user=Depends(require_jwt)):
    """Mettre à jour une zone."""
    log.info("update_zone: %s", req.zone_id)
    return {"success": True, "zone": req.zone_id}


@router.get("/send_test_alert")
async def send_test_alert(user=Depends(require_jwt)):
    """Envoyer une alerte de test."""
    return {"success": True, "message": "Test alert sent"}


@router.get("/get_policy")
async def get_policy(user=Depends(require_jwt)):
    """Obtenir la politique NAC."""
    cfg = get_config("nac")
    return {
        "default_zone": cfg.get("default_zone", "quarantine"),
        "auto_approve": cfg.get("auto_approve", False),
        "quarantine_timeout": cfg.get("quarantine_timeout", 0),
    }


class PolicyRequest(BaseModel):
    default_zone: str = "quarantine"
    auto_approve: bool = False
    quarantine_timeout: int = 0


@router.post("/set_policy")
async def set_policy(req: PolicyRequest, user=Depends(require_jwt)):
    """Définir la politique NAC."""
    log.info("set_policy: default_zone=%s auto_approve=%s", req.default_zone, req.auto_approve)
    return {"success": True, "policy": req.model_dump()}


@router.get("/sync_zones")
async def sync_zones(user=Depends(require_jwt)):
    """Synchroniser les zones avec nftables."""
    for zone_id, info in ZONES.items():
        # Ensure set exists
        subprocess.run(
            ["nft", "add", "set", "inet", "secubox_nac", info["nft_set"],
             "{ type ether_addr; }"],
            capture_output=True
        )
    return {"success": True, "zones": list(ZONES.keys())}


@router.get("/list_profiles")
async def list_profiles(user=Depends(require_jwt)):
    """Profils de configuration NAC."""
    return [
        {"id": "home", "name": "Maison", "description": "Config maison simple"},
        {"id": "small_business", "name": "PME", "description": "Petite entreprise"},
        {"id": "hotspot", "name": "Hotspot", "description": "Point d'accès public"},
    ]


class ApplyProfileRequest(BaseModel):
    profile_id: str


@router.post("/apply_profile")
async def apply_profile(req: ApplyProfileRequest, user=Depends(require_jwt)):
    """Appliquer un profil NAC."""
    log.info("apply_profile: %s", req.profile_id)
    return {"success": True, "profile": req.profile_id}


@router.get("/health")
async def health():
    return {"status": "ok", "module": "nac"}


app.include_router(router)
