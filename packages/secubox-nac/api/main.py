"""SecuBox NAC API - Network Access Control with Enhanced Monitoring

Port of luci-app-client-guardian with production features.
Manages client zones, parental controls, and network policies.
"""
from __future__ import annotations
import subprocess
import json
import threading
import time
import asyncio
import hashlib
import hmac
import httpx
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator
from secubox_core.auth import router as auth_router, require_jwt
from secubox_core.config import get_config
from secubox_core.logger import get_logger

app = FastAPI(title="secubox-nac", version="2.0.0", root_path="/api/v1/nac")
app.include_router(auth_router, prefix="/auth")

router = APIRouter()
log = get_logger("nac")

# Configuration
DATA_DIR = Path("/var/lib/secubox/nac")
DATA_DIR.mkdir(parents=True, exist_ok=True)
LEASES_FILE = Path("/var/lib/misc/dnsmasq.leases")
HISTORY_FILE = DATA_DIR / "history.json"
WEBHOOKS_FILE = DATA_DIR / "webhooks.json"
CLIENTS_META_FILE = DATA_DIR / "clients.json"
PARENTAL_FILE = Path("/etc/secubox/nac-parental.json")

NFT_TABLE = "inet secubox_nac"

# Zones → nftables set names
ZONES = {
    "lan": {"nft_set": "lan_allowed", "desc": "LAN principal", "color": "green"},
    "iot": {"nft_set": "iot_zone", "desc": "IoT isolé", "color": "orange"},
    "guest": {"nft_set": "guest_zone", "desc": "Invités", "color": "blue"},
    "quarantine": {"nft_set": "quarantine_zone", "desc": "Quarantaine", "color": "red"},
}


class StatsCache:
    """Thread-safe stats cache with TTL."""

    def __init__(self, ttl_seconds: int = 15):
        self.ttl = ttl_seconds
        self._cache: Dict[str, Any] = {}
        self._timestamps: Dict[str, float] = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            if key in self._cache:
                if time.time() - self._timestamps[key] < self.ttl:
                    return self._cache[key]
        return None

    def set(self, key: str, value: Any):
        with self._lock:
            self._cache[key] = value
            self._timestamps[key] = time.time()

    def clear(self):
        with self._lock:
            self._cache.clear()
            self._timestamps.clear()


stats_cache = StatsCache(ttl_seconds=15)


# Pydantic Models
class ZoneRequest(BaseModel):
    mac: str = Field(..., pattern="^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
    zone: str


class ParentalRule(BaseModel):
    mac: str
    block_until: str = "22:00"
    blocked_categories: List[str] = []
    enabled: bool = True


class UpdateClientRequest(BaseModel):
    mac: str
    hostname: str = ""
    zone: str = ""
    notes: str = ""


class UpdateZoneRequest(BaseModel):
    zone_id: str
    name: str = ""
    color: str = ""


class PolicyRequest(BaseModel):
    default_zone: str = "quarantine"
    auto_approve: bool = False
    quarantine_timeout: int = 0


class ApplyProfileRequest(BaseModel):
    profile_id: str


class WebhookConfig(BaseModel):
    url: str
    events: List[str] = Field(default=["client_joined", "client_moved", "client_banned", "alert"])
    secret: Optional[str] = None
    enabled: bool = True

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        if not v.startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")
        return v


# State
_monitoring_task: Optional[asyncio.Task] = None
_known_clients: set = set()


def _load_json(filepath: Path, default=None):
    """Load JSON file safely."""
    if filepath.exists():
        try:
            return json.loads(filepath.read_text())
        except Exception:
            pass
    return default if default is not None else []


def _save_json(filepath: Path, data):
    """Save JSON file safely."""
    filepath.parent.mkdir(parents=True, exist_ok=True)
    filepath.write_text(json.dumps(data, indent=2))


def _load_history() -> List[Dict[str, Any]]:
    return _load_json(HISTORY_FILE, [])


def _save_history(history: List[Dict[str, Any]]):
    history = history[-2000:]
    _save_json(HISTORY_FILE, history)


def _load_webhooks() -> List[Dict[str, Any]]:
    return _load_json(WEBHOOKS_FILE, [])


def _save_webhooks(webhooks: List[Dict[str, Any]]):
    _save_json(WEBHOOKS_FILE, webhooks)


def _load_clients_meta() -> Dict[str, Dict[str, Any]]:
    return _load_json(CLIENTS_META_FILE, {})


def _save_clients_meta(meta: Dict[str, Dict[str, Any]]):
    _save_json(CLIENTS_META_FILE, meta)


def _record_event(event: str, details: Optional[Dict] = None):
    """Record an event in history."""
    history = _load_history()
    entry = {
        "timestamp": datetime.now().isoformat(),
        "event": event,
        "details": details or {}
    }
    history.append(entry)
    _save_history(history)


async def _send_webhook(url: str, payload: Dict[str, Any], secret: Optional[str] = None):
    """Send webhook notification."""
    try:
        headers = {"Content-Type": "application/json"}
        body = json.dumps(payload)

        if secret:
            signature = hmac.new(
                secret.encode(),
                body.encode(),
                hashlib.sha256
            ).hexdigest()
            headers["X-SecuBox-Signature"] = f"sha256={signature}"

        async with httpx.AsyncClient(timeout=10.0) as client:
            await client.post(url, content=body, headers=headers)
    except Exception:
        pass


async def _notify_webhooks(event: str, data: Dict[str, Any]):
    """Send notifications to all webhooks for event."""
    webhooks = _load_webhooks()
    for webhook in webhooks:
        if webhook.get("enabled", True) and event in webhook.get("events", []):
            await _send_webhook(
                webhook["url"],
                {"event": event, "data": data, "timestamp": datetime.now().isoformat()},
                webhook.get("secret")
            )


def _parse_leases() -> list[dict]:
    """Parse /var/lib/misc/dnsmasq.leases → list of clients."""
    clients = []
    if not LEASES_FILE.exists():
        return clients
    for line in LEASES_FILE.read_text().splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        clients.append({
            "expiry": int(parts[0]),
            "mac": parts[1].lower(),
            "ip": parts[2],
            "hostname": parts[3] if parts[3] != "*" else "",
            "id": parts[4] if len(parts) > 4 else "",
        })
    return clients


def _nft_list_set(set_name: str) -> list[str]:
    """Return elements from an nftables set."""
    try:
        r = subprocess.run(
            ["nft", "-j", "list", "set", "inet", "secubox_nac", set_name],
            capture_output=True, text=True, timeout=5
        )
        data = json.loads(r.stdout)
        elements = []
        for item in data.get("nftables", []):
            if "set" in item:
                for e in item["set"].get("elem", []):
                    if isinstance(e, str):
                        elements.append(e.lower())
                    elif isinstance(e, dict):
                        elements.append(str(e.get("val", e)).lower())
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
    """Find a client's zone by MAC address."""
    mac_lower = mac.lower()
    for zone_id, zone_info in ZONES.items():
        if mac_lower in _nft_list_set(zone_info["nft_set"]):
            return zone_id
    return "quarantine"


async def _monitor_clients():
    """Background task to monitor new clients."""
    global _known_clients

    while True:
        try:
            leases = _parse_leases()
            current_macs = {c["mac"].lower() for c in leases}

            # Check for new clients
            new_clients = current_macs - _known_clients
            for mac in new_clients:
                client = next((c for c in leases if c["mac"].lower() == mac), None)
                if client:
                    _record_event("client_joined", {
                        "mac": mac,
                        "ip": client.get("ip"),
                        "hostname": client.get("hostname")
                    })
                    await _notify_webhooks("client_joined", {
                        "mac": mac,
                        "ip": client.get("ip"),
                        "hostname": client.get("hostname")
                    })

            _known_clients = current_macs

        except Exception:
            pass

        await asyncio.sleep(30)


@app.on_event("startup")
async def startup():
    """Start background monitoring."""
    global _monitoring_task, _known_clients
    # Initialize known clients
    leases = _parse_leases()
    _known_clients = {c["mac"].lower() for c in leases}
    _monitoring_task = asyncio.create_task(_monitor_clients())


@app.on_event("shutdown")
async def shutdown():
    """Stop background monitoring."""
    global _monitoring_task
    if _monitoring_task:
        _monitoring_task.cancel()


# Public endpoints
@router.get("/health")
async def health():
    return {"status": "ok", "module": "nac", "version": "2.0.0"}


@router.get("/status")
async def status(user=Depends(require_jwt)):
    """Get NAC status."""
    cached = stats_cache.get("status")
    if cached:
        return cached

    leases = _parse_leases()

    try:
        nft_ok = subprocess.run(
            ["nft", "list", "tables"],
            capture_output=True, timeout=5
        ).returncode == 0
    except Exception:
        nft_ok = False

    try:
        dnsmasq_ok = subprocess.run(
            ["pgrep", "dnsmasq"],
            capture_output=True, timeout=5
        ).returncode == 0
    except Exception:
        dnsmasq_ok = False

    # Count by zone
    by_zone: Dict[str, int] = {z: 0 for z in ZONES}
    for client in leases:
        zone = _get_client_zone(client["mac"])
        by_zone[zone] = by_zone.get(zone, 0) + 1

    result = {
        "client_count": len(leases),
        "nftables_ok": nft_ok,
        "dnsmasq_ok": dnsmasq_ok,
        "zones": list(ZONES.keys()),
        "by_zone": by_zone,
        "quarantine_count": by_zone.get("quarantine", 0),
        "timestamp": datetime.now().isoformat()
    }

    stats_cache.set("status", result)
    return result


@router.get("/clients")
async def clients(user=Depends(require_jwt)):
    """Get all clients with zone info."""
    cached = stats_cache.get("clients")
    if cached:
        return cached

    leases = _parse_leases()
    meta = _load_clients_meta()
    result = []

    for c in leases:
        mac = c["mac"].lower()
        zone = _get_client_zone(mac)
        client_meta = meta.get(mac, {})

        result.append({
            **c,
            "zone": zone,
            "zone_color": ZONES[zone]["color"],
            "zone_name": ZONES[zone]["desc"],
            "custom_hostname": client_meta.get("hostname", ""),
            "notes": client_meta.get("notes", ""),
            "first_seen": client_meta.get("first_seen"),
            "last_seen": datetime.now().isoformat()
        })

    response = {
        "clients": result,
        "count": len(result),
        "by_zone": {z: sum(1 for c in result if c["zone"] == z) for z in ZONES}
    }

    stats_cache.set("clients", response)
    return response


@router.get("/client/{mac}")
async def get_client(mac: str, user=Depends(require_jwt)):
    """Get details for a specific client."""
    leases = _parse_leases()
    meta = _load_clients_meta()
    mac_lower = mac.lower()

    for c in leases:
        if c["mac"].lower() == mac_lower:
            zone = _get_client_zone(mac_lower)
            client_meta = meta.get(mac_lower, {})

            # Get recent history
            history = _load_history()
            client_history = [
                h for h in history[-100:]
                if h.get("details", {}).get("mac", "").lower() == mac_lower
            ][-10:]

            return {
                **c,
                "zone": zone,
                "zone_color": ZONES[zone]["color"],
                "zone_name": ZONES[zone]["desc"],
                "custom_hostname": client_meta.get("hostname", ""),
                "notes": client_meta.get("notes", ""),
                "first_seen": client_meta.get("first_seen"),
                "recent_events": client_history
            }

    raise HTTPException(404, "Client not found")


@router.get("/zones")
async def zones(user=Depends(require_jwt)):
    """Get all zones with members."""
    result = []
    for zone_id, info in ZONES.items():
        members = _nft_list_set(info["nft_set"])
        result.append({
            "id": zone_id,
            "name": info["desc"],
            "color": info["color"],
            "nft_set": info["nft_set"],
            "members": members,
            "count": len(members),
        })
    return {"zones": result}


@router.post("/add_to_zone")
async def add_to_zone(req: ZoneRequest, user=Depends(require_jwt)):
    """Move a client to a zone."""
    if req.zone not in ZONES:
        raise HTTPException(400, f"Zone invalide: {req.zone}")

    mac_lower = req.mac.lower()
    old_zone = _get_client_zone(mac_lower)

    # Remove from all zones
    for zone_id, info in ZONES.items():
        _nft_delete_element(info["nft_set"], mac_lower)

    # Add to target zone
    try:
        _nft_add_element(ZONES[req.zone]["nft_set"], mac_lower)

        log.info("Client %s → zone %s (was %s)", mac_lower, req.zone, old_zone)
        _record_event("client_moved", {
            "mac": mac_lower,
            "from_zone": old_zone,
            "to_zone": req.zone,
            "by": user.get("sub", "unknown")
        })
        await _notify_webhooks("client_moved", {
            "mac": mac_lower,
            "from_zone": old_zone,
            "to_zone": req.zone
        })
        stats_cache.clear()

        return {"success": True, "mac": mac_lower, "zone": req.zone, "previous_zone": old_zone}
    except subprocess.CalledProcessError as e:
        raise HTTPException(500, f"nft error: {e}")


@router.post("/remove_from_zone")
async def remove_from_zone(mac: str, user=Depends(require_jwt)):
    """Remove client from all zones (to quarantine)."""
    mac_lower = mac.lower()
    old_zone = _get_client_zone(mac_lower)

    for info in ZONES.values():
        _nft_delete_element(info["nft_set"], mac_lower)

    _nft_add_element(ZONES["quarantine"]["nft_set"], mac_lower)

    _record_event("client_quarantined", {"mac": mac_lower, "from_zone": old_zone})
    stats_cache.clear()

    return {"success": True, "mac": mac_lower, "zone": "quarantine"}


@router.post("/approve_client")
async def approve_client(mac: str, zone: str = "lan", user=Depends(require_jwt)):
    """Approve a client (move from quarantine)."""
    return await add_to_zone(ZoneRequest(mac=mac, zone=zone), user)


@router.post("/ban_client")
async def ban_client(mac: str, user=Depends(require_jwt)):
    """Ban a client completely."""
    mac_lower = mac.lower()

    for info in ZONES.values():
        _nft_delete_element(info["nft_set"], mac_lower)

    try:
        subprocess.run(
            ["nft", "add", "element", "inet", "secubox_nac", "blocked", "{", mac_lower, "}"],
            capture_output=True, timeout=5
        )
    except Exception:
        pass

    log.info("Client banned: %s", mac_lower)
    _record_event("client_banned", {"mac": mac_lower, "by": user.get("sub", "unknown")})
    await _notify_webhooks("client_banned", {"mac": mac_lower})
    stats_cache.clear()

    return {"success": True, "mac": mac_lower, "status": "banned"}


@router.post("/unban_client")
async def unban_client(mac: str, user=Depends(require_jwt)):
    """Unban a client."""
    mac_lower = mac.lower()

    try:
        subprocess.run(
            ["nft", "delete", "element", "inet", "secubox_nac", "blocked", "{", mac_lower, "}"],
            capture_output=True, timeout=5
        )
    except Exception:
        pass

    _nft_add_element(ZONES["quarantine"]["nft_set"], mac_lower)
    _record_event("client_unbanned", {"mac": mac_lower, "by": user.get("sub", "unknown")})
    stats_cache.clear()

    return {"success": True, "mac": mac_lower, "status": "quarantine"}


@router.post("/update_client")
async def update_client(req: UpdateClientRequest, user=Depends(require_jwt)):
    """Update client metadata."""
    mac_lower = req.mac.lower()
    meta = _load_clients_meta()

    if mac_lower not in meta:
        meta[mac_lower] = {"first_seen": datetime.now().isoformat()}

    if req.hostname:
        meta[mac_lower]["hostname"] = req.hostname
    if req.notes:
        meta[mac_lower]["notes"] = req.notes

    _save_clients_meta(meta)

    if req.zone:
        await add_to_zone(ZoneRequest(mac=req.mac, zone=req.zone), user)

    _record_event("client_updated", {"mac": mac_lower})
    stats_cache.clear()

    return {"success": True, "mac": mac_lower}


# Parental controls
@router.get("/parental_rules")
async def parental_rules(user=Depends(require_jwt)):
    """Get parental control rules."""
    return {"rules": _load_json(PARENTAL_FILE, [])}


@router.post("/parental_rule")
async def set_parental_rule(req: ParentalRule, user=Depends(require_jwt)):
    """Set a parental control rule."""
    rules = _load_json(PARENTAL_FILE, [])
    rules = [r for r in rules if r.get("mac") != req.mac]
    rules.append(req.model_dump())
    _save_json(PARENTAL_FILE, rules)

    _record_event("parental_rule_set", {"mac": req.mac, "by": user.get("sub", "unknown")})

    return {"success": True, "rule": req.model_dump()}


@router.delete("/parental_rule/{mac}")
async def delete_parental_rule(mac: str, user=Depends(require_jwt)):
    """Delete a parental control rule."""
    rules = _load_json(PARENTAL_FILE, [])
    rules = [r for r in rules if r.get("mac") != mac]
    _save_json(PARENTAL_FILE, rules)

    _record_event("parental_rule_deleted", {"mac": mac})

    return {"success": True}


# Alerts
@router.get("/alerts")
async def alerts(user=Depends(require_jwt)):
    """Get current alerts."""
    quarantine = _nft_list_set("quarantine_zone")
    leases = _parse_leases()
    alerts_list = []

    for c in leases:
        if c["mac"].lower() in quarantine:
            alerts_list.append({
                "type": "new_client",
                "severity": "warning",
                "mac": c["mac"],
                "ip": c["ip"],
                "hostname": c["hostname"],
                "message": f"New client in quarantine: {c['hostname'] or c['mac']}"
            })

    return {"alerts": alerts_list, "count": len(alerts_list)}


# Policy
@router.get("/policy")
async def get_policy(user=Depends(require_jwt)):
    """Get NAC policy."""
    cfg = get_config("nac")
    return {
        "default_zone": cfg.get("default_zone", "quarantine") if cfg else "quarantine",
        "auto_approve": cfg.get("auto_approve", False) if cfg else False,
        "quarantine_timeout": cfg.get("quarantine_timeout", 0) if cfg else 0,
    }


@router.post("/policy")
async def set_policy(req: PolicyRequest, user=Depends(require_jwt)):
    """Set NAC policy."""
    log.info("set_policy: default_zone=%s auto_approve=%s", req.default_zone, req.auto_approve)
    _record_event("policy_changed", {"policy": req.model_dump(), "by": user.get("sub", "unknown")})
    return {"success": True, "policy": req.model_dump()}


# History
@router.get("/history")
async def get_history(limit: int = 100, mac: Optional[str] = None, user=Depends(require_jwt)):
    """Get NAC event history."""
    history = _load_history()

    if mac:
        history = [
            h for h in history
            if h.get("details", {}).get("mac", "").lower() == mac.lower()
        ]

    return {
        "events": history[-limit:],
        "total": len(history)
    }


@router.get("/logs")
async def logs(lines: int = 100, user=Depends(require_jwt)):
    """Get dnsmasq logs."""
    try:
        r = subprocess.run(
            ["journalctl", "-u", "dnsmasq", "-n", str(min(lines, 500)), "--no-pager", "-o", "short"],
            capture_output=True, text=True, timeout=10
        )
        return {"lines": r.stdout.splitlines(), "count": len(r.stdout.splitlines())}
    except Exception as e:
        return {"lines": [], "error": str(e)}


# Webhooks
@router.get("/webhooks")
async def list_webhooks(user=Depends(require_jwt)):
    return {"webhooks": _load_webhooks()}


@router.post("/webhooks")
async def add_webhook(webhook: WebhookConfig, user=Depends(require_jwt)):
    webhooks = _load_webhooks()
    webhook_data = webhook.model_dump()
    webhook_data["id"] = hashlib.md5(webhook.url.encode()).hexdigest()[:8]
    webhook_data["created_at"] = datetime.now().isoformat()
    webhooks.append(webhook_data)
    _save_webhooks(webhooks)
    return {"success": True, "webhook": webhook_data}


@router.delete("/webhooks/{webhook_id}")
async def delete_webhook(webhook_id: str, user=Depends(require_jwt)):
    webhooks = _load_webhooks()
    webhooks = [w for w in webhooks if w.get("id") != webhook_id]
    _save_webhooks(webhooks)
    return {"success": True}


@router.get("/summary")
async def summary(user=Depends(require_jwt)):
    """Get NAC summary."""
    status_info = await status(user)
    alerts_info = await alerts(user)

    return {
        "clients": {
            "total": status_info["client_count"],
            "by_zone": status_info["by_zone"],
            "quarantine": status_info["quarantine_count"]
        },
        "infrastructure": {
            "nftables": status_info["nftables_ok"],
            "dnsmasq": status_info["dnsmasq_ok"]
        },
        "alerts": {
            "count": alerts_info["count"]
        },
        "parental_rules": len(_load_json(PARENTAL_FILE, [])),
        "recent_events": _load_history()[-5:],
        "webhooks_configured": len(_load_webhooks()),
        "timestamp": datetime.now().isoformat()
    }


# Compatibility aliases
@router.get("/portal_config")
async def portal_config(user=Depends(require_jwt)):
    cfg = get_config("nac")
    return {
        "default_zone": cfg.get("default_zone", "quarantine") if cfg else "quarantine",
        "dhcp_range": cfg.get("dhcp_range", "") if cfg else "",
        "dns_servers": cfg.get("dns_servers", []) if cfg else [],
        "portal_enabled": True,
    }


@router.get("/parental")
async def parental(user=Depends(require_jwt)):
    return await parental_rules(user)


@router.post("/quarantine_client")
async def quarantine_client(mac: str, user=Depends(require_jwt)):
    return await add_to_zone(ZoneRequest(mac=mac, zone="quarantine"), user)


@router.get("/get_client")
async def get_client_compat(mac: str, user=Depends(require_jwt)):
    return await get_client(mac, user)


@router.get("/get_policy")
async def get_policy_compat(user=Depends(require_jwt)):
    return await get_policy(user)


@router.post("/set_policy")
async def set_policy_compat(req: PolicyRequest, user=Depends(require_jwt)):
    return await set_policy(req, user)


@router.post("/set_parental_rule")
async def set_parental_rule_compat(req: ParentalRule, user=Depends(require_jwt)):
    return await set_parental_rule(req, user)


@router.get("/sync_zones")
async def sync_zones(user=Depends(require_jwt)):
    for zone_id, info in ZONES.items():
        subprocess.run(
            ["nft", "add", "set", "inet", "secubox_nac", info["nft_set"],
             "{ type ether_addr; }"],
            capture_output=True
        )
    return {"success": True, "zones": list(ZONES.keys())}


@router.get("/list_profiles")
async def list_profiles(user=Depends(require_jwt)):
    return {"profiles": [
        {"id": "home", "name": "Maison", "description": "Config maison simple"},
        {"id": "small_business", "name": "PME", "description": "Petite entreprise"},
        {"id": "hotspot", "name": "Hotspot", "description": "Point d'accès public"},
    ]}


@router.post("/apply_profile")
async def apply_profile(req: ApplyProfileRequest, user=Depends(require_jwt)):
    log.info("apply_profile: %s", req.profile_id)
    _record_event("profile_applied", {"profile": req.profile_id, "by": user.get("sub", "unknown")})
    return {"success": True, "profile": req.profile_id}


@router.get("/send_test_alert")
async def send_test_alert(user=Depends(require_jwt)):
    await _notify_webhooks("alert", {"type": "test", "message": "Test alert"})
    return {"success": True, "message": "Test alert sent"}


@router.post("/update_zone")
async def update_zone(req: UpdateZoneRequest, user=Depends(require_jwt)):
    log.info("update_zone: %s", req.zone_id)
    return {"success": True, "zone": req.zone_id}


app.include_router(router)
