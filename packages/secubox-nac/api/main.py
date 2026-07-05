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

from .collector import Collector
from .enrich import load_oui
from .store import DeviceStore, canon_mac, migrate_legacy

app = FastAPI(title="secubox-nac", version="2.0.0", root_path="/api/v1/nac")

# ══════════════════════════════════════════════════════════════════
# Health Check Endpoint (public, no auth)
# ══════════════════════════════════════════════════════════════════

@app.get("/health")
async def health_check():
    """Public health check endpoint for sidebar status."""
    return {"status": "ok", "module": "deb"}

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

# #817 Task 4: canonical SQLite device store + legacy migration sources.
DEVICES_DB_PATH = str(DATA_DIR / "devices.db")
MACGUARD_DEVICES_JSON = "/var/lib/secubox/mac-guard/devices.json"
DEVICEINTEL_DEVICES_JSON = "/var/lib/secubox/device-intel/devices.json"
IOTGUARD_DEVICES_DB = "/var/lib/secubox/iot-guard/devices.db"
COLLECTOR_INTERVAL = 30

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

# #817 Task 4: canonical store + background collector (replaces
# `_discover_clients()`-per-request + `_monitor_clients()`). Populated at
# `startup`; `status`/`clients`/`client/{mac}` read them as plain `def`
# handlers — never re-run discovery inline (that was the aggregator
# SPOF, #808).
store: Optional[DeviceStore] = None
collector: Optional[Collector] = None


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
            "source": "dhcp",
        })
    return clients


# Interfaces to scan for ARP entries (LAN interfaces only)
LAN_INTERFACES = {"lan0", "lan1", "lan2", "lan3", "br0", "br-lan", "eth0", "eth1"}


def _parse_arp() -> list[dict]:
    """Parse ARP table for network clients (fallback when DHCP leases unavailable)."""
    clients = []
    try:
        # Use ip neigh for more reliable ARP parsing
        r = subprocess.run(
            ["ip", "neigh", "show"],
            capture_output=True, text=True, timeout=5
        )
        if r.returncode != 0:
            return clients

        for line in r.stdout.splitlines():
            # Format: IP dev IFACE lladdr MAC STATE
            # Example: 192.168.1.36 dev lan0 lladdr 92:83:c4:29:7d:47 REACHABLE
            parts = line.split()
            if len(parts) < 5:
                continue

            ip = parts[0]
            iface = parts[2] if len(parts) > 2 and parts[1] == "dev" else ""
            mac = ""
            state = ""

            # Find lladdr and state
            for i, part in enumerate(parts):
                if part == "lladdr" and i + 1 < len(parts):
                    mac = parts[i + 1].lower()
                if part in ("REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT"):
                    state = part

            # Skip if no MAC, failed entries, or non-LAN interfaces
            if not mac or state == "FAILED":
                continue

            # Only include clients from LAN interfaces
            if iface and iface not in LAN_INTERFACES:
                continue

            # Skip IPv6 link-local
            if ip.startswith("fe80:"):
                continue

            # Skip local/router IPs (common gateway patterns)
            if ip.endswith(".1") or ip.endswith(".254"):
                continue

            clients.append({
                "expiry": 0,  # ARP doesn't have expiry
                "mac": mac,
                "ip": ip,
                "hostname": "",  # ARP doesn't provide hostname
                "id": "",
                "source": "arp",
                "state": state,
                "interface": iface,
            })
    except Exception as e:
        log.warning("ARP parsing failed: %s", e)

    return clients


def _discover_clients() -> list[dict]:
    """Discover network clients from multiple sources (DHCP leases + ARP fallback)."""
    # Primary: DHCP leases
    clients = _parse_leases()

    # If leases file is empty/missing, fall back to ARP
    if not clients:
        clients = _parse_arp()
        if clients:
            log.info("Using ARP discovery: found %d clients (DHCP leases empty)", len(clients))
    else:
        # Merge ARP data for additional info (like STALE/REACHABLE state)
        arp_clients = {c["mac"]: c for c in _parse_arp()}
        for client in clients:
            arp_info = arp_clients.get(client["mac"])
            if arp_info:
                client["state"] = arp_info.get("state", "")
                client["interface"] = arp_info.get("interface", "")

    # Deduplicate by MAC
    seen_macs = set()
    unique_clients = []
    for c in clients:
        if c["mac"] not in seen_macs:
            seen_macs.add(c["mac"])
            unique_clients.append(c)

    return unique_clients


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


# Zone assignments file (fallback when nftables not available)
ZONE_ASSIGNMENTS_FILE = DATA_DIR / "zone_assignments.json"


def _load_zone_assignments() -> Dict[str, str]:
    """Load zone assignments from file."""
    return _load_json(ZONE_ASSIGNMENTS_FILE, {})


def _save_zone_assignments(assignments: Dict[str, str]):
    """Save zone assignments to file."""
    _save_json(ZONE_ASSIGNMENTS_FILE, assignments)


def _nft_add_element(set_name: str, element: str) -> bool:
    """Add element to nft set. Returns True if successful."""
    try:
        result = subprocess.run(
            ["nft", "add", "element", "inet", "secubox_nac", set_name, "{", element, "}"],
            capture_output=True, timeout=5
        )
        return result.returncode == 0
    except Exception:
        return False


def _nft_delete_element(set_name: str, element: str) -> bool:
    """Delete element from nft set. Returns True if successful."""
    try:
        result = subprocess.run(
            ["nft", "delete", "element", "inet", "secubox_nac", set_name, "{", element, "}"],
            capture_output=True, timeout=5
        )
        return result.returncode == 0
    except Exception:
        return False


def _get_client_zone(mac: str) -> str:
    """Find a client's zone by MAC address (checks nft sets + JSON fallback)."""
    mac_lower = mac.lower()

    # First check nft sets
    for zone_id, zone_info in ZONES.items():
        if mac_lower in _nft_list_set(zone_info["nft_set"]):
            return zone_id

    # Fallback to JSON assignments
    assignments = _load_zone_assignments()
    if mac_lower in assignments:
        return assignments[mac_lower]

    return "quarantine"


def _set_client_zone(mac: str, zone: str):
    """Set client zone in both nft and JSON fallback."""
    mac_lower = mac.lower()

    # Remove from all nft sets
    for zone_info in ZONES.values():
        _nft_delete_element(zone_info["nft_set"], mac_lower)

    # Add to target nft set (may fail if table doesn't exist)
    if zone in ZONES:
        _nft_add_element(ZONES[zone]["nft_set"], mac_lower)

    # Always update JSON fallback
    assignments = _load_zone_assignments()
    assignments[mac_lower] = zone
    _save_zone_assignments(assignments)


def _fire_collector_webhook(event: str, dev: Dict[str, Any]) -> None:
    """`Collector._emit` override: schedule the existing async webhook
    fire-and-forget without blocking `cycle_once()` (which is sync and
    may run outside a request context). Only called from within
    `run_forever()`, which is always executing on the running loop, so
    `asyncio.create_task` is safe here.
    """
    payload = {"mac": dev.get("mac"), "ip": dev.get("ip"), "hostname": dev.get("hostname")}
    try:
        asyncio.create_task(_notify_webhooks(event, payload))
    except RuntimeError:
        # No running loop (e.g. collector driven outside FastAPI) — drop.
        pass


@app.on_event("startup")
async def startup():
    """Build the canonical device store + background collector (#817 Task 4).

    Replaces the old `_discover_clients()`-per-request pattern and the
    `_monitor_clients()` task: one background `Collector.run_forever()`
    loop now owns all discovery/enrich/upsert work, and handlers read
    its double-cache (`collector.snapshot()`) or the SQLite store
    instead of scanning inline on every request.
    """
    global _monitoring_task, store, collector

    store = DeviceStore(DEVICES_DB_PATH)

    try:
        migration = migrate_legacy(
            store,
            macguard_json=MACGUARD_DEVICES_JSON,
            deviceintel_json=DEVICEINTEL_DEVICES_JSON,
            iot_db=IOTGUARD_DEVICES_DB,
        )
        log.info(
            "NAC startup: legacy migration imported=%d skipped=%d",
            migration.get("imported", 0), migration.get("skipped", 0),
        )
    except Exception:
        # Migration must never abort boot — a corrupt/missing legacy
        # source is logged and the collector still starts.
        log.exception("NAC startup: legacy migration failed (non-fatal)")

    oui_map = load_oui()
    collector = Collector(store, oui_map, interval=COLLECTOR_INTERVAL)
    collector._emit = _fire_collector_webhook

    log.info("NAC startup: device store at %s, %d device(s) known", DEVICES_DB_PATH, store.count())
    _monitoring_task = asyncio.create_task(collector.run_forever())


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
def status(user=Depends(require_jwt)):
    """Get NAC status.

    #817 Task 4: reads the SQLite store + the collector's double-cache
    instead of calling `_discover_clients()` inline — that blocking
    subprocess-heavy scan on every request was the aggregator SPOF
    (#808). Plain `def` so FastAPI threadpools it.
    """
    cached = stats_cache.get("status")
    if cached:
        return cached

    devices = store.list(limit=5000) if store else []
    online_macs = {d["mac"] for d in (collector.snapshot() if collector else [])}

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
    for device in devices:
        zone = _get_client_zone(device["mac"])
        by_zone[zone] = by_zone.get(zone, 0) + 1

    # Count online clients (present in the latest completed collector cycle)
    online_count = sum(1 for d in devices if d["mac"] in online_macs)

    result = {
        "client_count": len(devices),
        "total_clients": len(devices),  # Alias for frontend compatibility
        "online_count": online_count,
        "online": online_count,  # Alias for frontend compatibility
        "nftables_ok": nft_ok,
        "dnsmasq_ok": dnsmasq_ok,
        "zones": list(ZONES.keys()),
        "by_zone": by_zone,
        "quarantine_count": by_zone.get("quarantine", 0),
        "quarantined": by_zone.get("quarantine", 0),  # Alias for frontend compatibility
        "timestamp": datetime.now().isoformat()
    }

    stats_cache.set("status", result)
    return result


@router.get("/clients")
def clients(user=Depends(require_jwt)):
    """Get all known clients with zone info.

    #817 Task 4: reads the SQLite store (populated by the background
    `Collector`) instead of scanning DHCP leases/ARP inline on every
    request. Plain `def` so FastAPI threadpools it.
    """
    cached = stats_cache.get("clients")
    if cached:
        return cached

    devices = store.list(limit=5000) if store else []
    online_macs = {d["mac"] for d in (collector.snapshot() if collector else [])}
    meta = _load_clients_meta()
    result = []

    for d in devices:
        mac = d["mac"]
        zone = _get_client_zone(mac)
        client_meta = meta.get(mac, {})

        is_online = mac in online_macs
        # Status for frontend badge
        if zone == "quarantine":
            status = "quarantine"
        elif zone == "lan":
            status = "enabled" if is_online else "disabled"
        else:
            status = zone

        result.append({
            **d,
            "zone": zone,
            "zone_color": ZONES[zone]["color"],
            "zone_name": ZONES[zone]["desc"],
            "custom_hostname": client_meta.get("hostname", ""),
            "notes": client_meta.get("notes") or d.get("notes") or "",
            "first_seen": client_meta.get("first_seen") or d.get("first_seen"),
            "online": is_online,
            "status": status,  # For frontend badge
        })

    response = {
        "clients": result,
        "count": len(result),
        "by_zone": {z: sum(1 for c in result if c["zone"] == z) for z in ZONES}
    }

    stats_cache.set("clients", response)
    return response


@router.get("/client/{mac}")
def get_client(mac: str, user=Depends(require_jwt)):
    """Get details for a specific client.

    #817 Task 4: reads the SQLite store instead of re-scanning
    `_discover_clients()` inline. Plain `def` so FastAPI threadpools it.
    """
    mac_lower = canon_mac(mac) or mac.lower()
    d = store.get(mac_lower) if store else None
    if not d:
        raise HTTPException(404, "Client not found")

    zone = _get_client_zone(mac_lower)
    meta = _load_clients_meta()
    client_meta = meta.get(mac_lower, {})

    # Recent history: merge the JSON event log (client_moved/banned/etc,
    # still written by `_record_event`) with the SQLite `device_history`
    # events the collector writes directly (`client_joined`, see Task 4
    # Collector.cycle_once) — #817 Minor fix 2, so a device's join event
    # shows up here again instead of being silently dropped.
    history = _load_history()
    json_events = [
        h for h in history[-200:]
        if h.get("details", {}).get("mac", "").lower() == mac_lower
    ]
    sqlite_events = [
        {
            "timestamp": datetime.fromtimestamp(h["ts"]).isoformat(),
            "event": h["event"],
            "details": {"mac": mac_lower, "detail": h.get("detail", "")},
        }
        for h in (store.history(mac_lower, limit=20) if store else [])
    ]
    client_history = sorted(
        json_events + sqlite_events,
        key=lambda h: h.get("timestamp", ""),
        reverse=True,
    )[:10]

    return {
        **d,
        "zone": zone,
        "zone_color": ZONES[zone]["color"],
        "zone_name": ZONES[zone]["desc"],
        "custom_hostname": client_meta.get("hostname", ""),
        "notes": client_meta.get("notes") or d.get("notes") or "",
        "first_seen": client_meta.get("first_seen") or d.get("first_seen"),
        "recent_events": client_history
    }


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

    # Set client zone (handles both nft and JSON fallback)
    _set_client_zone(mac_lower, req.zone)

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
def unban_client(mac: str, user=Depends(require_jwt)):
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
def alerts(user=Depends(require_jwt)):
    """Get current alerts.

    #817 Task 4 fix (#808): converted from `async def` — the previous
    body called blocking `_discover_clients()` inline on the shared
    aggregator loop. Now reads the SQLite store (populated by the
    background `Collector`) and is a plain `def`, so FastAPI threadpools
    it off the loop.
    """
    quarantine = _nft_list_set("quarantine_zone")
    devices = store.list(limit=5000) if store else []
    alerts_list = []

    for d in devices:
        mac = d["mac"]
        if mac in quarantine:
            alerts_list.append({
                "type": "new_client",
                "severity": "warning",
                "mac": mac,
                "ip": d.get("ip"),
                "hostname": d.get("hostname"),
                "message": f"New client in quarantine: {d.get('hostname') or mac}"
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
def logs(lines: int = 100, user=Depends(require_jwt)):
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
def summary(user=Depends(require_jwt)):
    """Get NAC summary.

    #817 Task 4 fix (#808): converted from `async def` to plain `def` —
    it only calls other now-`def` handlers (`status`, `alerts`), which
    FastAPI threadpools off the shared aggregator loop, so no `await` is
    needed (or valid) here anymore.
    """
    status_info = status(user)
    alerts_info = alerts(user)

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


@router.get("/quarantine")
def list_quarantine(user=Depends(require_jwt)):
    """List all quarantined clients (frontend compatibility endpoint).

    #817 Task 4 fix (#808): converted from `async def` — the previous
    body called blocking `_discover_clients()` inline on the shared
    aggregator loop. Now reads the SQLite store instead and is a plain
    `def`, so FastAPI threadpools it off the loop.
    """
    devices = store.list(limit=5000) if store else []
    meta = _load_clients_meta()

    clients = []
    for d in devices:
        mac = d["mac"]
        zone = _get_client_zone(mac)
        if zone == "quarantine":
            client_meta = meta.get(mac, {})
            clients.append({
                "mac": mac,
                "ip": d.get("ip", ""),
                "hostname": d.get("hostname", "") or client_meta.get("hostname", ""),
                "reason": "New device" if not client_meta.get("first_seen") else "Quarantined",
                "since": client_meta.get("first_seen", datetime.now().isoformat()),
            })

    return {"clients": clients, "count": len(clients)}


@router.post("/quarantine_client")
async def quarantine_client(mac: str, user=Depends(require_jwt)):
    return await add_to_zone(ZoneRequest(mac=mac, zone="quarantine"), user)


class MacRequest(BaseModel):
    mac: str


@router.post("/unquarantine")
async def unquarantine(req: MacRequest, user=Depends(require_jwt)):
    """Move client from quarantine to LAN (frontend compatibility endpoint)."""
    return await add_to_zone(ZoneRequest(mac=req.mac, zone="lan"), user)


@router.get("/get_client")
async def get_client_compat(mac: str, user=Depends(require_jwt)):
    return get_client(mac, user)  # plain def (#817 Task 4) — no await


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
def sync_zones(user=Depends(require_jwt)):
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
