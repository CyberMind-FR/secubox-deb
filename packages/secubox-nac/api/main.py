"""SecuBox NAC API - Network Access Control with Enhanced Monitoring

Port of luci-app-client-guardian with production features.
Manages client zones, parental controls, and network policies.
"""
from __future__ import annotations
import csv
import io
import ipaddress
import re
import subprocess
import json
import threading
import time
import uuid
import asyncio
import hashlib
import hmac
import httpx
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, Field, field_validator
from secubox_core.auth import router as auth_router, require_jwt
from secubox_core.config import get_config
from secubox_core.logger import get_logger

from .collector import Collector
from .enrich import classify_device_type, load_oui, openwrt_fingerprint, oui_vendor, risk_score
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

# #817 Task 5 (finishing #808): the main event loop, captured at
# `startup`, so plain `def` action handlers — threadpooled off that loop
# by FastAPI — can fire-and-forget `_notify_webhooks` via
# `asyncio.run_coroutine_threadsafe` instead of `await`ing it (which
# would be a SyntaxError in a non-async function).
_main_loop: Optional[asyncio.AbstractEventLoop] = None

# #817 Task 4: canonical store + background collector (replaces
# `_discover_clients()`-per-request + `_monitor_clients()`). Populated at
# `startup`; `status`/`clients`/`client/{mac}` read them as plain `def`
# handlers — never re-run discovery inline (that was the aggregator
# SPOF, #808).
store: Optional[DeviceStore] = None
collector: Optional[Collector] = None

# #817 Task 6: OUI vendor map, also exposed at module level (not just
# captured in the Collector's closure) so `/vendors` can read it directly.
oui_map: Optional[Dict[str, str]] = None

# #817 whole-branch fix (C1): on the board, `/api/v1/nac` is served by the
# AGGREGATOR in-process (nac is in aggregator.toml; its own service is
# inactive). The aggregator does NOT run mounted sub-apps'
# `@app.on_event("startup")`, so the store/collector/migration would never
# init and the whole feature would be inert. These two flags let an
# idempotent lazy initializer (`_do_init`) + an HTTP middleware bring the
# feature up on the first request under EITHER mount (aggregator or nac's
# own uvicorn), without double-initializing.
_initialized: bool = False
_collector_started: bool = False


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


def _zone_map() -> Dict[str, str]:
    """Build a `mac -> zone` dict by listing each of the 4 zone nft sets
    ONCE (+ the JSON fallback read once), instead of the per-device
    `_get_client_zone` (which lists every set for every device).

    #817 whole-branch fix (I3): `status`/`clients`/`list_quarantine` iterate
    the whole store (~280 devices on the merged board). Calling
    `_get_client_zone(mac)` per device meant ~280×4 ≈ 1120 `nft list set`
    subprocesses per request. This lists each set once (4 subprocesses)
    and resolves every device's zone from the resulting dict.

    Resolution order matches `_get_client_zone`: an nft-set membership wins
    over the JSON fallback, and among nft sets the first zone in `ZONES`
    order wins (so the map never disagrees with the per-device helper).
    Devices absent from every set/assignment default to "quarantine" at
    lookup time (`.get(mac, "quarantine")`).
    """
    nft_assigned: Dict[str, str] = {}
    for zone_id, zone_info in ZONES.items():
        for mac in _nft_list_set(zone_info["nft_set"]):
            m = mac.lower()
            if m not in nft_assigned:  # first zone in ZONES order wins
                nft_assigned[m] = zone_id

    mapping: Dict[str, str] = {}
    for mac, zone in _load_zone_assignments().items():
        mapping[mac.lower()] = zone
    mapping.update(nft_assigned)  # nft wins over JSON fallback
    return mapping


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


def _fire_webhook_sync(event: str, data: Dict[str, Any]) -> None:
    """Fire `_notify_webhooks` from a plain `def` action handler (#817
    Task 5, finishing #808).

    Plain `def` handlers are threadpooled off the main event loop by
    FastAPI, so there is no running loop in the calling thread to
    `await` on — only `asyncio.run_coroutine_threadsafe` against the
    loop captured at `startup` is safe here. Fire-and-forget, mirrors
    `_fire_collector_webhook`; never blocks the handler nor raises.
    """
    if _main_loop is None:
        return
    try:
        asyncio.run_coroutine_threadsafe(_notify_webhooks(event, data), _main_loop)
    except RuntimeError:
        pass


def _do_init() -> None:
    """Idempotent, synchronous feature init (#817 whole-branch fix C1).

    Builds the canonical device store, runs the one-shot legacy migration
    (wrapped so a corrupt/missing source never aborts), loads the OUI map,
    and constructs the background `Collector`. Guarded by `_initialized`
    so it is a no-op after the first successful call — safe to invoke from
    `startup()` (nac's own uvicorn) AND from the HTTP middleware (the
    in-aggregator mount, whose `startup` event never fires). Does NOT
    start the collector task: that needs the running loop and is done by
    whichever entrypoint holds it (`startup`/middleware).
    """
    global store, collector, oui_map, _initialized
    if _initialized:
        return

    store = DeviceStore(DEVICES_DB_PATH)

    try:
        migration = migrate_legacy(
            store,
            macguard_json=MACGUARD_DEVICES_JSON,
            deviceintel_json=DEVICEINTEL_DEVICES_JSON,
            iot_db=IOTGUARD_DEVICES_DB,
        )
        log.info(
            "NAC init: legacy migration imported=%d skipped=%d",
            migration.get("imported", 0), migration.get("skipped", 0),
        )
    except Exception:
        # Migration must never abort boot — a corrupt/missing legacy
        # source is logged and the collector still starts.
        log.exception("NAC init: legacy migration failed (non-fatal)")

    oui_map = load_oui()
    collector = Collector(store, oui_map, interval=COLLECTOR_INTERVAL)
    collector._emit = _fire_collector_webhook

    _initialized = True
    log.info("NAC init: device store at %s, %d device(s) known", DEVICES_DB_PATH, store.count())


def _ensure_collector_started() -> None:
    """Capture the running loop and start the collector task exactly once.

    #817 whole-branch fix (C1): MUST be called from the loop thread (the
    `startup` coroutine or the HTTP middleware) — `asyncio.get_running_loop`
    and `asyncio.create_task` are invalid in the threadpool threads that
    run the plain-`def` handlers. Guarded by `_collector_started`.
    """
    global _monitoring_task, _main_loop, _collector_started
    if _collector_started or collector is None:
        return
    _main_loop = asyncio.get_running_loop()
    _monitoring_task = asyncio.create_task(collector.run_forever())
    _collector_started = True


@app.middleware("http")
async def _lazy_init_middleware(request, call_next):
    """Initialize the feature on the first request (#817 whole-branch C1).

    Under the aggregator's in-process mount, `@app.on_event("startup")`
    never fires, so without this the store/collector/migration would never
    init and every handler would return empty. This middleware runs on the
    loop thread, so it can both `_do_init()` (idempotent) and start the
    collector task via `_ensure_collector_started()`. Under nac's own
    uvicorn, `startup()` already did both and both are no-ops here.
    """
    if not _initialized:
        _do_init()
    _ensure_collector_started()
    return await call_next(request)


@app.on_event("startup")
async def startup():
    """Own-service path: init the feature + start the collector (#817 Task 4).

    Delegates to the shared idempotent `_do_init()` / `_ensure_collector_started()`
    so nac's own uvicorn and the in-aggregator mount take the exact same
    code path (the latter via `_lazy_init_middleware`).
    """
    _do_init()
    _ensure_collector_started()


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

    # Count by zone — #817 whole-branch fix (I3): one batched `_zone_map()`
    # (4 `nft list set` calls) instead of `_get_client_zone` per device.
    zmap = _zone_map()
    by_zone: Dict[str, int] = {z: 0 for z in ZONES}
    for device in devices:
        zone = zmap.get(device["mac"], "quarantine")
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
def clients(
    device_type: Optional[str] = None,
    risk_min: Optional[int] = None,
    user=Depends(require_jwt),
):
    """Get all known clients with zone info.

    #817 Task 4: reads the SQLite store (populated by the background
    `Collector`) instead of scanning DHCP leases/ARP inline on every
    request. Plain `def` so FastAPI threadpools it.

    #817 Task 6: `?device_type=`/`?risk_min=` are forwarded straight to
    `store.list()`'s indexed filters (device-intel/iot-guard absorption).
    The 15s stats cache is keyed on the unfiltered call only — a filtered
    request always re-queries the store (still a short indexed SQLite
    query, not a rescan) so two different filters never collide on one
    cache slot.
    """
    use_cache = device_type is None and risk_min is None
    if use_cache:
        cached = stats_cache.get("clients")
        if cached:
            return cached

    devices = store.list(device_type=device_type, risk_min=risk_min, limit=5000) if store else []
    online_macs = {d["mac"] for d in (collector.snapshot() if collector else [])}
    meta = _load_clients_meta()
    # #817 whole-branch fix (I3): batched zone lookup, once per request.
    zmap = _zone_map()
    result = []

    for d in devices:
        mac = d["mac"]
        zone = zmap.get(mac, "quarantine")
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

    if use_cache:
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
def zones(user=Depends(require_jwt)):
    """Get all zones with members.

    #817 Task 5 fix (#808): converted from `async def` — `_nft_list_set`
    is a blocking `subprocess.run` call; plain `def` lets FastAPI
    threadpool it off the shared aggregator loop.
    """
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
def add_to_zone(req: ZoneRequest, user=Depends(require_jwt)):
    """Move a client to a zone.

    #817 Task 5 fix (#808): converted from `async def` — `_get_client_zone`
    / `_set_client_zone` are blocking `subprocess.run` calls; plain `def`
    lets FastAPI threadpool it off the shared aggregator loop. The
    webhook notify can no longer be `await`ed from a non-async function,
    so it is fired via `_fire_webhook_sync` (schedules onto the main
    loop captured at startup, fire-and-forget — same event, same
    payload, just no longer blocking the handler on the HTTP POST).
    """
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
    _fire_webhook_sync("client_moved", {
        "mac": mac_lower,
        "from_zone": old_zone,
        "to_zone": req.zone
    })
    stats_cache.clear()

    return {"success": True, "mac": mac_lower, "zone": req.zone, "previous_zone": old_zone}


@router.post("/remove_from_zone")
def remove_from_zone(mac: str, user=Depends(require_jwt)):
    """Remove client from all zones (to quarantine).

    #817 Task 5 fix (#808): converted from `async def` — `_get_client_zone`
    / `_nft_*` are blocking `subprocess.run` calls; plain `def` lets
    FastAPI threadpool it off the shared aggregator loop.
    """
    mac_lower = mac.lower()
    old_zone = _get_client_zone(mac_lower)

    for info in ZONES.values():
        _nft_delete_element(info["nft_set"], mac_lower)

    _nft_add_element(ZONES["quarantine"]["nft_set"], mac_lower)

    _record_event("client_quarantined", {"mac": mac_lower, "from_zone": old_zone})
    stats_cache.clear()

    return {"success": True, "mac": mac_lower, "zone": "quarantine"}


@router.post("/approve_client")
def approve_client(mac: str, zone: str = "lan", user=Depends(require_jwt)):
    """Approve a client (move from quarantine).

    #817 Task 5 fix (#808): converted from `async def` — it only delegates
    to `add_to_zone`, which is now plain `def` too, so the `await` on it
    is no longer valid (or needed).
    """
    return add_to_zone(ZoneRequest(mac=mac, zone=zone), user)


@router.post("/ban_client")
def ban_client(mac: str, user=Depends(require_jwt)):
    """Ban a client completely.

    #817 Task 5 fix (#808): converted from `async def` — the body is all
    blocking `subprocess.run`/`_nft_*` calls; plain `def` lets FastAPI
    threadpool it off the shared aggregator loop. The webhook notify is
    fired via `_fire_webhook_sync` instead of `await`ed (see `add_to_zone`).
    """
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
    _fire_webhook_sync("client_banned", {"mac": mac_lower})
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


@router.post("/deny/{mac}")
def deny(mac: str, user=Depends(require_jwt)):
    """Deny a client — mac-guard `allow_state` absorption (#817 Task 5).

    Sets `allow_state="deny"` in the canonical SQLite store and mirrors
    it into nft on nac's existing `inet secubox_nac` table: add the MAC
    to `blocked` and remove it from `lan_allowed`. Reuses `_nft_add_element`
    / `_nft_delete_element` — mac-guard's separate `inet secubox_mac_guard`
    table is retired; migrating its elements into `secubox_nac` is
    Task 9, not here. Plain `def` (#808): all work below is blocking
    subprocess/SQLite, threadpooled off the shared aggregator loop.
    """
    mac_lower = canon_mac(mac) or mac.lower()

    _nft_add_element("blocked", mac_lower)
    _nft_delete_element("lan_allowed", mac_lower)

    if store:
        store.upsert({"mac": mac_lower, "allow_state": "deny"})
        store.record_event(mac_lower, "client_denied")

    _record_event("client_denied", {"mac": mac_lower, "by": user.get("sub", "unknown")})
    stats_cache.clear()

    return {"success": True, "mac": mac_lower, "allow_state": "deny"}


@router.post("/allow/{mac}")
def allow(mac: str, user=Depends(require_jwt)):
    """Allow a client — mac-guard `allow_state` absorption (#817 Task 5).

    Sets `allow_state="allow"` in the canonical SQLite store and mirrors
    it into nft: remove the MAC from `blocked` and add it to `lan_allowed`.
    Reverse of `deny`; see its docstring for the nft-table/migration notes.
    """
    mac_lower = canon_mac(mac) or mac.lower()

    _nft_delete_element("blocked", mac_lower)
    _nft_add_element("lan_allowed", mac_lower)

    if store:
        store.upsert({"mac": mac_lower, "allow_state": "allow"})
        store.record_event(mac_lower, "client_allowed")

    _record_event("client_allowed", {"mac": mac_lower, "by": user.get("sub", "unknown")})
    stats_cache.clear()

    return {"success": True, "mac": mac_lower, "allow_state": "allow"}


@router.post("/update_client")
def update_client(req: UpdateClientRequest, user=Depends(require_jwt)):
    """Update client metadata.

    #817 Task 5 fix (#808): converted from `async def` — it delegates to
    `add_to_zone`, which is now plain `def` too, so the `await` on it is
    no longer valid (or needed).
    """
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
        add_to_zone(ZoneRequest(mac=req.mac, zone=req.zone), user)

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
    # #817 whole-branch fix (I3): batched zone lookup, once per request.
    zmap = _zone_map()

    clients = []
    for d in devices:
        mac = d["mac"]
        zone = zmap.get(mac, "quarantine")
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
def quarantine_client(mac: str, user=Depends(require_jwt)):
    """#817 Task 5 fix (#808): converted from `async def` — delegates to
    the now-`def` `add_to_zone`, so `await` is no longer valid (or needed)."""
    return add_to_zone(ZoneRequest(mac=mac, zone="quarantine"), user)


class MacRequest(BaseModel):
    mac: str


@router.post("/unquarantine")
def unquarantine(req: MacRequest, user=Depends(require_jwt)):
    """Move client from quarantine to LAN (frontend compatibility endpoint).

    #817 Task 5 fix (#808): converted from `async def` — delegates to the
    now-`def` `add_to_zone`, so `await` is no longer valid (or needed).
    """
    return add_to_zone(ZoneRequest(mac=req.mac, zone="lan"), user)


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


# ══════════════════════════════════════════════════════════════════
# #817 Task 6 — absorbed endpoints: vendors, scan, probe, mDNS, groups, export
#
# mac-guard (`/scan`, `/vendors`) and device-intel (`_probe_luci`,
# `_discover_mdns_services`, groups CRUD, `/export/*`) are folded in here.
# Every handler below is plain `def`; the actual subprocess call in each
# is factored into its own module-level function so tests can
# monkeypatch it and never shell out for real (#808 constraint: nothing
# heavy runs inline on the aggregator's shared loop — `def` handlers are
# already threadpooled by FastAPI, and bounded `ThreadPoolExecutor`s are
# used where a single request fans out to many subprocess calls).
# ══════════════════════════════════════════════════════════════════

# --- /vendors (mac-guard absorption) ---


@router.get("/vendors")
def vendors(mac: Optional[str] = None, user=Depends(require_jwt)):
    """OUI vendor lookup. With no `?mac=`, report the loaded OUI map size."""
    om = oui_map or {}
    if mac:
        mac_c = canon_mac(mac) or mac.lower()
        return {"mac": mac_c, "vendor": oui_vendor(mac_c, om)}
    return {"oui_entries": len(om)}


# --- /scan (mac-guard absorption) ---

DEFAULT_SCAN_SUBNET = "192.168.1.0/24"


def _scan_subprocess(subnet: str = DEFAULT_SCAN_SUBNET) -> str:
    """Run `nmap -sn -PR` (ARP ping sweep) and return its grepable stdout,
    or "" if nmap isn't installed / fails. Factored out so tests
    monkeypatch this instead of shelling out for real.
    """
    try:
        result = subprocess.run(
            ["nmap", "-sn", "-PR", subnet, "-oG", "-"],
            capture_output=True, text=True, timeout=60,
        )
        return result.stdout
    except (FileNotFoundError, subprocess.SubprocessError):
        return ""


def _parse_nmap_hosts(output: str) -> List[str]:
    """Extract the IPs from nmap `-oG` `Host: <ip> (...)` lines."""
    ips = []
    for line in output.splitlines():
        if line.startswith("Host:"):
            parts = line.split()
            if len(parts) >= 2:
                ips.append(parts[1])
    return ips


def _scan_devices(subnet: str = DEFAULT_SCAN_SUBNET) -> List[Dict[str, Any]]:
    """On-demand active scan: nmap ARP sweep to find live IPs, then
    cross-reference the ARP/neighbor table (`_parse_arp`, already blocking
    subprocess) for the MAC — nmap's grepable output doesn't reliably
    carry it. No nmap / no hits at all -> fall back to whatever's already
    in the ARP table (mac-guard's original fallback behaviour).
    """
    stdout = _scan_subprocess(subnet)
    found_ips = set(_parse_nmap_hosts(stdout))
    arp = _parse_arp()

    if not found_ips:
        return arp

    by_ip = {c["ip"]: c for c in arp}
    return [by_ip[ip] for ip in found_ips if ip in by_ip]


@router.post("/scan")
def scan(subnet: str = DEFAULT_SCAN_SUBNET, user=Depends(require_jwt)):
    """Trigger an on-demand network scan and merge findings into the store.

    #817 Task 6 (mac-guard absorption): plain `def` — FastAPI threadpools
    the blocking nmap/ARP subprocess calls below off the shared aggregator
    loop (#808); this never runs on the passive collector's own loop.

    #817 Task 6 review fix 1: enriches each discovered device (oui_vendor,
    device_type, risk_score/risk_level, is_router/is_openwrt) before
    `store.upsert()` — mirrors `Collector.cycle_once`'s enrichment block —
    so scan-only devices no longer land with NULL device_type/risk columns
    (`upsert` binds `None` for every listed column, and the SQLite
    `DEFAULT` never fires on an explicit `NULL`).

    #817 Task 6 review fix 2: `subnet` is validated as an IP network
    (`ipaddress.ip_network`) before it ever reaches the `nmap` argv — an
    authenticated caller could otherwise pass an argv-injection token
    (e.g. `--script=...`) or an arbitrary external range.
    """
    try:
        ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        raise HTTPException(400, "invalid subnet")

    devices = _scan_devices(subnet)
    now = int(time.time())
    merged = 0

    for d in devices:
        mac = canon_mac(d.get("mac", ""))
        if not mac:
            continue
        if store:
            hostname = d.get("hostname") or ""
            vendor = oui_vendor(mac, oui_map or {})
            device_type = classify_device_type(hostname, vendor)
            fp = openwrt_fingerprint(hostname, mac)

            # #817 addendum (Task 10): a device already in the store, or
            # explicitly allow-listed, is "known" -> trusted; a
            # never-before-seen device is unknown. For a router this is
            # the known-router-vs-rogue-AP signal risk_score() acts on.
            existing_row = store.get(mac)
            is_known = (existing_row is not None) or (
                bool(existing_row) and existing_row.get("allow_state") == "allow"
            )

            # #817 whole-branch fix (I4): OMIT fields the enricher couldn't
            # determine (None vendor, "unknown" device_type + its derived
            # risk) so a re-scanned migrated device isn't clobbered by a
            # sentinel through `upsert`'s best-value merge; a brand-new
            # device still gets the column DEFAULT.
            upsert_dev = {
                "mac": mac,
                "ip": d.get("ip"),
                "hostname": hostname or None,
                "last_seen": now,
                "source": "scan",
                "is_router": int(fp["is_router"]),
                "is_openwrt": int(fp["is_openwrt"]),
            }
            if vendor:
                upsert_dev["oui_vendor"] = vendor
            if device_type != "unknown":
                score, level = risk_score(device_type, fp["is_router"], is_known)
                upsert_dev["device_type"] = device_type
                upsert_dev["risk_score"] = score
                upsert_dev["risk_level"] = level

            store.upsert(upsert_dev)
            merged += 1

    stats_cache.clear()
    return {"success": True, "devices_found": len(devices), "merged": merged}


# --- /probe/openwrt[/{ip}] (device-intel `_probe_luci` absorption) ---

_SECUBOX_MARKERS = (
    "data-secubox-theme", "luci-static/secubox", "secubox-auth-hook",
    "secubox-portal", "secubox-public", "luci-app-secubox",
    "/luci/admin/secubox", "secubox-dashboard",
)


def _curl_body(url: str, timeout: float) -> str:
    """Blocking `curl` GET, returns the response body (or "" on any
    failure/timeout). Factored so `_probe_ip` tests can monkeypatch this
    single function instead of touching subprocess/network.
    """
    try:
        r = subprocess.run(
            ["curl", "-s", "--connect-timeout", str(max(1, int(timeout))), "-k", url],
            capture_output=True, text=True, timeout=timeout + 1,
        )
        return r.stdout or ""
    except (subprocess.SubprocessError, OSError):
        return ""


def _probe_ip(ip: str, timeout: float = 2.0) -> Dict[str, Any]:
    """Active LuCI/OpenWrt/SecuBox fingerprint of a single IP (device-intel
    `_probe_luci` absorption, synchronous form). Tests monkeypatch this
    function directly to avoid any real curl/network call.
    """
    result: Dict[str, Any] = {
        "luci_detected": False, "secubox_detected": False,
        "version": None, "model": None,
    }

    for scheme in ("http", "https"):
        if result["luci_detected"]:
            break
        body = _curl_body(f"{scheme}://{ip}/cgi-bin/luci", timeout)
        if not body:
            continue

        result["luci_detected"] = True
        body_lower = body.lower()

        model_match = re.search(r"<title>([^<]+)</title>", body, re.IGNORECASE)
        if model_match:
            title = model_match.group(1)
            if " - " in title:
                result["model"] = title.split(" - ")[0].strip()

        ver_match = re.search(r"git-[\d.]+-[a-f0-9]+", body)
        if ver_match:
            result["version"] = ver_match.group(0)
        elif "luci.js?v=" in body:
            alt_ver = re.search(r"luci\.js\?v=([\d.~a-f0-9-]+)", body)
            if alt_ver:
                result["version"] = alt_ver.group(1)

        for marker in _SECUBOX_MARKERS:
            if marker in body_lower:
                result["secubox_detected"] = True
                break

    return result


def _apply_probe_result(mac: str, probe: Dict[str, Any]) -> None:
    """Persist a positive probe result's fingerprint columns into the store."""
    if not store or not probe.get("luci_detected"):
        return
    store.upsert({
        "mac": mac,
        "is_openwrt": 1,
        "is_secubox": int(bool(probe.get("secubox_detected"))),
        "model": probe.get("model"),
        "luci_version": probe.get("version"),
    })
    store.record_event(mac, "openwrt_probed")


@router.post("/probe/openwrt")
def probe_openwrt(user=Depends(require_jwt)):
    """Probe every known device with an IP for LuCI/OpenWrt (bounded
    concurrency), updating the store's fingerprint columns for matches.

    #817 Task 6 (device-intel absorption): plain `def`; the
    `ThreadPoolExecutor` bounds concurrency across many IPs within this
    one request — it never runs on the collector's own async loop.
    """
    devices = store.list(limit=5000) if store else []
    targets = [d for d in devices if d.get("ip")]
    results: List[Dict[str, Any]] = []

    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = {pool.submit(_probe_ip, d["ip"], 3.0): d for d in targets}
        for fut in as_completed(futures):
            d = futures[fut]
            probe = fut.result()
            _apply_probe_result(d["mac"], probe)
            results.append({"ip": d["ip"], "mac": d["mac"], **probe})

    stats_cache.clear()
    return {
        "success": True,
        "total_probed": len(results),
        "openwrt_detected": sum(1 for r in results if r.get("luci_detected")),
        "secubox_detected": sum(1 for r in results if r.get("secubox_detected")),
        "results": results,
    }


@router.post("/probe/openwrt/{ip}")
def probe_openwrt_single(ip: str, user=Depends(require_jwt)):
    """Probe a single IP for LuCI/OpenWrt/SecuBox and update the matching
    device's fingerprint columns, if a device with that IP is known.

    #817 Task 6 review fix 3 (SSRF): `ip` is validated as an IP literal
    (`ipaddress.ip_address`) before it reaches `_probe_ip` -> `curl` — a
    non-IP value (a hostname, or an argv-like token) is rejected with 400
    rather than handed to the subprocess.
    """
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(400, "invalid ip")

    probe = _probe_ip(ip, 5.0)

    mac = None
    for d in (store.list(limit=5000) if store else []):
        if d.get("ip") == ip:
            mac = d["mac"]
            break

    if mac:
        _apply_probe_result(mac, probe)
        stats_cache.clear()

    return {"ip": ip, "mac": mac, **probe}


# --- /mdns (device-intel `_discover_mdns_services` absorption) ---


def _mdns_subprocess() -> str:
    """Blocking `avahi-browse` call, returns stdout (or "" on any
    failure/timeout/missing binary). Factored so tests monkeypatch this
    instead of shelling out for real.
    """
    try:
        r = subprocess.run(
            ["avahi-browse", "-t", "-r", "-p", "_http._tcp"],
            capture_output=True, text=True, timeout=10,
        )
        return r.stdout or ""
    except (subprocess.SubprocessError, OSError):
        return ""


def _parse_mdns(output: str) -> List[Dict[str, Any]]:
    """Parse `avahi-browse -p` machine-readable lines (`=;iface;proto;
    name;type;domain;hostname;address;port;txt`) into service dicts."""
    services = []
    for line in output.split("\n"):
        if not line.startswith("="):
            continue
        parts = line.split(";")
        if len(parts) >= 8:
            services.append({
                "name": parts[3],
                "type": parts[4],
                "hostname": parts[6],
                "ip": parts[7],
                "port": int(parts[8]) if parts[8].isdigit() else 80,
            })
    return services


@router.get("/mdns")
def mdns(user=Depends(require_jwt)):
    """Discover devices/services via mDNS/Avahi."""
    services = _parse_mdns(_mdns_subprocess())
    return {"services": services, "total": len(services)}


# --- /groups CRUD (device-intel absorption, simplified) ---


class GroupRequest(BaseModel):
    name: str
    description: str = ""
    color: str = "#3498db"
    icon: str = "devices"


class GroupMemberRequest(BaseModel):
    mac: str


@router.get("/groups")
def list_groups(user=Depends(require_jwt)):
    """List all device groups with their members.

    #817 Task 6: simplified to one group per device (the `devices.group_id`
    column already reserved in the schema) rather than device-intel's
    many-to-many membership list — see `store.py`'s device-groups section.
    """
    groups = store.list_groups() if store else []
    result = []
    for g in groups:
        members = [d["mac"] for d in (store.group_members(g["id"]) if store else [])]
        result.append({**g, "members": members, "member_count": len(members)})
    return {"groups": result, "count": len(result)}


@router.post("/groups")
def create_group(req: GroupRequest, user=Depends(require_jwt)):
    """Create a new device group."""
    group_id = uuid.uuid4().hex[:8]
    group = store.create_group(group_id, req.name, req.description, req.color, req.icon) if store else {}
    return {"success": True, "group": group}


@router.delete("/groups/{group_id}")
def delete_group(group_id: str, user=Depends(require_jwt)):
    """Delete a device group; member devices are unassigned, not deleted."""
    if store:
        store.delete_group(group_id)
    return {"success": True}


@router.post("/groups/{group_id}/members")
def add_group_member(group_id: str, req: GroupMemberRequest, user=Depends(require_jwt)):
    """Assign a device (by MAC) to a group."""
    mac = canon_mac(req.mac) or req.mac.lower()
    if store:
        store.assign_group(mac, group_id)
    return {"success": True, "mac": mac, "group_id": group_id}


# --- /export/json + /export/csv (device-intel absorption) ---

_EXPORT_COLUMNS = [
    "mac", "ip", "hostname", "oui_vendor", "device_type", "risk_level",
    "risk_score", "zone", "allow_state", "is_router", "is_openwrt",
    "model", "luci_version", "first_seen", "last_seen", "source",
]

# #817 Task 6 review fix 4: hostname/model/oui_vendor are attacker-influenceable
# (a device can announce any hostname). A leading =/+/-/@ (or tab/CR) is how
# spreadsheet apps (Excel, LibreOffice, Google Sheets) trigger formula
# evaluation on CSV import — prefix such cells with a single quote so they
# import as inert text instead.
_CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _csv_safe_cell(value: Any) -> Any:
    """Neutralize a CSV cell that would otherwise be interpreted as a
    spreadsheet formula on import."""
    if isinstance(value, str) and value.startswith(_CSV_FORMULA_PREFIXES):
        return "'" + value
    return value


@router.get("/export/json")
def export_json(user=Depends(require_jwt)):
    """Export the full device store as JSON."""
    devices = store.list(limit=100000) if store else []
    return {
        "exported_at": datetime.now().isoformat(),
        "device_count": len(devices),
        "devices": devices,
    }


@router.get("/export/csv")
def export_csv(user=Depends(require_jwt)):
    """Export the full device store as CSV (header row + one row per device)."""
    devices = store.list(limit=100000) if store else []

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(_EXPORT_COLUMNS)
    for d in devices:
        writer.writerow([_csv_safe_cell(d.get(c, "")) for c in _EXPORT_COLUMNS])

    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=devices.csv"},
    )


app.include_router(router)
