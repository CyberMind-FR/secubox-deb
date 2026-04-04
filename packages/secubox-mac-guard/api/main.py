"""SecuBox MAC Guard API - MAC Address Control and Network Access

MAC-based network access control with device discovery, vendor lookup,
whitelist/blacklist management, and nftables integration.
"""
import asyncio
import subprocess
import json
import threading
import time
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional, Set
from fastapi import FastAPI, APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field, field_validator
from secubox_core.auth import router as auth_router, require_jwt
from secubox_core.config import get_config
from secubox_core.logger import get_logger

app = FastAPI(title="secubox-mac-guard", version="1.0.0", root_path="/api/v1/mac-guard")
app.include_router(auth_router, prefix="/auth")

router = APIRouter()
log = get_logger("mac-guard")

# Configuration paths
DATA_DIR = Path("/var/lib/secubox/mac-guard")
DATA_DIR.mkdir(parents=True, exist_ok=True)

DEVICES_FILE = DATA_DIR / "devices.json"
WHITELIST_FILE = DATA_DIR / "whitelist.json"
BLACKLIST_FILE = DATA_DIR / "blacklist.json"
ALERTS_FILE = DATA_DIR / "alerts.json"
CONFIG_FILE = Path("/etc/secubox/mac-guard.toml")

# OUI database path (install via apt: ieee-data)
OUI_DB_PATH = "/usr/share/ieee-data/oui.txt"

# DHCP lease files
DNSMASQ_LEASES = "/var/lib/misc/dnsmasq.leases"

# nftables configuration
NFT_TABLE = "inet secubox_mac_guard"
NFT_WHITELIST_SET = "mac_whitelist"
NFT_BLACKLIST_SET = "mac_blacklist"


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
class DeviceTag(BaseModel):
    mac: str = Field(..., pattern="^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
    name: str = ""
    tags: List[str] = []


class MacEntry(BaseModel):
    mac: str = Field(..., pattern="^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
    name: str = ""
    reason: str = ""
    expires: Optional[str] = None


class ConfigUpdate(BaseModel):
    mode: str = Field(default="whitelist", pattern="^(whitelist|blacklist|disabled)$")
    alert_on_unknown: bool = True
    auto_block_unknown: bool = False
    scan_interval: int = Field(default=60, ge=30, le=3600)


class Alert(BaseModel):
    id: str
    mac: str
    type: str
    message: str
    timestamp: str
    acknowledged: bool = False


# Helper Functions
def _load_json(filepath: Path, default=None):
    """Load JSON file safely."""
    if filepath.exists():
        try:
            return json.loads(filepath.read_text())
        except Exception:
            pass
    return default if default is not None else {}


def _save_json(filepath: Path, data):
    """Save JSON file safely."""
    filepath.parent.mkdir(parents=True, exist_ok=True)
    filepath.write_text(json.dumps(data, indent=2))


def _load_devices() -> Dict[str, Dict[str, Any]]:
    """Load discovered devices."""
    return _load_json(DEVICES_FILE, {})


def _save_devices(devices: Dict[str, Dict[str, Any]]):
    """Save discovered devices."""
    _save_json(DEVICES_FILE, devices)


def _load_whitelist() -> Dict[str, Dict[str, Any]]:
    """Load MAC whitelist."""
    return _load_json(WHITELIST_FILE, {})


def _save_whitelist(whitelist: Dict[str, Dict[str, Any]]):
    """Save MAC whitelist."""
    _save_json(WHITELIST_FILE, whitelist)


def _load_blacklist() -> Dict[str, Dict[str, Any]]:
    """Load MAC blacklist."""
    return _load_json(BLACKLIST_FILE, {})


def _save_blacklist(blacklist: Dict[str, Dict[str, Any]]):
    """Save MAC blacklist."""
    _save_json(BLACKLIST_FILE, blacklist)


def _load_alerts() -> List[Dict[str, Any]]:
    """Load alerts."""
    return _load_json(ALERTS_FILE, [])


def _save_alerts(alerts: List[Dict[str, Any]]):
    """Save alerts (keep last 500)."""
    _save_json(ALERTS_FILE, alerts[-500:])


def _add_alert(mac: str, alert_type: str, message: str):
    """Add a new alert."""
    alerts = _load_alerts()
    alert_id = f"{int(time.time() * 1000)}"
    alerts.append({
        "id": alert_id,
        "mac": mac,
        "type": alert_type,
        "message": message,
        "timestamp": datetime.now().isoformat(),
        "acknowledged": False
    })
    _save_alerts(alerts)
    log.info("Alert: %s - %s", mac, message)


def _load_oui_db() -> Dict[str, str]:
    """Load MAC vendor database."""
    oui = {}
    if not Path(OUI_DB_PATH).exists():
        return oui
    try:
        with open(OUI_DB_PATH, 'r', errors='ignore') as f:
            for line in f:
                if "(hex)" in line:
                    parts = line.split("(hex)")
                    if len(parts) >= 2:
                        mac_prefix = parts[0].strip().replace("-", ":").upper()[:8]
                        vendor = parts[1].strip()
                        oui[mac_prefix] = vendor
    except Exception:
        pass
    return oui


def _get_vendor(mac: str, oui_db: Dict[str, str]) -> str:
    """Look up vendor from MAC address."""
    mac_upper = mac.upper().replace("-", ":")
    prefix = mac_upper[:8]
    return oui_db.get(prefix, "Unknown")


def _get_arp_table() -> List[Dict[str, Any]]:
    """Get ARP table entries."""
    devices = []
    try:
        result = subprocess.run(
            ["ip", "neigh", "show"],
            capture_output=True, text=True, timeout=10
        )
        for line in result.stdout.strip().split('\n'):
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 5 and "lladdr" in parts:
                ip = parts[0]
                dev_idx = parts.index("dev") + 1 if "dev" in parts else -1
                lladdr_idx = parts.index("lladdr") + 1 if "lladdr" in parts else -1
                iface = parts[dev_idx] if dev_idx > 0 and dev_idx < len(parts) else ""
                mac = parts[lladdr_idx] if lladdr_idx > 0 and lladdr_idx < len(parts) else ""
                state = parts[-1] if parts[-1] in ["REACHABLE", "STALE", "DELAY", "PROBE", "FAILED", "PERMANENT"] else "UNKNOWN"
                if mac and re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', mac):
                    devices.append({
                        "ip": ip,
                        "mac": mac.upper(),
                        "interface": iface,
                        "state": state
                    })
    except Exception:
        pass
    return devices


def _get_dhcp_leases() -> Dict[str, Dict[str, Any]]:
    """Get DHCP lease information."""
    leases = {}
    if Path(DNSMASQ_LEASES).exists():
        try:
            with open(DNSMASQ_LEASES, 'r') as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 4:
                        mac = parts[1].upper()
                        leases[mac] = {
                            "ip": parts[2],
                            "hostname": parts[3] if parts[3] != "*" else "",
                            "expires": int(parts[0]) if parts[0].isdigit() else 0
                        }
        except Exception:
            pass
    return leases


def _nft_list_set(set_name: str) -> List[str]:
    """Return elements from an nftables set."""
    try:
        r = subprocess.run(
            ["nft", "-j", "list", "set", "inet", "secubox_mac_guard", set_name],
            capture_output=True, text=True, timeout=5
        )
        data = json.loads(r.stdout)
        elements = []
        for item in data.get("nftables", []):
            if "set" in item:
                for e in item["set"].get("elem", []):
                    if isinstance(e, str):
                        elements.append(e.upper())
                    elif isinstance(e, dict):
                        elements.append(str(e.get("val", e)).upper())
        return elements
    except Exception:
        return []


def _nft_add_element(set_name: str, mac: str):
    """Add MAC to nftables set."""
    mac_lower = mac.lower()
    subprocess.run(
        ["nft", "add", "element", "inet", "secubox_mac_guard", set_name, "{", mac_lower, "}"],
        capture_output=True, timeout=5
    )


def _nft_delete_element(set_name: str, mac: str):
    """Remove MAC from nftables set."""
    mac_lower = mac.lower()
    subprocess.run(
        ["nft", "delete", "element", "inet", "secubox_mac_guard", set_name, "{", mac_lower, "}"],
        capture_output=True, timeout=5
    )


def _ensure_nft_table():
    """Ensure nftables table and sets exist."""
    try:
        # Create table if not exists
        subprocess.run(
            ["nft", "add", "table", "inet", "secubox_mac_guard"],
            capture_output=True, timeout=5
        )
        # Create sets if not exist
        subprocess.run(
            ["nft", "add", "set", "inet", "secubox_mac_guard", NFT_WHITELIST_SET,
             "{ type ether_addr; }"],
            capture_output=True, timeout=5
        )
        subprocess.run(
            ["nft", "add", "set", "inet", "secubox_mac_guard", NFT_BLACKLIST_SET,
             "{ type ether_addr; }"],
            capture_output=True, timeout=5
        )
    except Exception:
        pass


def _sync_nft_sets():
    """Sync whitelist/blacklist to nftables sets."""
    _ensure_nft_table()

    # Sync whitelist
    whitelist = _load_whitelist()
    nft_whitelist = set(_nft_list_set(NFT_WHITELIST_SET))
    file_whitelist = set(whitelist.keys())

    # Add missing to nft
    for mac in file_whitelist - nft_whitelist:
        _nft_add_element(NFT_WHITELIST_SET, mac)
    # Remove stale from nft
    for mac in nft_whitelist - file_whitelist:
        _nft_delete_element(NFT_WHITELIST_SET, mac)

    # Sync blacklist
    blacklist = _load_blacklist()
    nft_blacklist = set(_nft_list_set(NFT_BLACKLIST_SET))
    file_blacklist = set(blacklist.keys())

    # Add missing to nft
    for mac in file_blacklist - nft_blacklist:
        _nft_add_element(NFT_BLACKLIST_SET, mac)
    # Remove stale from nft
    for mac in nft_blacklist - file_blacklist:
        _nft_delete_element(NFT_BLACKLIST_SET, mac)


# Background monitoring
_monitoring_task: Optional[asyncio.Task] = None
_known_macs: Set[str] = set()
_oui_db: Optional[Dict[str, str]] = None


async def _monitor_devices():
    """Background task to monitor for new devices."""
    global _known_macs, _oui_db

    if _oui_db is None:
        _oui_db = _load_oui_db()

    while True:
        try:
            arp_devices = _get_arp_table()
            dhcp_leases = _get_dhcp_leases()
            devices = _load_devices()
            whitelist = _load_whitelist()
            blacklist = _load_blacklist()
            config = get_config("mac-guard") or {}

            current_macs = {d["mac"] for d in arp_devices}

            # Check for new devices
            new_macs = current_macs - _known_macs
            for mac in new_macs:
                dev = next((d for d in arp_devices if d["mac"] == mac), None)
                if not dev:
                    continue

                lease = dhcp_leases.get(mac, {})
                vendor = _get_vendor(mac, _oui_db)

                # Update devices database
                if mac not in devices:
                    devices[mac] = {
                        "first_seen": datetime.now().isoformat(),
                        "ip": dev["ip"],
                        "hostname": lease.get("hostname", ""),
                        "vendor": vendor,
                        "name": "",
                        "tags": []
                    }

                devices[mac]["last_seen"] = datetime.now().isoformat()
                devices[mac]["ip"] = dev["ip"]
                devices[mac]["state"] = dev["state"]

                # Check if unknown device
                if mac not in whitelist and mac not in blacklist:
                    if config.get("alert_on_unknown", True):
                        _add_alert(mac, "unknown_device",
                                   f"Unknown device detected: {mac} ({vendor}) - IP: {dev['ip']}")

                    if config.get("auto_block_unknown", False):
                        blacklist[mac] = {
                            "name": f"Auto-blocked: {vendor}",
                            "reason": "Unknown device auto-blocked",
                            "added": datetime.now().isoformat()
                        }
                        _save_blacklist(blacklist)
                        _nft_add_element(NFT_BLACKLIST_SET, mac)
                        _add_alert(mac, "auto_blocked",
                                   f"Device auto-blocked: {mac} ({vendor})")

            # Update all devices
            for dev in arp_devices:
                mac = dev["mac"]
                if mac in devices:
                    devices[mac]["last_seen"] = datetime.now().isoformat()
                    devices[mac]["ip"] = dev["ip"]
                    devices[mac]["state"] = dev["state"]

            _save_devices(devices)
            _known_macs = current_macs

        except Exception as e:
            log.error("Monitor error: %s", str(e))

        await asyncio.sleep(60)


@app.on_event("startup")
async def startup():
    """Start background monitoring."""
    global _monitoring_task, _known_macs

    # Initialize known MACs from devices file
    devices = _load_devices()
    _known_macs = set(devices.keys())

    # Ensure nftables table exists
    _ensure_nft_table()

    # Sync nftables sets
    _sync_nft_sets()

    # Start monitoring
    _monitoring_task = asyncio.create_task(_monitor_devices())


@app.on_event("shutdown")
async def shutdown():
    """Stop background monitoring."""
    global _monitoring_task
    if _monitoring_task:
        _monitoring_task.cancel()


# Public endpoints
@router.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "ok", "module": "mac-guard", "version": "1.0.0"}


@router.get("/status")
async def status(user=Depends(require_jwt)):
    """Get MAC Guard status."""
    cached = stats_cache.get("status")
    if cached:
        return cached

    devices = _load_devices()
    whitelist = _load_whitelist()
    blacklist = _load_blacklist()
    alerts = _load_alerts()
    config = get_config("mac-guard") or {}

    # Count online devices
    online_count = sum(1 for d in devices.values()
                       if d.get("state") in ["REACHABLE", "STALE", "DELAY"])

    # Count unknown (not in whitelist or blacklist)
    unknown_count = sum(1 for mac in devices if mac not in whitelist and mac not in blacklist)

    # Unacknowledged alerts
    unack_alerts = sum(1 for a in alerts if not a.get("acknowledged"))

    try:
        nft_ok = subprocess.run(
            ["nft", "list", "tables"],
            capture_output=True, timeout=5
        ).returncode == 0
    except Exception:
        nft_ok = False

    result = {
        "mode": config.get("mode", "whitelist"),
        "total_devices": len(devices),
        "online_devices": online_count,
        "whitelist_count": len(whitelist),
        "blacklist_count": len(blacklist),
        "unknown_count": unknown_count,
        "alert_count": unack_alerts,
        "nftables_ok": nft_ok,
        "alert_on_unknown": config.get("alert_on_unknown", True),
        "auto_block_unknown": config.get("auto_block_unknown", False),
        "timestamp": datetime.now().isoformat()
    }

    stats_cache.set("status", result)
    return result


# Config endpoints
@router.get("/config")
async def get_config_endpoint(user=Depends(require_jwt)):
    """Get MAC Guard configuration."""
    config = get_config("mac-guard") or {}
    return {
        "mode": config.get("mode", "whitelist"),
        "alert_on_unknown": config.get("alert_on_unknown", True),
        "auto_block_unknown": config.get("auto_block_unknown", False),
        "scan_interval": config.get("scan_interval", 60)
    }


@router.post("/config")
async def set_config_endpoint(req: ConfigUpdate, user=Depends(require_jwt)):
    """Update MAC Guard configuration."""
    # In production, this would update the TOML config file
    log.info("Config update: mode=%s, alert_on_unknown=%s, auto_block_unknown=%s",
             req.mode, req.alert_on_unknown, req.auto_block_unknown)
    stats_cache.clear()
    return {"success": True, "config": req.model_dump()}


# Device endpoints
@router.get("/devices")
async def get_devices(user=Depends(require_jwt)):
    """Get all discovered devices."""
    global _oui_db
    if _oui_db is None:
        _oui_db = _load_oui_db()

    devices = _load_devices()
    whitelist = _load_whitelist()
    blacklist = _load_blacklist()
    arp_devices = _get_arp_table()
    dhcp_leases = _get_dhcp_leases()

    # Update with current ARP state
    arp_by_mac = {d["mac"]: d for d in arp_devices}

    result = []
    for mac, info in devices.items():
        arp_info = arp_by_mac.get(mac, {})
        lease = dhcp_leases.get(mac, {})

        status = "offline"
        if mac in blacklist:
            status = "blocked"
        elif arp_info.get("state") in ["REACHABLE", "STALE", "DELAY"]:
            status = "online"
        elif arp_info.get("state") == "FAILED":
            status = "offline"

        list_status = "unknown"
        if mac in whitelist:
            list_status = "whitelist"
        elif mac in blacklist:
            list_status = "blacklist"

        result.append({
            "mac": mac,
            "ip": arp_info.get("ip", info.get("ip", "")),
            "hostname": lease.get("hostname", info.get("hostname", "")),
            "vendor": info.get("vendor", _get_vendor(mac, _oui_db)),
            "name": info.get("name", ""),
            "tags": info.get("tags", []),
            "status": status,
            "list_status": list_status,
            "first_seen": info.get("first_seen"),
            "last_seen": info.get("last_seen"),
            "interface": arp_info.get("interface", "")
        })

    # Sort: online first, then by last_seen
    result.sort(key=lambda x: (x["status"] != "online", x.get("last_seen") or ""), reverse=False)

    return {
        "devices": result,
        "count": len(result),
        "online": sum(1 for d in result if d["status"] == "online"),
        "blocked": sum(1 for d in result if d["status"] == "blocked")
    }


@router.get("/device/{mac}")
async def get_device(mac: str, user=Depends(require_jwt)):
    """Get details for a specific device."""
    global _oui_db
    if _oui_db is None:
        _oui_db = _load_oui_db()

    mac_upper = mac.upper()
    devices = _load_devices()
    whitelist = _load_whitelist()
    blacklist = _load_blacklist()
    alerts = _load_alerts()

    if mac_upper not in devices:
        raise HTTPException(404, "Device not found")

    info = devices[mac_upper]
    arp_devices = _get_arp_table()
    dhcp_leases = _get_dhcp_leases()

    arp_info = next((d for d in arp_devices if d["mac"] == mac_upper), {})
    lease = dhcp_leases.get(mac_upper, {})

    # Get device alerts
    device_alerts = [a for a in alerts if a.get("mac") == mac_upper][-10:]

    return {
        "mac": mac_upper,
        "ip": arp_info.get("ip", info.get("ip", "")),
        "hostname": lease.get("hostname", info.get("hostname", "")),
        "vendor": info.get("vendor", _get_vendor(mac_upper, _oui_db)),
        "name": info.get("name", ""),
        "tags": info.get("tags", []),
        "status": "online" if arp_info.get("state") in ["REACHABLE", "STALE", "DELAY"] else "offline",
        "list_status": "whitelist" if mac_upper in whitelist else ("blacklist" if mac_upper in blacklist else "unknown"),
        "first_seen": info.get("first_seen"),
        "last_seen": info.get("last_seen"),
        "interface": arp_info.get("interface", ""),
        "whitelist_info": whitelist.get(mac_upper),
        "blacklist_info": blacklist.get(mac_upper),
        "recent_alerts": device_alerts
    }


@router.post("/device/{mac}/tag")
async def tag_device(mac: str, req: DeviceTag, user=Depends(require_jwt)):
    """Tag a device with name and tags."""
    mac_upper = mac.upper()
    devices = _load_devices()

    if mac_upper not in devices:
        devices[mac_upper] = {"first_seen": datetime.now().isoformat()}

    devices[mac_upper]["name"] = req.name
    devices[mac_upper]["tags"] = req.tags
    _save_devices(devices)
    stats_cache.clear()

    return {"success": True, "mac": mac_upper}


# Whitelist endpoints
@router.get("/whitelist")
async def get_whitelist(user=Depends(require_jwt)):
    """Get MAC whitelist."""
    global _oui_db
    if _oui_db is None:
        _oui_db = _load_oui_db()

    whitelist = _load_whitelist()
    devices = _load_devices()

    result = []
    for mac, info in whitelist.items():
        device = devices.get(mac, {})
        result.append({
            "mac": mac,
            "name": info.get("name", device.get("name", "")),
            "vendor": device.get("vendor", _get_vendor(mac, _oui_db)),
            "reason": info.get("reason", ""),
            "added": info.get("added"),
            "expires": info.get("expires"),
            "last_seen": device.get("last_seen")
        })

    return {"whitelist": result, "count": len(result)}


@router.post("/whitelist")
async def add_to_whitelist(req: MacEntry, user=Depends(require_jwt)):
    """Add MAC to whitelist."""
    mac_upper = req.mac.upper()

    # Remove from blacklist if present
    blacklist = _load_blacklist()
    if mac_upper in blacklist:
        del blacklist[mac_upper]
        _save_blacklist(blacklist)
        _nft_delete_element(NFT_BLACKLIST_SET, mac_upper)

    # Add to whitelist
    whitelist = _load_whitelist()
    whitelist[mac_upper] = {
        "name": req.name,
        "reason": req.reason,
        "added": datetime.now().isoformat(),
        "expires": req.expires
    }
    _save_whitelist(whitelist)
    _nft_add_element(NFT_WHITELIST_SET, mac_upper)

    log.info("MAC whitelisted: %s", mac_upper)
    stats_cache.clear()

    return {"success": True, "mac": mac_upper}


@router.delete("/whitelist/{mac}")
async def remove_from_whitelist(mac: str, user=Depends(require_jwt)):
    """Remove MAC from whitelist."""
    mac_upper = mac.upper()

    whitelist = _load_whitelist()
    if mac_upper in whitelist:
        del whitelist[mac_upper]
        _save_whitelist(whitelist)
        _nft_delete_element(NFT_WHITELIST_SET, mac_upper)

    log.info("MAC removed from whitelist: %s", mac_upper)
    stats_cache.clear()

    return {"success": True, "mac": mac_upper}


# Blacklist endpoints
@router.get("/blacklist")
async def get_blacklist(user=Depends(require_jwt)):
    """Get MAC blacklist."""
    global _oui_db
    if _oui_db is None:
        _oui_db = _load_oui_db()

    blacklist = _load_blacklist()
    devices = _load_devices()

    result = []
    for mac, info in blacklist.items():
        device = devices.get(mac, {})
        result.append({
            "mac": mac,
            "name": info.get("name", device.get("name", "")),
            "vendor": device.get("vendor", _get_vendor(mac, _oui_db)),
            "reason": info.get("reason", ""),
            "added": info.get("added"),
            "expires": info.get("expires"),
            "last_seen": device.get("last_seen")
        })

    return {"blacklist": result, "count": len(result)}


@router.post("/blacklist")
async def add_to_blacklist(req: MacEntry, user=Depends(require_jwt)):
    """Add MAC to blacklist."""
    mac_upper = req.mac.upper()

    # Remove from whitelist if present
    whitelist = _load_whitelist()
    if mac_upper in whitelist:
        del whitelist[mac_upper]
        _save_whitelist(whitelist)
        _nft_delete_element(NFT_WHITELIST_SET, mac_upper)

    # Add to blacklist
    blacklist = _load_blacklist()
    blacklist[mac_upper] = {
        "name": req.name,
        "reason": req.reason,
        "added": datetime.now().isoformat(),
        "expires": req.expires
    }
    _save_blacklist(blacklist)
    _nft_add_element(NFT_BLACKLIST_SET, mac_upper)

    log.info("MAC blacklisted: %s", mac_upper)
    _add_alert(mac_upper, "blocked", f"Device blocked: {mac_upper}")
    stats_cache.clear()

    return {"success": True, "mac": mac_upper}


@router.delete("/blacklist/{mac}")
async def remove_from_blacklist(mac: str, user=Depends(require_jwt)):
    """Remove MAC from blacklist."""
    mac_upper = mac.upper()

    blacklist = _load_blacklist()
    if mac_upper in blacklist:
        del blacklist[mac_upper]
        _save_blacklist(blacklist)
        _nft_delete_element(NFT_BLACKLIST_SET, mac_upper)

    log.info("MAC removed from blacklist: %s", mac_upper)
    stats_cache.clear()

    return {"success": True, "mac": mac_upper}


# Unknown devices endpoint
@router.get("/unknown")
async def get_unknown(user=Depends(require_jwt)):
    """Get unknown devices (not in whitelist or blacklist)."""
    global _oui_db
    if _oui_db is None:
        _oui_db = _load_oui_db()

    devices = _load_devices()
    whitelist = _load_whitelist()
    blacklist = _load_blacklist()
    arp_devices = _get_arp_table()

    arp_by_mac = {d["mac"]: d for d in arp_devices}

    result = []
    for mac, info in devices.items():
        if mac not in whitelist and mac not in blacklist:
            arp_info = arp_by_mac.get(mac, {})
            result.append({
                "mac": mac,
                "ip": arp_info.get("ip", info.get("ip", "")),
                "hostname": info.get("hostname", ""),
                "vendor": info.get("vendor", _get_vendor(mac, _oui_db)),
                "name": info.get("name", ""),
                "status": "online" if arp_info.get("state") in ["REACHABLE", "STALE", "DELAY"] else "offline",
                "first_seen": info.get("first_seen"),
                "last_seen": info.get("last_seen")
            })

    # Sort by last_seen
    result.sort(key=lambda x: x.get("last_seen") or "", reverse=True)

    return {"unknown": result, "count": len(result)}


# Scan endpoint
@router.post("/scan")
async def scan_network(background_tasks: BackgroundTasks, user=Depends(require_jwt)):
    """Trigger network scan."""
    try:
        # Use arping or nmap if available
        result = subprocess.run(
            ["nmap", "-sn", "-PR", "192.168.1.0/24", "-oG", "-"],
            capture_output=True, text=True, timeout=60
        )
        devices_found = result.stdout.count("Host:")
    except FileNotFoundError:
        # Fallback to ARP
        devices_found = len(_get_arp_table())

    stats_cache.clear()

    return {"success": True, "devices_found": devices_found}


# Vendor lookup endpoint
@router.get("/vendors")
async def get_vendors(mac: Optional[str] = None, user=Depends(require_jwt)):
    """OUI vendor lookup."""
    global _oui_db
    if _oui_db is None:
        _oui_db = _load_oui_db()

    if mac:
        mac_upper = mac.upper()
        return {"mac": mac_upper, "vendor": _get_vendor(mac_upper, _oui_db)}

    # Return vendor summary from known devices
    devices = _load_devices()
    vendors = {}
    for info in devices.values():
        vendor = info.get("vendor", "Unknown")
        vendors[vendor] = vendors.get(vendor, 0) + 1

    return {
        "vendors": [{"name": k, "count": v} for k, v in sorted(vendors.items(), key=lambda x: -x[1])],
        "total": len(vendors)
    }


# Alerts endpoints
@router.get("/alerts")
async def get_alerts(acknowledged: Optional[bool] = None, limit: int = 100, user=Depends(require_jwt)):
    """Get MAC alerts."""
    alerts = _load_alerts()

    if acknowledged is not None:
        alerts = [a for a in alerts if a.get("acknowledged") == acknowledged]

    # Return most recent first
    alerts = sorted(alerts, key=lambda x: x.get("timestamp", ""), reverse=True)[:limit]

    return {"alerts": alerts, "count": len(alerts)}


@router.post("/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(alert_id: str, user=Depends(require_jwt)):
    """Acknowledge an alert."""
    alerts = _load_alerts()

    for alert in alerts:
        if alert.get("id") == alert_id:
            alert["acknowledged"] = True
            alert["acknowledged_by"] = user.get("sub", "unknown")
            alert["acknowledged_at"] = datetime.now().isoformat()
            break

    _save_alerts(alerts)

    return {"success": True, "alert_id": alert_id}


@router.post("/alerts/acknowledge_all")
async def acknowledge_all_alerts(user=Depends(require_jwt)):
    """Acknowledge all alerts."""
    alerts = _load_alerts()

    for alert in alerts:
        if not alert.get("acknowledged"):
            alert["acknowledged"] = True
            alert["acknowledged_by"] = user.get("sub", "unknown")
            alert["acknowledged_at"] = datetime.now().isoformat()

    _save_alerts(alerts)

    return {"success": True, "acknowledged_count": len([a for a in alerts if a.get("acknowledged")])}


@router.delete("/alerts/{alert_id}")
async def delete_alert(alert_id: str, user=Depends(require_jwt)):
    """Delete an alert."""
    alerts = _load_alerts()
    alerts = [a for a in alerts if a.get("id") != alert_id]
    _save_alerts(alerts)

    return {"success": True}


# Stats endpoint
@router.get("/stats")
async def get_stats(user=Depends(require_jwt)):
    """Get MAC Guard statistics."""
    devices = _load_devices()
    whitelist = _load_whitelist()
    blacklist = _load_blacklist()
    alerts = _load_alerts()
    arp_devices = _get_arp_table()

    # Online devices
    online_macs = {d["mac"] for d in arp_devices if d["state"] in ["REACHABLE", "STALE", "DELAY"]}
    online_count = len(online_macs)

    # Vendor breakdown
    vendors = {}
    for info in devices.values():
        vendor = info.get("vendor", "Unknown")
        vendors[vendor] = vendors.get(vendor, 0) + 1

    # Recent alerts (last 24h)
    yesterday = (datetime.now() - timedelta(days=1)).isoformat()
    recent_alerts = [a for a in alerts if a.get("timestamp", "") >= yesterday]

    return {
        "total_devices": len(devices),
        "online_devices": online_count,
        "whitelist_count": len(whitelist),
        "blacklist_count": len(blacklist),
        "unknown_count": len(devices) - len(whitelist) - len(set(blacklist.keys()) & set(devices.keys())),
        "alerts_today": len(recent_alerts),
        "alerts_unack": sum(1 for a in alerts if not a.get("acknowledged")),
        "top_vendors": sorted(vendors.items(), key=lambda x: -x[1])[:10],
        "timestamp": datetime.now().isoformat()
    }


@router.post("/sync")
async def sync_nft(user=Depends(require_jwt)):
    """Sync whitelist/blacklist to nftables."""
    _sync_nft_sets()
    stats_cache.clear()
    return {"success": True, "message": "nftables sets synchronized"}


app.include_router(router)
