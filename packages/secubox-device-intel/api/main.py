"""SecuBox Device-Intel API - Asset Discovery and Fingerprinting

Enhanced with OpenWRT/SecuBox device detection:
- MAC vendor fingerprinting for router manufacturers
- HTTP probe for LuCI interface detection
- DHCP hostname pattern matching
- mDNS/Avahi service discovery
- Device history tracking with connection logs
- Scheduled background scanning
- Export functionality (CSV/JSON)
- New device alerts via webhooks
- Device grouping and organization
"""
import asyncio
import subprocess
import re
import os
import json
import socket
import time
import csv
import io
import threading
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Set
from enum import Enum
from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks, Response
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
import httpx
from secubox_core.auth import require_jwt
from secubox_core.config import get_config

app = FastAPI(title="SecuBox Device-Intel", version="2.0.0")
config = get_config("device-intel")

# OUI database path (install via apt: ieee-data)
OUI_DB_PATH = "/usr/share/ieee-data/oui.txt"
DATA_DIR = Path("/var/lib/secubox/device-intel")
DEVICES_FILE = DATA_DIR / "devices.json"
HISTORY_FILE = DATA_DIR / "history.json"
GROUPS_FILE = DATA_DIR / "groups.json"
WEBHOOKS_FILE = DATA_DIR / "webhooks.json"
SCAN_STATE_FILE = DATA_DIR / "scan_state.json"
DHCP_LEASES = "/var/lib/dhcp/dhcpd.leases"
DNSMASQ_LEASES = "/var/lib/misc/dnsmasq.leases"

# Configuration
SCAN_INTERVAL = 300  # Default scan interval in seconds (5 minutes)
HISTORY_RETENTION_DAYS = 30
MAX_HISTORY_ENTRIES = 10000

# Ensure state directory exists
DATA_DIR.mkdir(parents=True, exist_ok=True)

# OpenWRT/Router MAC vendor prefixes (common manufacturers)
ROUTER_VENDORS = {
    "TP-LINK": ["EC:08:6B", "50:C7:BF", "14:CC:20", "AC:84:C6", "C0:25:E9", "E4:F4:C6"],
    "Ubiquiti": ["DC:9F:DB", "24:A4:3C", "80:2A:A8", "F0:9F:C2", "78:8A:20", "68:72:51"],
    "GL.iNet": ["E4:95:6E", "94:83:C4"],
    "Netgear": ["A0:63:91", "20:0C:C8", "C0:FF:D4", "9C:D3:6D", "10:0D:7F"],
    "Asus": ["04:D9:F5", "AC:9E:17", "50:46:5D", "38:D5:47", "1C:87:2C"],
    "Linksys": ["20:AA:4B", "C0:56:27", "58:6D:8F", "A4:2B:8C"],
    "D-Link": ["1C:7E:E5", "28:10:7B", "90:94:E4", "C4:A8:1D", "78:54:2E"],
    "MikroTik": ["D4:01:C3", "4C:5E:0C", "6C:3B:6B", "C4:AD:34", "E4:8D:8C"],
    "OpenWrt": ["02:00:00"],  # OpenWrt default MAC prefix
    "Xiaomi": ["64:09:80", "78:11:DC", "28:6C:07", "50:64:2B"],
    "Huawei": ["48:46:FB", "20:F3:A3", "E0:24:7F", "88:CE:FA"],
}

# OpenWRT hostname patterns
OPENWRT_HOSTNAMES = [
    r"^openwrt",
    r"^lede",
    r"^gl-",  # GL.iNet
    r"^router",
    r"^secubox",
    r"^espressobin",
    r"^mochabin",
]


class DeviceEvent(str, Enum):
    FIRST_SEEN = "first_seen"
    ONLINE = "online"
    OFFLINE = "offline"
    IP_CHANGED = "ip_changed"
    HOSTNAME_CHANGED = "hostname_changed"


class DeviceNote(BaseModel):
    mac: str
    note: str


class DeviceGroup(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    color: str = "#3498db"
    icon: str = "devices"
    members: List[str] = []  # List of MAC addresses
    created_at: str
    updated_at: Optional[str] = None


class DeviceHistoryEntry(BaseModel):
    timestamp: str
    mac: str
    event: DeviceEvent
    ip: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


class WebhookConfig(BaseModel):
    url: str
    events: List[str] = ["new_device", "device_offline"]
    enabled: bool = True
    secret: Optional[str] = None
    timeout: float = 5.0


class ScanState(BaseModel):
    enabled: bool = True
    interval_seconds: int = 300
    last_scan: Optional[str] = None
    next_scan: Optional[str] = None
    devices_found_last: int = 0
    new_devices_last: int = 0


class DeviceIntelManager:
    """Manager for device intelligence operations."""

    def __init__(self):
        self._oui_db: Optional[dict] = None
        self._known_macs: Set[str] = set()
        self._scan_lock = threading.Lock()
        self._last_online: Dict[str, str] = {}  # MAC -> last seen timestamp
        self._initialized = False

    def _ensure_initialized(self):
        """Lazy initialization to avoid import-time issues."""
        if not self._initialized:
            self._load_known_macs()
            self._initialized = True

    @property
    def oui_db(self) -> dict:
        """Lazy-load OUI database."""
        if self._oui_db is None:
            self._oui_db = _load_oui_db()
        return self._oui_db

    def _load_known_macs(self):
        """Load known MAC addresses from devices file."""
        devices = _load_devices()
        self._known_macs = set(devices.keys())

    def is_new_device(self, mac: str) -> bool:
        """Check if device is new (never seen before)."""
        return mac.upper() not in self._known_macs

    def register_device(self, mac: str):
        """Register a device as known."""
        self._known_macs.add(mac.upper())

    def record_history(self, mac: str, event: DeviceEvent, ip: str = None, details: Dict = None):
        """Record a device history event."""
        entry = DeviceHistoryEntry(
            timestamp=datetime.utcnow().isoformat() + "Z",
            mac=mac.upper(),
            event=event,
            ip=ip,
            details=details
        )

        history = self._load_history()
        history.append(entry.dict())

        # Trim old entries
        if len(history) > MAX_HISTORY_ENTRIES:
            history = history[-MAX_HISTORY_ENTRIES:]

        self._save_history(history)
        return entry

    def _load_history(self) -> List[Dict]:
        """Load device history."""
        if HISTORY_FILE.exists():
            try:
                with open(HISTORY_FILE) as f:
                    return json.load(f)
            except Exception:
                pass
        return []

    def _save_history(self, history: List[Dict]):
        """Save device history."""
        try:
            with open(HISTORY_FILE, 'w') as f:
                json.dump(history, f)
        except Exception:
            pass

    def get_device_history(self, mac: str = None, limit: int = 100) -> List[DeviceHistoryEntry]:
        """Get device history, optionally filtered by MAC."""
        history = self._load_history()

        if mac:
            history = [h for h in history if h.get("mac", "").upper() == mac.upper()]

        # Return most recent first
        history = sorted(history, key=lambda x: x.get("timestamp", ""), reverse=True)
        return [DeviceHistoryEntry(**h) for h in history[:limit]]

    def cleanup_old_history(self, days: int = HISTORY_RETENTION_DAYS) -> int:
        """Remove history entries older than specified days."""
        cutoff = (datetime.utcnow() - timedelta(days=days)).isoformat() + "Z"
        history = self._load_history()
        original_count = len(history)

        history = [h for h in history if h.get("timestamp", "") >= cutoff]
        self._save_history(history)

        return original_count - len(history)

    async def send_webhook(self, event: str, data: Dict[str, Any]):
        """Send webhook notification."""
        webhooks = self._load_webhooks()

        for wh in webhooks:
            if not wh.enabled or event not in wh.events:
                continue

            payload = {
                "event": event,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "data": data
            }

            try:
                headers = {"Content-Type": "application/json"}
                if wh.secret:
                    import hashlib
                    import hmac
                    sig = hmac.new(
                        wh.secret.encode(),
                        json.dumps(payload).encode(),
                        hashlib.sha256
                    ).hexdigest()
                    headers["X-Webhook-Signature"] = sig

                async with httpx.AsyncClient() as client:
                    await client.post(wh.url, json=payload, headers=headers, timeout=wh.timeout)
            except Exception:
                pass

    def _load_webhooks(self) -> List[WebhookConfig]:
        """Load webhook configurations."""
        if WEBHOOKS_FILE.exists():
            try:
                with open(WEBHOOKS_FILE) as f:
                    return [WebhookConfig(**wh) for wh in json.load(f)]
            except Exception:
                pass
        return []

    def _save_webhooks(self, webhooks: List[WebhookConfig]):
        """Save webhook configurations."""
        try:
            with open(WEBHOOKS_FILE, 'w') as f:
                json.dump([wh.dict() for wh in webhooks], f, indent=2)
        except Exception:
            pass

    def load_scan_state(self) -> ScanState:
        """Load scan state."""
        if SCAN_STATE_FILE.exists():
            try:
                with open(SCAN_STATE_FILE) as f:
                    return ScanState(**json.load(f))
            except Exception:
                pass
        return ScanState()

    def save_scan_state(self, state: ScanState):
        """Save scan state."""
        try:
            with open(SCAN_STATE_FILE, 'w') as f:
                json.dump(state.dict(), f, indent=2)
        except Exception:
            pass


# Groups management functions
def _load_groups() -> Dict[str, DeviceGroup]:
    """Load device groups."""
    if GROUPS_FILE.exists():
        try:
            with open(GROUPS_FILE) as f:
                data = json.load(f)
                return {k: DeviceGroup(**v) for k, v in data.items()}
        except Exception:
            pass
    return {}


def _save_groups(groups: Dict[str, DeviceGroup]):
    """Save device groups."""
    try:
        with open(GROUPS_FILE, 'w') as f:
            json.dump({k: v.dict() for k, v in groups.items()}, f, indent=2)
    except Exception:
        pass


# Global manager instance (lazily initialized)
_intel_manager: Optional[DeviceIntelManager] = None


def get_intel_manager() -> DeviceIntelManager:
    """Get or create the global intel manager instance."""
    global _intel_manager
    if _intel_manager is None:
        _intel_manager = DeviceIntelManager()
    return _intel_manager


# Convenience alias for direct access (lazily initialized via property)
class _IntelManagerProxy:
    """Proxy that provides lazy access to intel_manager."""
    def __getattr__(self, name):
        return getattr(get_intel_manager(), name)

intel_manager = _IntelManagerProxy()


class DeviceTag(BaseModel):
    mac: str
    tags: list[str]


class OpenWRTProbeResult(BaseModel):
    ip: str
    is_openwrt: bool
    luci_detected: bool
    secubox_detected: bool
    version: Optional[str] = None
    hostname: Optional[str] = None


def _load_oui_db() -> dict:
    """Load MAC vendor database."""
    oui = {}
    if not os.path.exists(OUI_DB_PATH):
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


def _get_vendor(mac: str, oui_db: dict) -> str:
    """Look up vendor from MAC address."""
    mac_upper = mac.upper().replace("-", ":")
    prefix = mac_upper[:8]
    return oui_db.get(prefix, "Unknown")


def _is_router_vendor(mac: str) -> tuple[bool, str]:
    """Check if MAC belongs to a known router vendor."""
    mac_upper = mac.upper().replace("-", ":")
    prefix = mac_upper[:8]

    for vendor, prefixes in ROUTER_VENDORS.items():
        for p in prefixes:
            if prefix.startswith(p.upper()):
                return True, vendor
    return False, ""


def _is_openwrt_hostname(hostname: str) -> bool:
    """Check if hostname matches OpenWRT patterns."""
    if not hostname:
        return False
    hostname_lower = hostname.lower()
    for pattern in OPENWRT_HOSTNAMES:
        if re.match(pattern, hostname_lower):
            return True
    return False


def _load_devices() -> dict:
    """Load known devices from state file."""
    if os.path.exists(DEVICES_FILE):
        try:
            with open(DEVICES_FILE, 'r') as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def _save_devices(devices: dict):
    """Save devices to state file."""
    try:
        with open(DEVICES_FILE, 'w') as f:
            json.dump(devices, f, indent=2)
    except Exception:
        pass


def _get_arp_table() -> list[dict]:
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


def _get_dhcp_leases() -> dict:
    """Get DHCP lease information."""
    leases = {}

    # Try dnsmasq format first
    if os.path.exists(DNSMASQ_LEASES):
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

    # Try ISC DHCP format
    if os.path.exists(DHCP_LEASES):
        try:
            with open(DHCP_LEASES, 'r') as f:
                content = f.read()
                lease_blocks = re.findall(r'lease\s+([\d.]+)\s*{([^}]+)}', content, re.MULTILINE)
                for ip, block in lease_blocks:
                    mac_match = re.search(r'hardware ethernet\s+([0-9a-fA-F:]+)', block)
                    hostname_match = re.search(r'client-hostname\s+"([^"]+)"', block)
                    if mac_match:
                        mac = mac_match.group(1).upper()
                        leases[mac] = {
                            "ip": ip,
                            "hostname": hostname_match.group(1) if hostname_match else "",
                            "expires": 0
                        }
        except Exception:
            pass

    return leases


async def _probe_luci(ip: str, timeout: float = 2.0) -> dict:
    """Probe an IP for LuCI/OpenWRT interface."""
    result = {
        "luci_detected": False,
        "secubox_detected": False,
        "version": None,
        "model": None,
        "gl_inet": False,
        "secubox_theme": None
    }

    async def curl_get(url: str, return_body: bool = False) -> tuple[str, str]:
        """Helper to run curl and return status code and optionally body."""
        args = ["curl", "-s", "--connect-timeout", str(timeout), "-k"]
        if not return_body:
            args.extend(["-o", "/dev/null", "-w", "%{http_code}"])
        args.append(url)
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout + 1)
        return stdout.decode().strip(), stdout.decode() if return_body else ""

    # Try HTTP probe for LuCI
    for scheme in ["http", "https"]:
        if result["luci_detected"]:
            break
        try:
            code, _ = await curl_get(f"{scheme}://{ip}/cgi-bin/luci")
            if code in ["200", "301", "302", "401", "403"]:
                result["luci_detected"] = True

                # Get LuCI page to extract version/model
                _, body = await curl_get(f"{scheme}://{ip}/cgi-bin/luci", return_body=True)
                body_lower = body.lower()

                # Extract model from title (e.g., "GL-MT3000 - Dashboard - LuCI")
                import re
                model_match = re.search(r'<title>([^<]+)</title>', body, re.IGNORECASE)
                if model_match:
                    title = model_match.group(1)
                    if " - " in title:
                        result["model"] = title.split(" - ")[0].strip()

                # Extract LuCI version
                ver_match = re.search(r'git-[\d.]+-[a-f0-9]+', body)
                if ver_match:
                    result["version"] = ver_match.group(0)

                # Check for SecuBox - look for specific markers
                secubox_markers = [
                    "data-secubox-theme",
                    "luci-static/secubox",
                    "secubox-auth-hook",
                    "secubox-portal",
                    "secubox-public",
                    "luci-app-secubox",
                    "/luci/admin/secubox",
                    "secubox-dashboard",
                ]
                for marker in secubox_markers:
                    if marker in body_lower:
                        result["secubox_detected"] = True
                        break

                # Extract SecuBox theme if present
                theme_match = re.search(r'data-secubox-theme="([^"]+)"', body)
                if theme_match:
                    result["secubox_theme"] = theme_match.group(1)

                # Try alternative LuCI version format (e.g., luci.js?v=26.021.66732~...)
                if not result["version"]:
                    alt_ver_match = re.search(r'luci\.js\?v=([\d.~a-f0-9-]+)', body)
                    if alt_ver_match:
                        result["version"] = alt_ver_match.group(1)

        except (asyncio.TimeoutError, Exception):
            pass

    # Check for GL.iNet custom UI
    if not result["luci_detected"]:
        try:
            _, body = await curl_get(f"http://{ip}/", return_body=True)
            if "gl-ui" in body.lower() or "gl.inet" in body.lower():
                result["gl_inet"] = True
                # GL.iNet routers have LuCI at /cgi-bin/luci
                result["luci_detected"] = True
        except (asyncio.TimeoutError, Exception):
            pass

    return result


async def _discover_mdns_services() -> list[dict]:
    """Discover devices via mDNS/Avahi."""
    services = []

    try:
        # Use avahi-browse to discover services
        proc = await asyncio.create_subprocess_exec(
            "avahi-browse", "-t", "-r", "-p", "_http._tcp",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)

        for line in stdout.decode().split('\n'):
            if line.startswith('='):
                parts = line.split(';')
                if len(parts) >= 8:
                    services.append({
                        "name": parts[3],
                        "type": parts[4],
                        "hostname": parts[6],
                        "ip": parts[7],
                        "port": int(parts[8]) if parts[8].isdigit() else 80
                    })
    except (asyncio.TimeoutError, FileNotFoundError, Exception):
        pass

    return services


async def _scan_network(interface: str = "eth0", subnet: str = None) -> list[dict]:
    """Perform ARP scan on network."""
    devices = []

    if not subnet:
        try:
            result = subprocess.run(
                ["ip", "-4", "addr", "show", interface],
                capture_output=True, text=True, timeout=5
            )
            match = re.search(r'inet\s+(\d+\.\d+\.\d+)\.\d+/(\d+)', result.stdout)
            if match:
                subnet = f"{match.group(1)}.0/{match.group(2)}"
        except Exception:
            subnet = "192.168.1.0/24"

    try:
        result = subprocess.run(
            ["nmap", "-sn", "-PR", subnet, "-oG", "-"],
            capture_output=True, text=True, timeout=60
        )
        for line in result.stdout.split('\n'):
            if "Host:" in line and "Status: Up" in line:
                ip_match = re.search(r'Host:\s+(\d+\.\d+\.\d+\.\d+)', line)
                if ip_match:
                    devices.append({"ip": ip_match.group(1)})
    except FileNotFoundError:
        try:
            for i in range(1, 255):
                ip = f"{subnet.rsplit('.', 2)[0]}.{i}"
                subprocess.run(
                    ["arping", "-c", "1", "-w", "1", ip],
                    capture_output=True, timeout=2
                )
        except Exception:
            pass

    return devices


def _get_network_interfaces() -> list[dict]:
    """Get list of network interfaces."""
    interfaces = []
    try:
        result = subprocess.run(
            ["ip", "-j", "link", "show"],
            capture_output=True, text=True, timeout=10
        )
        data = json.loads(result.stdout)
        for iface in data:
            if iface.get("ifname") not in ["lo"]:
                interfaces.append({
                    "name": iface.get("ifname", ""),
                    "mac": iface.get("address", ""),
                    "state": iface.get("operstate", "UNKNOWN"),
                    "mtu": iface.get("mtu", 1500)
                })
    except Exception:
        try:
            result = subprocess.run(
                ["ip", "link", "show"],
                capture_output=True, text=True, timeout=10
            )
            for line in result.stdout.split('\n'):
                match = re.match(r'^\d+:\s+(\w+):', line)
                if match and match.group(1) != "lo":
                    interfaces.append({"name": match.group(1)})
        except Exception:
            pass
    return interfaces


@app.get("/status")
async def status():
    """Public status endpoint."""
    scan_state = intel_manager.load_scan_state()
    return {
        "module": "device-intel",
        "status": "ok",
        "version": "2.0.0",
        "features": [
            "arp_scan", "dhcp_leases", "vendor_lookup", "openwrt_detection",
            "mdns_discovery", "device_history", "device_groups", "scheduled_scan",
            "export_csv", "export_json", "webhooks"
        ],
        "scan_enabled": scan_state.enabled,
        "last_scan": scan_state.last_scan
    }


@app.get("/devices", dependencies=[Depends(require_jwt)])
async def get_devices():
    """Get all discovered devices with enriched data."""
    oui_db = intel_manager.oui_db
    known_devices = _load_devices()
    arp_devices = _get_arp_table()
    dhcp_leases = _get_dhcp_leases()
    groups = _load_groups()

    devices = []
    seen_macs = set()

    for dev in arp_devices:
        mac = dev["mac"]
        if mac in seen_macs:
            continue
        seen_macs.add(mac)

        lease = dhcp_leases.get(mac, {})
        known = known_devices.get(mac, {})
        hostname = lease.get("hostname", known.get("hostname", ""))

        # Check if it's a router vendor
        is_router, router_vendor = _is_router_vendor(mac)
        is_openwrt = _is_openwrt_hostname(hostname) or known.get("is_openwrt", False)

        # Find groups this device belongs to
        device_groups = [g.id for g in groups.values() if mac in g.members]

        devices.append({
            "mac": mac,
            "ip": dev["ip"],
            "interface": dev["interface"],
            "state": dev["state"],
            "vendor": _get_vendor(mac, oui_db),
            "hostname": hostname,
            "first_seen": known.get("first_seen", datetime.now().isoformat()),
            "last_seen": datetime.now().isoformat(),
            "note": known.get("note", ""),
            "tags": known.get("tags", []),
            "groups": device_groups,
            "trusted": known.get("trusted", False),
            "is_router": is_router,
            "router_vendor": router_vendor,
            "is_openwrt": is_openwrt,
            "is_secubox": known.get("is_secubox", False),
            "secubox_version": known.get("secubox_version", None),
        })

    return {
        "devices": devices,
        "total": len(devices),
        "routers": sum(1 for d in devices if d["is_router"]),
        "openwrt_devices": sum(1 for d in devices if d["is_openwrt"]),
        "secubox_devices": sum(1 for d in devices if d["is_secubox"]),
        "groups_count": len(groups)
    }


@app.get("/device/{mac}", dependencies=[Depends(require_jwt)])
async def get_device(mac: str):
    """Get detailed info for a specific device."""
    oui_db = _load_oui_db()
    known_devices = _load_devices()
    arp_devices = _get_arp_table()
    dhcp_leases = _get_dhcp_leases()

    mac_upper = mac.upper()
    arp_info = next((d for d in arp_devices if d["mac"] == mac_upper), {})
    lease = dhcp_leases.get(mac_upper, {})
    known = known_devices.get(mac_upper, {})

    if not arp_info and not known:
        raise HTTPException(status_code=404, detail="Device not found")

    hostname = lease.get("hostname", known.get("hostname", ""))
    is_router, router_vendor = _is_router_vendor(mac_upper)
    is_openwrt = _is_openwrt_hostname(hostname) or known.get("is_openwrt", False)

    return {
        "mac": mac_upper,
        "ip": arp_info.get("ip", lease.get("ip", known.get("ip", ""))),
        "interface": arp_info.get("interface", ""),
        "state": arp_info.get("state", "UNKNOWN"),
        "vendor": _get_vendor(mac_upper, oui_db),
        "hostname": hostname,
        "first_seen": known.get("first_seen", datetime.now().isoformat()),
        "last_seen": datetime.now().isoformat(),
        "note": known.get("note", ""),
        "tags": known.get("tags", []),
        "trusted": known.get("trusted", False),
        "lease_expires": lease.get("expires", 0),
        "is_router": is_router,
        "router_vendor": router_vendor,
        "is_openwrt": is_openwrt,
        "is_secubox": known.get("is_secubox", False),
        "secubox_version": known.get("secubox_version", None),
    }


@app.post("/device/note", dependencies=[Depends(require_jwt)])
async def set_device_note(data: DeviceNote):
    """Set a note for a device."""
    devices = _load_devices()
    mac = data.mac.upper()

    if mac not in devices:
        devices[mac] = {"first_seen": datetime.now().isoformat()}

    devices[mac]["note"] = data.note
    _save_devices(devices)

    return {"success": True, "mac": mac}


@app.post("/device/tags", dependencies=[Depends(require_jwt)])
async def set_device_tags(data: DeviceTag):
    """Set tags for a device."""
    devices = _load_devices()
    mac = data.mac.upper()

    if mac not in devices:
        devices[mac] = {"first_seen": datetime.now().isoformat()}

    devices[mac]["tags"] = data.tags
    _save_devices(devices)

    return {"success": True, "mac": mac}


@app.post("/device/{mac}/trust", dependencies=[Depends(require_jwt)])
async def trust_device(mac: str, trusted: bool = True):
    """Mark a device as trusted or untrusted."""
    devices = _load_devices()
    mac_upper = mac.upper()

    if mac_upper not in devices:
        devices[mac_upper] = {"first_seen": datetime.now().isoformat()}

    devices[mac_upper]["trusted"] = trusted
    _save_devices(devices)

    return {"success": True, "mac": mac_upper, "trusted": trusted}


@app.post("/scan", dependencies=[Depends(require_jwt)])
async def scan_network(interface: str = "eth0"):
    """Trigger network scan for device discovery."""
    await _scan_network(interface)
    arp_devices = _get_arp_table()

    return {
        "success": True,
        "interface": interface,
        "devices_found": len(arp_devices)
    }


@app.post("/probe/openwrt", dependencies=[Depends(require_jwt)])
async def probe_openwrt_devices():
    """Probe all devices for OpenWRT/LuCI interface."""
    arp_devices = _get_arp_table()
    known_devices = _load_devices()
    results = []

    # Probe each device in parallel (max 10 concurrent)
    semaphore = asyncio.Semaphore(10)

    async def probe_with_semaphore(dev):
        async with semaphore:
            ip = dev["ip"]
            mac = dev["mac"]
            probe_result = await _probe_luci(ip, timeout=3.0)

            # Update known devices if OpenWRT detected
            if probe_result["luci_detected"]:
                if mac not in known_devices:
                    known_devices[mac] = {"first_seen": datetime.now().isoformat()}
                known_devices[mac]["is_openwrt"] = True
                known_devices[mac]["is_secubox"] = probe_result["secubox_detected"]
                known_devices[mac]["is_gl_inet"] = probe_result.get("gl_inet", False)
                known_devices[mac]["model"] = probe_result.get("model")
                known_devices[mac]["luci_version"] = probe_result.get("version")
                known_devices[mac]["ip"] = ip
                known_devices[mac]["last_probed"] = datetime.now().isoformat()

            return {
                "ip": ip,
                "mac": mac,
                "is_openwrt": probe_result["luci_detected"],
                "is_secubox": probe_result["secubox_detected"],
                "is_gl_inet": probe_result.get("gl_inet", False),
                "model": probe_result.get("model"),
                "version": probe_result.get("version")
            }

    tasks = [probe_with_semaphore(dev) for dev in arp_devices]
    results = await asyncio.gather(*tasks)

    # Save updated device info
    _save_devices(known_devices)

    openwrt_count = sum(1 for r in results if r["is_openwrt"])
    secubox_count = sum(1 for r in results if r["is_secubox"])

    return {
        "success": True,
        "total_probed": len(results),
        "openwrt_detected": openwrt_count,
        "secubox_detected": secubox_count,
        "results": results
    }


@app.post("/probe/openwrt/{ip}", dependencies=[Depends(require_jwt)])
async def probe_single_openwrt(ip: str):
    """Probe a single IP for OpenWRT/LuCI interface."""
    probe_result = await _probe_luci(ip, timeout=5.0)

    # Get MAC from ARP if available
    mac = None
    for dev in _get_arp_table():
        if dev["ip"] == ip:
            mac = dev["mac"]
            break

    # Check MAC vendor
    vendor = None
    is_router = False
    if mac:
        mac_prefix = mac[:8].upper()
        for vendor_name, prefixes in ROUTER_VENDORS.items():
            if mac_prefix in prefixes:
                vendor = vendor_name
                is_router = True
                break
        if not vendor:
            oui_db = _load_oui_db()
            vendor = _get_vendor(mac, oui_db)

    return {
        "ip": ip,
        "mac": mac,
        "vendor": vendor,
        "is_router": is_router,
        "is_openwrt": probe_result["luci_detected"],
        "is_secubox": probe_result["secubox_detected"],
        "is_gl_inet": probe_result.get("gl_inet", False),
        "model": probe_result.get("model"),
        "version": probe_result.get("version"),
        "secubox_theme": probe_result.get("secubox_theme")
    }


@app.get("/openwrt", dependencies=[Depends(require_jwt)])
async def get_openwrt_devices():
    """Get all detected OpenWRT/SecuBox devices."""
    known_devices = _load_devices()
    arp_devices = _get_arp_table()
    dhcp_leases = _get_dhcp_leases()
    oui_db = _load_oui_db()

    openwrt_devices = []

    for mac, info in known_devices.items():
        if info.get("is_openwrt") or info.get("is_secubox"):
            arp_info = next((d for d in arp_devices if d["mac"] == mac), {})
            lease = dhcp_leases.get(mac, {})

            openwrt_devices.append({
                "mac": mac,
                "ip": arp_info.get("ip", info.get("ip", "")),
                "hostname": lease.get("hostname", info.get("hostname", "")),
                "vendor": _get_vendor(mac, oui_db),
                "is_openwrt": info.get("is_openwrt", False),
                "is_secubox": info.get("is_secubox", False),
                "is_gl_inet": info.get("is_gl_inet", False),
                "model": info.get("model"),
                "luci_version": info.get("luci_version"),
                "secubox_version": info.get("secubox_version"),
                "online": bool(arp_info),
                "last_probed": info.get("last_probed"),
                "first_seen": info.get("first_seen"),
            })

    return {
        "devices": openwrt_devices,
        "total": len(openwrt_devices),
        "online": sum(1 for d in openwrt_devices if d["online"])
    }


@app.get("/mdns", dependencies=[Depends(require_jwt)])
async def discover_mdns():
    """Discover devices via mDNS/Avahi."""
    services = await _discover_mdns_services()
    return {
        "services": services,
        "total": len(services)
    }


@app.get("/interfaces", dependencies=[Depends(require_jwt)])
async def get_interfaces():
    """Get list of network interfaces."""
    return {"interfaces": _get_network_interfaces()}


@app.get("/stats", dependencies=[Depends(require_jwt)])
async def get_stats():
    """Get device discovery statistics."""
    known_devices = _load_devices()
    arp_devices = _get_arp_table()

    trusted = sum(1 for d in known_devices.values() if d.get("trusted", False))
    tagged = sum(1 for d in known_devices.values() if d.get("tags", []))
    openwrt = sum(1 for d in known_devices.values() if d.get("is_openwrt", False))
    secubox = sum(1 for d in known_devices.values() if d.get("is_secubox", False))
    gl_inet = sum(1 for d in known_devices.values() if d.get("is_gl_inet", False))

    return {
        "total_known": len(known_devices),
        "currently_online": len(arp_devices),
        "trusted_devices": trusted,
        "tagged_devices": tagged,
        "openwrt_devices": openwrt,
        "secubox_devices": secubox,
        "gl_inet_devices": gl_inet
    }


@app.get("/info", dependencies=[Depends(require_jwt)])
async def info():
    """Protected info endpoint."""
    return {"config": dict(config)}


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy", "service": "secubox-device-intel", "version": "2.0.0"}


# ============================================================================
# Device History Endpoints
# ============================================================================

@app.get("/history", dependencies=[Depends(require_jwt)])
async def get_history(mac: str = None, limit: int = 100):
    """Get device connection history."""
    history = intel_manager.get_device_history(mac, limit)
    return {
        "history": [h.dict() for h in history],
        "count": len(history),
        "filter_mac": mac
    }


@app.post("/history/cleanup", dependencies=[Depends(require_jwt)])
async def cleanup_history(days: int = 30):
    """Clean up old history entries."""
    removed = intel_manager.cleanup_old_history(days)
    return {"removed": removed, "retention_days": days}


# ============================================================================
# Device Groups Endpoints
# ============================================================================

@app.get("/groups", dependencies=[Depends(require_jwt)])
async def list_groups():
    """List all device groups."""
    groups = _load_groups()
    return {
        "groups": [g.dict() for g in groups.values()],
        "count": len(groups)
    }


@app.get("/groups/{group_id}", dependencies=[Depends(require_jwt)])
async def get_group(group_id: str):
    """Get a specific group."""
    groups = _load_groups()
    if group_id not in groups:
        raise HTTPException(status_code=404, detail="Group not found")
    return groups[group_id].dict()


class CreateGroupRequest(BaseModel):
    name: str
    description: Optional[str] = None
    color: str = "#3498db"
    icon: str = "devices"


@app.post("/groups", dependencies=[Depends(require_jwt)])
async def create_group(request: CreateGroupRequest):
    """Create a new device group."""
    import uuid
    groups = _load_groups()

    group_id = str(uuid.uuid4())[:8]
    group = DeviceGroup(
        id=group_id,
        name=request.name,
        description=request.description,
        color=request.color,
        icon=request.icon,
        created_at=datetime.utcnow().isoformat() + "Z"
    )

    groups[group_id] = group
    _save_groups(groups)

    return {"status": "created", "group": group.dict()}


@app.put("/groups/{group_id}", dependencies=[Depends(require_jwt)])
async def update_group(group_id: str, request: CreateGroupRequest):
    """Update a group."""
    groups = _load_groups()
    if group_id not in groups:
        raise HTTPException(status_code=404, detail="Group not found")

    group = groups[group_id]
    group.name = request.name
    group.description = request.description
    group.color = request.color
    group.icon = request.icon
    group.updated_at = datetime.utcnow().isoformat() + "Z"

    _save_groups(groups)
    return {"status": "updated", "group": group.dict()}


@app.delete("/groups/{group_id}", dependencies=[Depends(require_jwt)])
async def delete_group(group_id: str):
    """Delete a group."""
    groups = _load_groups()
    if group_id not in groups:
        raise HTTPException(status_code=404, detail="Group not found")

    del groups[group_id]
    _save_groups(groups)
    return {"status": "deleted"}


@app.post("/groups/{group_id}/members", dependencies=[Depends(require_jwt)])
async def add_group_member(group_id: str, mac: str):
    """Add a device to a group."""
    groups = _load_groups()
    if group_id not in groups:
        raise HTTPException(status_code=404, detail="Group not found")

    mac_upper = mac.upper()
    if mac_upper not in groups[group_id].members:
        groups[group_id].members.append(mac_upper)
        groups[group_id].updated_at = datetime.utcnow().isoformat() + "Z"
        _save_groups(groups)

    return {"status": "added", "mac": mac_upper}


@app.delete("/groups/{group_id}/members/{mac}", dependencies=[Depends(require_jwt)])
async def remove_group_member(group_id: str, mac: str):
    """Remove a device from a group."""
    groups = _load_groups()
    if group_id not in groups:
        raise HTTPException(status_code=404, detail="Group not found")

    mac_upper = mac.upper()
    if mac_upper in groups[group_id].members:
        groups[group_id].members.remove(mac_upper)
        groups[group_id].updated_at = datetime.utcnow().isoformat() + "Z"
        _save_groups(groups)

    return {"status": "removed"}


@app.get("/device/{mac}/groups", dependencies=[Depends(require_jwt)])
async def get_device_groups(mac: str):
    """Get groups a device belongs to."""
    mac_upper = mac.upper()
    groups = _load_groups()
    device_groups = [g.dict() for g in groups.values() if mac_upper in g.members]
    return {"mac": mac_upper, "groups": device_groups}


# ============================================================================
# Export Endpoints
# ============================================================================

@app.get("/export/json", dependencies=[Depends(require_jwt)])
async def export_json():
    """Export all devices as JSON."""
    oui_db = _load_oui_db()
    known_devices = _load_devices()
    arp_devices = _get_arp_table()
    dhcp_leases = _get_dhcp_leases()
    groups = _load_groups()

    devices = []
    seen_macs = set()

    for dev in arp_devices:
        mac = dev["mac"]
        if mac in seen_macs:
            continue
        seen_macs.add(mac)

        lease = dhcp_leases.get(mac, {})
        known = known_devices.get(mac, {})
        hostname = lease.get("hostname", known.get("hostname", ""))
        is_router, router_vendor = _is_router_vendor(mac)

        # Find groups this device belongs to
        device_groups = [g.id for g in groups.values() if mac in g.members]

        devices.append({
            "mac": mac,
            "ip": dev["ip"],
            "interface": dev["interface"],
            "state": dev["state"],
            "vendor": _get_vendor(mac, oui_db),
            "hostname": hostname,
            "first_seen": known.get("first_seen"),
            "last_seen": datetime.utcnow().isoformat(),
            "note": known.get("note", ""),
            "tags": known.get("tags", []),
            "groups": device_groups,
            "trusted": known.get("trusted", False),
            "is_router": is_router,
            "router_vendor": router_vendor,
            "is_openwrt": known.get("is_openwrt", False),
            "is_secubox": known.get("is_secubox", False),
        })

    export_data = {
        "exported_at": datetime.utcnow().isoformat() + "Z",
        "device_count": len(devices),
        "devices": devices
    }

    return Response(
        content=json.dumps(export_data, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=devices.json"}
    )


@app.get("/export/csv", dependencies=[Depends(require_jwt)])
async def export_csv():
    """Export all devices as CSV."""
    oui_db = _load_oui_db()
    known_devices = _load_devices()
    arp_devices = _get_arp_table()
    dhcp_leases = _get_dhcp_leases()

    output = io.StringIO()
    writer = csv.writer(output)

    # Header row
    writer.writerow([
        "MAC", "IP", "Vendor", "Hostname", "Interface", "State",
        "First Seen", "Last Seen", "Trusted", "Is Router", "Router Vendor",
        "Is OpenWRT", "Is SecuBox", "Tags", "Note"
    ])

    seen_macs = set()
    for dev in arp_devices:
        mac = dev["mac"]
        if mac in seen_macs:
            continue
        seen_macs.add(mac)

        lease = dhcp_leases.get(mac, {})
        known = known_devices.get(mac, {})
        hostname = lease.get("hostname", known.get("hostname", ""))
        is_router, router_vendor = _is_router_vendor(mac)

        writer.writerow([
            mac,
            dev["ip"],
            _get_vendor(mac, oui_db),
            hostname,
            dev["interface"],
            dev["state"],
            known.get("first_seen", ""),
            datetime.utcnow().isoformat(),
            known.get("trusted", False),
            is_router,
            router_vendor,
            known.get("is_openwrt", False),
            known.get("is_secubox", False),
            ";".join(known.get("tags", [])),
            known.get("note", "")
        ])

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=devices.csv"}
    )


# ============================================================================
# Webhooks Endpoints
# ============================================================================

@app.get("/webhooks", dependencies=[Depends(require_jwt)])
async def list_webhooks():
    """List configured webhooks."""
    webhooks = intel_manager._load_webhooks()
    return {"webhooks": [wh.dict() for wh in webhooks]}


class AddWebhookRequest(BaseModel):
    url: str
    events: List[str] = ["new_device", "device_offline"]
    secret: Optional[str] = None
    timeout: float = 5.0


@app.post("/webhooks", dependencies=[Depends(require_jwt)])
async def add_webhook(request: AddWebhookRequest):
    """Add a webhook configuration."""
    webhooks = intel_manager._load_webhooks()

    for wh in webhooks:
        if wh.url == request.url:
            raise HTTPException(status_code=409, detail="Webhook URL already exists")

    new_webhook = WebhookConfig(
        url=request.url,
        events=request.events,
        secret=request.secret,
        timeout=request.timeout
    )
    webhooks.append(new_webhook)
    intel_manager._save_webhooks(webhooks)

    return {"status": "added", "webhook": new_webhook.dict()}


@app.delete("/webhooks", dependencies=[Depends(require_jwt)])
async def remove_webhook(url: str):
    """Remove a webhook by URL."""
    webhooks = intel_manager._load_webhooks()
    original_count = len(webhooks)
    webhooks = [wh for wh in webhooks if wh.url != url]

    if len(webhooks) == original_count:
        raise HTTPException(status_code=404, detail="Webhook not found")

    intel_manager._save_webhooks(webhooks)
    return {"status": "removed"}


# ============================================================================
# Scheduled Scanning Endpoints
# ============================================================================

@app.get("/scan/state", dependencies=[Depends(require_jwt)])
async def get_scan_state():
    """Get scheduled scan state."""
    state = intel_manager.load_scan_state()
    return state.dict()


class UpdateScanStateRequest(BaseModel):
    enabled: bool
    interval_seconds: int = Field(ge=60, le=3600)


@app.put("/scan/state", dependencies=[Depends(require_jwt)])
async def update_scan_state(request: UpdateScanStateRequest):
    """Update scheduled scan configuration."""
    state = intel_manager.load_scan_state()
    state.enabled = request.enabled
    state.interval_seconds = request.interval_seconds

    if state.enabled and state.last_scan:
        last = datetime.fromisoformat(state.last_scan.rstrip("Z"))
        next_scan = last + timedelta(seconds=state.interval_seconds)
        state.next_scan = next_scan.isoformat() + "Z"

    intel_manager.save_scan_state(state)
    return {"status": "updated", "state": state.dict()}


@app.post("/scan/now", dependencies=[Depends(require_jwt)])
async def trigger_scan(background_tasks: BackgroundTasks, interface: str = "eth0"):
    """Trigger an immediate network scan."""
    background_tasks.add_task(run_discovery_scan, interface)
    return {"status": "scan_triggered", "interface": interface}


async def run_discovery_scan(interface: str = "eth0"):
    """Run a discovery scan and track new devices."""
    with intel_manager._scan_lock:
        known_devices = _load_devices()
        previous_macs = set(known_devices.keys())

        # Run network scan
        await _scan_network(interface)
        arp_devices = _get_arp_table()

        new_devices = []
        for dev in arp_devices:
            mac = dev["mac"]

            # Track as known
            if mac not in known_devices:
                known_devices[mac] = {
                    "first_seen": datetime.utcnow().isoformat() + "Z",
                    "ip": dev["ip"]
                }

                # Record history and send webhook for new device
                intel_manager.record_history(mac, DeviceEvent.FIRST_SEEN, dev["ip"])
                intel_manager.register_device(mac)
                new_devices.append({"mac": mac, "ip": dev["ip"]})

                # Send webhook
                await intel_manager.send_webhook("new_device", {
                    "mac": mac,
                    "ip": dev["ip"],
                    "interface": interface
                })

            # Update last seen
            known_devices[mac]["last_seen"] = datetime.utcnow().isoformat() + "Z"
            known_devices[mac]["ip"] = dev["ip"]

        _save_devices(known_devices)

        # Update scan state
        state = intel_manager.load_scan_state()
        state.last_scan = datetime.utcnow().isoformat() + "Z"
        state.devices_found_last = len(arp_devices)
        state.new_devices_last = len(new_devices)
        if state.enabled:
            next_scan = datetime.utcnow() + timedelta(seconds=state.interval_seconds)
            state.next_scan = next_scan.isoformat() + "Z"
        intel_manager.save_scan_state(state)

        return {
            "devices_found": len(arp_devices),
            "new_devices": len(new_devices),
            "new_device_list": new_devices
        }


# ============================================================================
# Startup / Shutdown
# ============================================================================

background_scan_task: Optional[asyncio.Task] = None


async def periodic_scan():
    """Background task for periodic network scanning."""
    while True:
        try:
            state = intel_manager.load_scan_state()
            if state.enabled:
                await asyncio.sleep(state.interval_seconds)
                await run_discovery_scan()
            else:
                await asyncio.sleep(60)  # Check state every minute when disabled
        except asyncio.CancelledError:
            break
        except Exception:
            await asyncio.sleep(60)


@app.on_event("startup")
async def startup():
    """Initialize on startup."""
    global background_scan_task
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    background_scan_task = asyncio.create_task(periodic_scan())


@app.on_event("shutdown")
async def shutdown():
    """Cleanup on shutdown."""
    global background_scan_task
    if background_scan_task:
        background_scan_task.cancel()
        try:
            await background_scan_task
        except asyncio.CancelledError:
            pass
