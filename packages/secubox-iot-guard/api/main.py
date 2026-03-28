"""SecuBox IoT Guard - IoT Device Security Management
Discovers, classifies, and monitors IoT devices on the network.

Features:
- Network device discovery (ARP, mDNS, SSDP)
- OUI-based manufacturer identification
- Device fingerprinting and classification
- Risk scoring based on behavior
- Quarantine management
- Firmware vulnerability tracking
"""
import os
import re
import json
import time
import logging
import subprocess
import sqlite3
import socket
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, List, Any
from enum import Enum

from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel, Field
import httpx

from secubox_core.auth import require_jwt
from secubox_core.config import get_config

# P2P API socket for mesh peer integration
P2P_SOCKET = "/run/secubox/p2p.sock"

# Configuration
CONFIG_PATH = Path("/etc/secubox/iot-guard.toml")
DATA_DIR = Path("/var/lib/secubox/iot-guard")
DB_FILE = DATA_DIR / "devices.db"
OUI_FILE = DATA_DIR / "oui.txt"
QUARANTINE_FILE = DATA_DIR / "quarantine.json"

app = FastAPI(title="SecuBox IoT Guard", version="1.0.0")
logger = logging.getLogger("secubox.iot-guard")


class DeviceType(str, Enum):
    UNKNOWN = "unknown"
    COMPUTER = "computer"
    PHONE = "phone"
    TABLET = "tablet"
    ROUTER = "router"
    PRINTER = "printer"
    CAMERA = "camera"
    SMART_TV = "smart_tv"
    SMART_SPEAKER = "smart_speaker"
    SMART_HOME = "smart_home"
    IOT_SENSOR = "iot_sensor"
    INDUSTRIAL = "industrial"
    NETWORK_DEVICE = "network_device"


class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    SAFE = "safe"


class QuarantineStatus(str, Enum):
    ACTIVE = "active"
    RELEASED = "released"
    PENDING = "pending"


class Device(BaseModel):
    mac_address: str
    ip_address: Optional[str] = None
    hostname: Optional[str] = None
    manufacturer: Optional[str] = None
    device_type: DeviceType = DeviceType.UNKNOWN
    model: Optional[str] = None
    firmware_version: Optional[str] = None
    os_fingerprint: Optional[str] = None
    risk_level: RiskLevel = RiskLevel.MEDIUM
    risk_score: int = Field(default=50, ge=0, le=100)
    first_seen: str
    last_seen: str
    is_known: bool = False
    is_quarantined: bool = False
    open_ports: List[int] = []
    services: List[str] = []
    tags: List[str] = []
    notes: str = ""


class QuarantineEntry(BaseModel):
    mac_address: str
    reason: str
    status: QuarantineStatus = QuarantineStatus.ACTIVE
    created_at: str
    released_at: Optional[str] = None
    expires_at: Optional[str] = None


class DeviceUpdate(BaseModel):
    hostname: Optional[str] = None
    device_type: Optional[DeviceType] = None
    is_known: Optional[bool] = None
    tags: Optional[List[str]] = None
    notes: Optional[str] = None


class IoTGuard:
    """Manages IoT device discovery and security."""

    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self.db_file = data_dir / "devices.db"
        self.oui_file = data_dir / "oui.txt"
        self.quarantine_file = data_dir / "quarantine.json"
        self._ensure_dirs()
        self._init_db()
        self._load_oui()
        self._load_quarantine()

        # Device type indicators
        self.type_indicators = {
            DeviceType.CAMERA: ["camera", "ipcam", "hikvision", "dahua", "axis", "wyze", "ring", "nest"],
            DeviceType.SMART_TV: ["tv", "roku", "firetv", "chromecast", "appletv", "samsung", "lg", "sony"],
            DeviceType.SMART_SPEAKER: ["echo", "alexa", "google-home", "homepod", "sonos"],
            DeviceType.SMART_HOME: ["philips-hue", "wemo", "smartthings", "tuya", "zigbee", "zwave"],
            DeviceType.PRINTER: ["printer", "hp", "epson", "canon", "brother", "xerox"],
            DeviceType.ROUTER: ["router", "gateway", "ubiquiti", "mikrotik", "cisco", "netgear"],
            DeviceType.PHONE: ["iphone", "android", "pixel", "samsung", "oneplus", "xiaomi"],
        }

        # Known risky manufacturers (cheap IoT)
        self.risky_manufacturers = [
            "tuya", "espressif", "shenzhen", "hangzhou", "realtek", "mediatek"
        ]

    def _ensure_dirs(self):
        self.data_dir.mkdir(parents=True, exist_ok=True)

    def _init_db(self):
        """Initialize SQLite database."""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                mac_address TEXT PRIMARY KEY,
                ip_address TEXT,
                hostname TEXT,
                manufacturer TEXT,
                device_type TEXT DEFAULT 'unknown',
                model TEXT,
                firmware_version TEXT,
                os_fingerprint TEXT,
                risk_level TEXT DEFAULT 'medium',
                risk_score INTEGER DEFAULT 50,
                first_seen TEXT,
                last_seen TEXT,
                is_known INTEGER DEFAULT 0,
                is_quarantined INTEGER DEFAULT 0,
                open_ports TEXT,
                services TEXT,
                tags TEXT,
                notes TEXT
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS device_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mac_address TEXT,
                event_type TEXT,
                details TEXT,
                timestamp TEXT
            )
        """)
        conn.commit()
        conn.close()

    def _load_oui(self):
        """Load OUI database for MAC address lookup."""
        self.oui_db: Dict[str, str] = {}
        if self.oui_file.exists():
            try:
                for line in self.oui_file.read_text().split("\n"):
                    if "(hex)" in line:
                        parts = line.split("(hex)")
                        if len(parts) == 2:
                            prefix = parts[0].strip().replace("-", ":").lower()
                            vendor = parts[1].strip()
                            self.oui_db[prefix] = vendor
            except Exception:
                pass

    def _load_quarantine(self):
        """Load quarantine list."""
        self.quarantine: Dict[str, QuarantineEntry] = {}
        if self.quarantine_file.exists():
            try:
                data = json.loads(self.quarantine_file.read_text())
                self.quarantine = {k: QuarantineEntry(**v) for k, v in data.items()}
            except Exception:
                pass

    def _save_quarantine(self):
        self.quarantine_file.write_text(json.dumps(
            {k: v.model_dump() for k, v in self.quarantine.items()}, indent=2
        ))

    def lookup_manufacturer(self, mac_address: str) -> Optional[str]:
        """Lookup manufacturer from OUI database."""
        prefix = mac_address[:8].lower()
        return self.oui_db.get(prefix)

    def classify_device(self, hostname: str, manufacturer: str) -> DeviceType:
        """Classify device based on hostname and manufacturer."""
        combined = f"{hostname or ''} {manufacturer or ''}".lower()

        for device_type, indicators in self.type_indicators.items():
            for indicator in indicators:
                if indicator in combined:
                    return device_type

        return DeviceType.UNKNOWN

    def calculate_risk_score(self, device: Device) -> int:
        """Calculate risk score based on device characteristics."""
        score = 50  # Base score

        # Unknown devices are riskier
        if not device.is_known:
            score += 15

        # Device type risk
        type_risk = {
            DeviceType.CAMERA: 20,
            DeviceType.IOT_SENSOR: 15,
            DeviceType.SMART_HOME: 15,
            DeviceType.INDUSTRIAL: 25,
            DeviceType.UNKNOWN: 10,
        }
        score += type_risk.get(device.device_type, 0)

        # Manufacturer risk
        if device.manufacturer:
            for risky in self.risky_manufacturers:
                if risky in device.manufacturer.lower():
                    score += 15
                    break

        # Open ports risk
        risky_ports = {23, 21, 80, 8080, 8443, 554}  # telnet, ftp, http, rtsp
        for port in device.open_ports:
            if port in risky_ports:
                score += 5

        return min(100, max(0, score))

    def discover_arp(self) -> List[Dict]:
        """Discover devices via ARP table."""
        devices = []
        try:
            result = subprocess.run(
                ["ip", "neigh", "show"],
                capture_output=True,
                text=True,
                timeout=10
            )
            for line in result.stdout.strip().split("\n"):
                parts = line.split()
                if len(parts) >= 5 and parts[3] == "lladdr":
                    devices.append({
                        "ip_address": parts[0],
                        "mac_address": parts[4].lower()
                    })
        except Exception as e:
            logger.warning(f"ARP discovery failed: {e}")

        return devices

    def discover_nmap(self, network: str = "192.168.1.0/24") -> List[Dict]:
        """Discover devices via nmap scan."""
        devices = []
        try:
            result = subprocess.run(
                ["nmap", "-sn", "-oX", "-", network],
                capture_output=True,
                text=True,
                timeout=120
            )
            # Parse XML output (simplified)
            import xml.etree.ElementTree as ET
            root = ET.fromstring(result.stdout)
            for host in root.findall(".//host"):
                addr = host.find("address[@addrtype='ipv4']")
                mac = host.find("address[@addrtype='mac']")
                hostname = host.find(".//hostname")
                if addr is not None:
                    device = {
                        "ip_address": addr.get("addr"),
                        "mac_address": mac.get("addr", "").lower() if mac is not None else None,
                        "hostname": hostname.get("name") if hostname is not None else None,
                        "manufacturer": mac.get("vendor") if mac is not None else None
                    }
                    devices.append(device)
        except Exception as e:
            logger.warning(f"nmap discovery failed: {e}")

        return devices

    def register_device(self, mac_address: str, ip_address: str = None,
                       hostname: str = None) -> Device:
        """Register or update a device."""
        mac_address = mac_address.lower()
        now = datetime.utcnow().isoformat() + "Z"

        # Check if device exists
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM devices WHERE mac_address = ?", (mac_address,))
        row = cursor.fetchone()

        if row:
            # Update existing device
            cursor.execute("""
                UPDATE devices SET ip_address = ?, last_seen = ?
                WHERE mac_address = ?
            """, (ip_address, now, mac_address))
            conn.commit()
            cursor.execute("SELECT * FROM devices WHERE mac_address = ?", (mac_address,))
            row = cursor.fetchone()
        else:
            # Create new device
            manufacturer = self.lookup_manufacturer(mac_address)
            device_type = self.classify_device(hostname, manufacturer)

            cursor.execute("""
                INSERT INTO devices (
                    mac_address, ip_address, hostname, manufacturer, device_type,
                    first_seen, last_seen, open_ports, services, tags
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                mac_address, ip_address, hostname, manufacturer, device_type.value,
                now, now, "[]", "[]", "[]"
            ))
            conn.commit()
            cursor.execute("SELECT * FROM devices WHERE mac_address = ?", (mac_address,))
            row = cursor.fetchone()

        conn.close()
        return self._row_to_device(row)

    def _row_to_device(self, row) -> Device:
        """Convert database row to Device model."""
        return Device(
            mac_address=row[0],
            ip_address=row[1],
            hostname=row[2],
            manufacturer=row[3],
            device_type=DeviceType(row[4]) if row[4] else DeviceType.UNKNOWN,
            model=row[5],
            firmware_version=row[6],
            os_fingerprint=row[7],
            risk_level=RiskLevel(row[8]) if row[8] else RiskLevel.MEDIUM,
            risk_score=row[9] or 50,
            first_seen=row[10],
            last_seen=row[11],
            is_known=bool(row[12]),
            is_quarantined=bool(row[13]),
            open_ports=json.loads(row[14] or "[]"),
            services=json.loads(row[15] or "[]"),
            tags=json.loads(row[16] or "[]"),
            notes=row[17] or ""
        )

    def list_devices(self, device_type: str = None, risk_level: str = None,
                      quarantined: bool = None, limit: int = 100, offset: int = 0) -> Dict[str, Any]:
        """List devices with filtering and pagination."""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()

        query = "SELECT * FROM devices WHERE 1=1"
        count_query = "SELECT COUNT(*) FROM devices WHERE 1=1"
        params = []

        if device_type:
            query += " AND device_type = ?"
            count_query += " AND device_type = ?"
            params.append(device_type)
        if risk_level:
            query += " AND risk_level = ?"
            count_query += " AND risk_level = ?"
            params.append(risk_level)
        if quarantined is not None:
            query += " AND is_quarantined = ?"
            count_query += " AND is_quarantined = ?"
            params.append(1 if quarantined else 0)

        # Get total count
        cursor.execute(count_query, params)
        total = cursor.fetchone()[0]

        # Get paginated results
        query += " ORDER BY last_seen DESC LIMIT ? OFFSET ?"
        cursor.execute(query, params + [limit, offset])
        rows = cursor.fetchall()
        conn.close()

        devices = [self._row_to_device(row) for row in rows]
        return {
            "devices": devices,
            "total": total,
            "limit": limit,
            "offset": offset,
            "has_more": offset + len(devices) < total
        }

    def get_device(self, mac_address: str) -> Optional[Device]:
        """Get device by MAC address."""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM devices WHERE mac_address = ?", (mac_address.lower(),))
        row = cursor.fetchone()
        conn.close()
        return self._row_to_device(row) if row else None

    def update_device(self, mac_address: str, update: DeviceUpdate) -> Optional[Device]:
        """Update device properties."""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()

        updates = []
        params = []

        if update.hostname is not None:
            updates.append("hostname = ?")
            params.append(update.hostname)
        if update.device_type is not None:
            updates.append("device_type = ?")
            params.append(update.device_type.value)
        if update.is_known is not None:
            updates.append("is_known = ?")
            params.append(1 if update.is_known else 0)
        if update.tags is not None:
            updates.append("tags = ?")
            params.append(json.dumps(update.tags))
        if update.notes is not None:
            updates.append("notes = ?")
            params.append(update.notes)

        if updates:
            query = f"UPDATE devices SET {', '.join(updates)} WHERE mac_address = ?"
            params.append(mac_address.lower())
            cursor.execute(query, params)
            conn.commit()

        conn.close()
        return self.get_device(mac_address)

    def quarantine_device(self, mac_address: str, reason: str) -> QuarantineEntry:
        """Quarantine a device."""
        mac_address = mac_address.lower()
        now = datetime.utcnow().isoformat() + "Z"

        entry = QuarantineEntry(
            mac_address=mac_address,
            reason=reason,
            status=QuarantineStatus.ACTIVE,
            created_at=now
        )

        self.quarantine[mac_address] = entry
        self._save_quarantine()

        # Update device
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE devices SET is_quarantined = 1 WHERE mac_address = ?",
            (mac_address,)
        )
        conn.commit()
        conn.close()

        # Apply network isolation (nftables)
        self._apply_quarantine(mac_address)

        return entry

    def release_quarantine(self, mac_address: str) -> bool:
        """Release a device from quarantine."""
        mac_address = mac_address.lower()
        if mac_address not in self.quarantine:
            return False

        entry = self.quarantine[mac_address]
        entry.status = QuarantineStatus.RELEASED
        entry.released_at = datetime.utcnow().isoformat() + "Z"
        self._save_quarantine()

        # Update device
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE devices SET is_quarantined = 0 WHERE mac_address = ?",
            (mac_address,)
        )
        conn.commit()
        conn.close()

        # Remove network isolation
        self._remove_quarantine(mac_address)

        return True

    def _apply_quarantine(self, mac_address: str):
        """Apply nftables rules to quarantine device."""
        # Validate MAC address to prevent injection
        if not self._validate_mac(mac_address):
            logger.warning(f"Invalid MAC address format: {mac_address}")
            return False

        try:
            result = subprocess.run([
                "nft", "add", "rule", "inet", "filter", "forward",
                "ether", "saddr", mac_address, "drop"
            ], capture_output=True, timeout=5)
            if result.returncode == 0:
                logger.info(f"Applied quarantine rule for {mac_address}")
                return True
            else:
                logger.warning(f"nft returned {result.returncode}: {result.stderr}")
                return False
        except Exception as e:
            logger.warning(f"Failed to apply quarantine: {e}")
            return False

    def _validate_mac(self, mac_address: str) -> bool:
        """Validate MAC address format to prevent injection."""
        pattern = r'^([0-9a-f]{2}:){5}[0-9a-f]{2}$'
        return bool(re.match(pattern, mac_address.lower()))

    def _remove_quarantine(self, mac_address: str):
        """Remove nftables quarantine rules safely."""
        # Validate MAC address to prevent shell injection
        if not self._validate_mac(mac_address):
            logger.warning(f"Invalid MAC address format: {mac_address}")
            return

        try:
            # Step 1: List rules with handles to find matching rule
            result = subprocess.run(
                ["nft", "-a", "list", "chain", "inet", "filter", "forward"],
                capture_output=True,
                text=True,
                timeout=5
            )

            # Step 2: Find handle for this MAC address
            handle = None
            for line in result.stdout.split('\n'):
                if mac_address.lower() in line.lower() and 'handle' in line:
                    # Extract handle number from line like "... handle 42"
                    match = re.search(r'handle\s+(\d+)', line)
                    if match:
                        handle = match.group(1)
                        break

            # Step 3: Delete rule by handle (safe, no shell interpolation)
            if handle:
                subprocess.run(
                    ["nft", "delete", "rule", "inet", "filter", "forward", "handle", handle],
                    capture_output=True,
                    timeout=5
                )
                logger.info(f"Removed quarantine rule for {mac_address}")
            else:
                logger.warning(f"No quarantine rule found for {mac_address}")

        except Exception as e:
            logger.warning(f"Failed to remove quarantine: {e}")

    def run_discovery(self, network: str = None, use_nmap: bool = False) -> Dict[str, Any]:
        """Run full device discovery."""
        discovered = []
        methods_used = []

        # ARP discovery (fast, always runs)
        arp_devices = self.discover_arp()
        methods_used.append("arp")
        for dev in arp_devices:
            if dev.get("mac_address") and self._validate_mac(dev["mac_address"]):
                device = self.register_device(
                    dev["mac_address"],
                    dev.get("ip_address"),
                    dev.get("hostname")
                )
                discovered.append(device.mac_address)

        # nmap discovery (optional, slower but more thorough)
        if use_nmap and network:
            nmap_devices = self.discover_nmap(network)
            methods_used.append("nmap")
            for dev in nmap_devices:
                mac = dev.get("mac_address")
                if mac and self._validate_mac(mac) and mac not in discovered:
                    device = self.register_device(
                        mac,
                        dev.get("ip_address"),
                        dev.get("hostname")
                    )
                    discovered.append(device.mac_address)

        return {
            "discovered": len(discovered),
            "methods": methods_used,
            "devices": discovered
        }

    def get_stats(self) -> Dict[str, Any]:
        """Get IoT guard statistics."""
        result = self.list_devices(limit=10000)  # Get all for stats
        devices = result["devices"]

        by_type = {}
        by_risk = {}
        recent_24h = 0
        now = datetime.utcnow()

        for device in devices:
            by_type[device.device_type.value] = by_type.get(device.device_type.value, 0) + 1
            by_risk[device.risk_level.value] = by_risk.get(device.risk_level.value, 0) + 1

            # Count devices seen in last 24h
            try:
                last_seen = datetime.fromisoformat(device.last_seen.replace('Z', '+00:00').replace('+00:00', ''))
                if (now - last_seen).total_seconds() < 86400:
                    recent_24h += 1
            except Exception:
                pass

        return {
            "total_devices": len(devices),
            "known_devices": sum(1 for d in devices if d.is_known),
            "unknown_devices": sum(1 for d in devices if not d.is_known),
            "quarantined": sum(1 for d in devices if d.is_quarantined),
            "active_24h": recent_24h,
            "high_risk": sum(1 for d in devices if d.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]),
            "by_type": by_type,
            "by_risk": by_risk
        }


# Global instance
guard = IoTGuard(DATA_DIR)


# ============================================================================
# P2P Mesh Integration
# ============================================================================

def fetch_p2p_peers() -> List[Dict[str, Any]]:
    """Fetch peers from the P2P API via Unix socket."""
    peers = []
    try:
        # Use httpx with Unix socket transport
        import urllib.request
        import http.client

        class UnixHTTPConnection(http.client.HTTPConnection):
            def __init__(self, socket_path):
                super().__init__("localhost")
                self.socket_path = socket_path

            def connect(self):
                self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                self.sock.connect(self.socket_path)

        if os.path.exists(P2P_SOCKET):
            conn = UnixHTTPConnection(P2P_SOCKET)
            conn.request("GET", "/peers")
            response = conn.getresponse()
            if response.status == 200:
                data = json.loads(response.read().decode())
                peers = data.get("peers", [])
            conn.close()
    except Exception as e:
        logger.warning(f"Failed to fetch P2P peers: {e}")

    return peers


def fetch_p2p_master_tree() -> Dict[str, Any]:
    """Fetch master-link tree from P2P API."""
    tree = {}
    try:
        import http.client

        class UnixHTTPConnection(http.client.HTTPConnection):
            def __init__(self, socket_path):
                super().__init__("localhost")
                self.socket_path = socket_path

            def connect(self):
                self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                self.sock.connect(self.socket_path)

        if os.path.exists(P2P_SOCKET):
            conn = UnixHTTPConnection(P2P_SOCKET)
            conn.request("GET", "/master-link/tree")
            response = conn.getresponse()
            if response.status == 200:
                data = json.loads(response.read().decode())
                tree = data.get("tree", {})
            conn.close()
    except Exception as e:
        logger.warning(f"Failed to fetch master-link tree: {e}")

    return tree


async def probe_secubox_device(ip_address: str, timeout: float = 5.0) -> Dict[str, Any]:
    """Probe an IP to detect if it's a SecuBox device."""
    result = {
        "is_secubox": False,
        "is_openwrt": False,
        "hostname": None,
        "model": None,
        "version": None,
        "theme": None
    }

    try:
        async with httpx.AsyncClient(verify=False, timeout=timeout) as client:
            # Try HTTPS first, then HTTP
            for scheme in ["https", "http"]:
                try:
                    resp = await client.get(f"{scheme}://{ip_address}/cgi-bin/luci")
                    if resp.status_code in [200, 301, 302, 401, 403]:
                        body = resp.text

                        # Check for SecuBox markers
                        if "data-secubox-theme" in body or "secubox" in body.lower():
                            result["is_secubox"] = True
                            result["is_openwrt"] = True

                            # Extract theme
                            theme_match = re.search(r'data-secubox-theme="([^"]+)"', body)
                            if theme_match:
                                result["theme"] = theme_match.group(1)

                            # Extract title/hostname
                            title_match = re.search(r'<title>([^<]+)</title>', body)
                            if title_match:
                                result["hostname"] = title_match.group(1).split(" - ")[0]

                        elif "LuCI" in body or "OpenWrt" in body:
                            result["is_openwrt"] = True

                        break
                except Exception:
                    continue
    except Exception as e:
        logger.debug(f"Failed to probe {ip_address}: {e}")

    return result


def sync_p2p_peers_to_devices() -> Dict[str, Any]:
    """Sync P2P mesh peers to IoT Guard device database."""
    peers = fetch_p2p_peers()
    synced = []
    skipped = []

    now = datetime.utcnow().isoformat() + "Z"

    for peer in peers:
        peer_id = peer.get("id", "")
        name = peer.get("name", "Unknown Peer")
        address = peer.get("address", "unknown")
        fingerprint = peer.get("fingerprint", "")
        status = peer.get("status", "unknown")
        is_local = peer.get("is_local", False)

        # Skip local node
        if is_local:
            skipped.append({"id": peer_id, "reason": "local node"})
            continue

        # Skip if no valid address
        if address in ["unknown", "", None]:
            skipped.append({"id": peer_id, "reason": "no address"})
            continue

        # Generate synthetic MAC from peer ID (for database key)
        # Format: sb:xx:xx:xx:xx:xx (SecuBox prefix + hash of peer_id)
        import hashlib
        peer_hash = hashlib.md5(peer_id.encode()).hexdigest()[:10]
        synthetic_mac = f"sb:{peer_hash[0:2]}:{peer_hash[2:4]}:{peer_hash[4:6]}:{peer_hash[6:8]}:{peer_hash[8:10]}"

        # Register or update device
        conn = sqlite3.connect(guard.db_file)
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM devices WHERE mac_address = ?", (synthetic_mac,))
        row = cursor.fetchone()

        if row:
            # Update existing
            cursor.execute("""
                UPDATE devices SET
                    ip_address = ?,
                    hostname = ?,
                    last_seen = ?,
                    device_type = ?,
                    manufacturer = ?,
                    is_known = 1
                WHERE mac_address = ?
            """, (address, name, now, "router", "SecuBox Mesh", synthetic_mac))
        else:
            # Insert new
            cursor.execute("""
                INSERT INTO devices (
                    mac_address, ip_address, hostname, manufacturer, device_type,
                    first_seen, last_seen, is_known, risk_level, risk_score,
                    open_ports, services, tags, notes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                synthetic_mac, address, name, "SecuBox Mesh", "router",
                now, now, 1, "safe", 10,
                "[]", '["secubox-mesh", "p2p"]', f'["mesh", "peer", "{status}"]',
                f"P2P Peer ID: {peer_id}\nFingerprint: {fingerprint}"
            ))

        conn.commit()
        conn.close()

        synced.append({
            "peer_id": peer_id,
            "name": name,
            "address": address,
            "mac": synthetic_mac,
            "status": status
        })

    return {
        "synced": len(synced),
        "skipped": len(skipped),
        "peers": synced,
        "skipped_details": skipped
    }


# ============================================================================
# API Endpoints
# ============================================================================

@app.get("/status")
async def status():
    """Public status endpoint."""
    stats = guard.get_stats()
    return {
        "module": "iot-guard",
        "status": "ok",
        "version": "1.0.0",
        "total_devices": stats["total_devices"],
        "quarantined": stats["quarantined"]
    }


@app.get("/health")
async def health():
    """Health check."""
    return {"status": "healthy"}


@app.get("/stats", dependencies=[Depends(require_jwt)])
async def get_stats():
    """Get IoT guard statistics."""
    return guard.get_stats()


@app.post("/discover", dependencies=[Depends(require_jwt)])
async def run_discovery(network: Optional[str] = None, use_nmap: bool = False):
    """Run device discovery.

    Args:
        network: Network CIDR for nmap scan (e.g., 192.168.1.0/24)
        use_nmap: Whether to use nmap for thorough scanning (slower)
    """
    result = guard.run_discovery(network, use_nmap)
    return result


@app.get("/devices", dependencies=[Depends(require_jwt)])
async def list_devices(
    device_type: Optional[str] = None,
    risk_level: Optional[str] = None,
    quarantined: Optional[bool] = None,
    limit: int = 100,
    offset: int = 0
):
    """List devices with filtering and pagination."""
    return guard.list_devices(device_type, risk_level, quarantined, limit, offset)


@app.get("/devices/{mac_address}", dependencies=[Depends(require_jwt)])
async def get_device(mac_address: str):
    """Get device details."""
    device = guard.get_device(mac_address)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    return device


@app.put("/devices/{mac_address}", dependencies=[Depends(require_jwt)])
async def update_device(mac_address: str, update: DeviceUpdate):
    """Update device properties."""
    device = guard.update_device(mac_address, update)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    return {"status": "updated", "device": device}


@app.post("/devices/{mac_address}/quarantine", dependencies=[Depends(require_jwt)])
async def quarantine_device(mac_address: str, reason: str = "Manual quarantine"):
    """Quarantine a device."""
    entry = guard.quarantine_device(mac_address, reason)
    return {"status": "quarantined", "entry": entry}


@app.delete("/devices/{mac_address}/quarantine", dependencies=[Depends(require_jwt)])
async def release_quarantine(mac_address: str):
    """Release device from quarantine."""
    if not guard.release_quarantine(mac_address):
        raise HTTPException(status_code=404, detail="Device not quarantined")
    return {"status": "released"}


@app.get("/quarantine", dependencies=[Depends(require_jwt)])
async def list_quarantine():
    """List quarantined devices."""
    active = [e for e in guard.quarantine.values() if e.status == QuarantineStatus.ACTIVE]
    return {"quarantined": active, "count": len(active)}


@app.get("/manufacturers/{mac_address}")
async def lookup_manufacturer(mac_address: str):
    """Lookup manufacturer by MAC address."""
    manufacturer = guard.lookup_manufacturer(mac_address)
    return {"mac_address": mac_address, "manufacturer": manufacturer}


# ============================================================================
# P2P Mesh Integration Endpoints
# ============================================================================

@app.get("/mesh/peers")
async def get_mesh_peers():
    """Get P2P mesh peers (raw data from P2P API)."""
    peers = fetch_p2p_peers()
    tree = fetch_p2p_master_tree()
    return {
        "peers": peers,
        "count": len(peers),
        "tree": tree,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }


@app.post("/mesh/sync", dependencies=[Depends(require_jwt)])
async def sync_mesh_peers():
    """Sync P2P mesh peers to IoT Guard device database.

    This imports all mesh peers as known devices with 'router' type
    and 'safe' risk level since they are trusted SecuBox nodes.
    """
    result = sync_p2p_peers_to_devices()
    return {
        "status": "synced",
        **result,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }


@app.post("/mesh/probe/{ip_address}", dependencies=[Depends(require_jwt)])
async def probe_mesh_device(ip_address: str):
    """Probe an IP address to detect SecuBox/OpenWRT."""
    result = await probe_secubox_device(ip_address)
    return {
        "ip_address": ip_address,
        **result,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }


@app.post("/discover/full", dependencies=[Depends(require_jwt)])
async def full_discovery(
    network: Optional[str] = None,
    include_mesh: bool = True,
    use_arping: bool = True,
    use_nmap: bool = False
):
    """Run comprehensive device discovery.

    Combines multiple discovery methods:
    - ARP table scan (fast, passive)
    - ARP ping scan (active, finds more devices)
    - P2P mesh peers (SecuBox nodes)
    - Optional nmap scan (thorough but slow)

    Args:
        network: Network CIDR for active scanning (auto-detected if not provided)
        include_mesh: Include P2P mesh peers as devices
        use_arping: Use arping for active discovery
        use_nmap: Use nmap for thorough scanning (slower)
    """
    results = {
        "arp_devices": 0,
        "arping_devices": 0,
        "mesh_peers": 0,
        "nmap_devices": 0,
        "total_discovered": 0,
        "methods_used": []
    }

    discovered_macs = set()

    # 1. ARP table (passive, fast)
    arp_devices = guard.discover_arp()
    results["methods_used"].append("arp")
    for dev in arp_devices:
        mac = dev.get("mac_address", "").lower()
        if mac and guard._validate_mac(mac):
            guard.register_device(mac, dev.get("ip_address"), dev.get("hostname"))
            discovered_macs.add(mac)
    results["arp_devices"] = len(arp_devices)

    # 2. Active ARP ping scan (finds devices not in ARP table)
    if use_arping:
        try:
            # Auto-detect network if not provided
            if not network:
                proc = subprocess.run(
                    ["ip", "-4", "route", "show", "default"],
                    capture_output=True, text=True, timeout=5
                )
                # Get the interface
                parts = proc.stdout.split()
                if "dev" in parts:
                    iface = parts[parts.index("dev") + 1]
                    # Get network from interface
                    proc2 = subprocess.run(
                        ["ip", "-4", "addr", "show", iface],
                        capture_output=True, text=True, timeout=5
                    )
                    match = re.search(r'inet\s+(\d+\.\d+\.\d+)\.\d+/(\d+)', proc2.stdout)
                    if match:
                        network = f"{match.group(1)}.0/{match.group(2)}"

            if network:
                results["methods_used"].append("arping")
                # Use nmap -sn for ARP ping (faster than arping loop)
                base = network.rsplit('.', 1)[0]
                for i in range(1, 255):
                    ip = f"{base}.{i}"
                    try:
                        proc = subprocess.run(
                            ["arping", "-c", "1", "-w", "1", ip],
                            capture_output=True, text=True, timeout=3
                        )
                        if "reply from" in proc.stdout.lower():
                            # Extract MAC from arping output
                            match = re.search(r'\[([0-9A-Fa-f:]{17})\]', proc.stdout)
                            if match:
                                mac = match.group(1).lower()
                                if mac not in discovered_macs and guard._validate_mac(mac):
                                    guard.register_device(mac, ip)
                                    discovered_macs.add(mac)
                                    results["arping_devices"] += 1
                    except Exception:
                        continue
                    # Stop early if we've found enough
                    if results["arping_devices"] >= 50:
                        break
        except Exception as e:
            logger.warning(f"ARP ping scan failed: {e}")

    # 3. P2P Mesh peers
    if include_mesh:
        results["methods_used"].append("mesh")
        mesh_result = sync_p2p_peers_to_devices()
        results["mesh_peers"] = mesh_result["synced"]

    # 4. Optional nmap scan
    if use_nmap and network:
        results["methods_used"].append("nmap")
        nmap_devices = guard.discover_nmap(network)
        for dev in nmap_devices:
            mac = dev.get("mac_address", "").lower()
            if mac and guard._validate_mac(mac) and mac not in discovered_macs:
                guard.register_device(mac, dev.get("ip_address"), dev.get("hostname"))
                discovered_macs.add(mac)
                results["nmap_devices"] += 1

    results["total_discovered"] = len(discovered_macs)

    return {
        **results,
        "devices": list(discovered_macs),
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }


# ============================================================================
# Google Cast / Chromecast Debug Module
# ============================================================================

# Known Google device OUI prefixes (for MAC address detection)
GOOGLE_OUI_PREFIXES = [
    "1c:f2:9a", "54:60:09", "f4:f5:d8", "48:d6:d5", "a4:77:33",
    "44:07:0b", "e4:f0:42", "cc:fa:00", "d8:6c:63", "f4:f5:e8",
    "30:fd:38", "6c:ad:f8", "94:eb:2c", "70:cd:60"
]

# Google Cast domains that must not be blocked
CAST_DOMAINS = [
    "cast.googleapis.com", "clients1.google.com", "gvt2.com",
    "googlecast.com", "play.google.com", "accounts.google.com",
    "clouddevices.googleapis.com", "www.gstatic.com"
]

# Ports used by Google Cast
CAST_PORTS = {8008, 8009, 8443, 8012, 9000, 5353}


class CastDiagnostic(BaseModel):
    """Google Cast device diagnostic result."""
    mac_address: str
    ip_address: Optional[str]
    device_name: Optional[str]
    is_google_device: bool
    diagnostic_vector: Optional[str] = None  # V1=WiFi, V2=LAN, V3=Cloud
    issues_found: List[str] = []
    crowdsec_status: Dict[str, Any] = {}
    suricata_alerts: List[str] = []
    dns_blocks: List[str] = []
    nftables_drops: List[str] = []
    recommendations: List[str] = []
    timestamp: str


def is_google_device(mac_address: str) -> bool:
    """Check if MAC address belongs to a Google device."""
    prefix = mac_address[:8].lower()
    return prefix in GOOGLE_OUI_PREFIXES


def find_google_cast_devices() -> List[Dict[str, str]]:
    """Find Google Cast devices on the network."""
    devices = []
    try:
        # Check ARP table for Google OUIs
        result = subprocess.run(
            ["ip", "neigh", "show"],
            capture_output=True, text=True, timeout=10
        )
        for line in result.stdout.strip().split("\n"):
            parts = line.split()
            if len(parts) >= 5 and parts[3] == "lladdr":
                mac = parts[4].lower()
                if is_google_device(mac):
                    devices.append({
                        "ip_address": parts[0],
                        "mac_address": mac,
                        "state": parts[-1] if len(parts) > 5 else "unknown"
                    })
    except Exception as e:
        logger.warning(f"ARP scan failed: {e}")

    # Also try mDNS lookup for _googlecast._tcp
    try:
        result = subprocess.run(
            ["avahi-browse", "-t", "-r", "_googlecast._tcp", "-p"],
            capture_output=True, text=True, timeout=15
        )
        for line in result.stdout.strip().split("\n"):
            if line.startswith("="):
                parts = line.split(";")
                if len(parts) >= 8:
                    ip = parts[7]
                    name = parts[3]
                    # Check if already found
                    if not any(d["ip_address"] == ip for d in devices):
                        devices.append({
                            "ip_address": ip,
                            "mac_address": "",
                            "name": name,
                            "state": "mdns"
                        })
    except Exception:
        pass  # avahi-browse may not be available

    return devices


def check_crowdsec_for_ip(ip_address: str) -> Dict[str, Any]:
    """Check if IP is banned or has alerts in CrowdSec."""
    result = {"banned": False, "alerts": [], "decisions": []}
    try:
        # Check decisions
        proc = subprocess.run(
            ["cscli", "decisions", "list", "-o", "json"],
            capture_output=True, text=True, timeout=30
        )
        if proc.returncode == 0 and proc.stdout.strip():
            decisions = json.loads(proc.stdout)
            for d in (decisions or []):
                if d.get("value") == ip_address:
                    result["banned"] = True
                    result["decisions"].append({
                        "type": d.get("type"),
                        "scenario": d.get("scenario"),
                        "duration": d.get("duration")
                    })

        # Check alerts
        proc = subprocess.run(
            ["cscli", "alerts", "list", "--ip", ip_address, "-o", "json"],
            capture_output=True, text=True, timeout=30
        )
        if proc.returncode == 0 and proc.stdout.strip():
            alerts = json.loads(proc.stdout)
            result["alerts"] = [a.get("scenario") for a in (alerts or [])][:10]
    except Exception as e:
        result["error"] = str(e)

    return result


def check_suricata_alerts(ip_address: str, limit: int = 20) -> List[str]:
    """Check Suricata alerts for IP."""
    alerts = []
    fast_log = Path("/var/log/suricata/fast.log")
    if fast_log.exists():
        try:
            result = subprocess.run(
                ["grep", ip_address, str(fast_log)],
                capture_output=True, text=True, timeout=30
            )
            for line in result.stdout.strip().split("\n")[-limit:]:
                if line.strip():
                    alerts.append(line.strip()[:200])
        except Exception:
            pass
    return alerts


def check_dns_blocks(domains: List[str] = None) -> List[str]:
    """Check if Cast domains are blocked in Unbound."""
    blocked = []
    domains = domains or CAST_DOMAINS
    unbound_log = Path("/var/log/unbound/unbound.log")

    if unbound_log.exists():
        try:
            for domain in domains:
                result = subprocess.run(
                    ["grep", "-i", domain, str(unbound_log)],
                    capture_output=True, text=True, timeout=10
                )
                for line in result.stdout.strip().split("\n"):
                    if any(x in line.upper() for x in ["REFUSED", "NXDOMAIN", "BLOCKED"]):
                        blocked.append(f"{domain}: {line.strip()[:100]}")
                        break
        except Exception:
            pass

    return blocked


def check_nftables_drops(ip_address: str) -> List[str]:
    """Check nftables for DROP rules affecting the IP."""
    drops = []
    try:
        result = subprocess.run(
            ["nft", "list", "ruleset"],
            capture_output=True, text=True, timeout=30
        )
        # Look for drop/reject rules
        for line in result.stdout.split("\n"):
            if ("drop" in line.lower() or "reject" in line.lower()):
                if ip_address in line or "counter packets" in line:
                    drops.append(line.strip()[:150])
    except Exception as e:
        drops.append(f"Error checking nftables: {e}")

    return drops[:20]


def generate_whitelist_nft(ip_address: str, mac_address: str = "") -> str:
    """Generate nftables whitelist rules for Google Cast device."""
    return f'''# Google Cast Whitelist - {ip_address}
# File: /etc/secubox/firewall/shadow/cast-whitelist.nft
# Apply: secubox-params swap --module firewall --validate-zkp

table inet filter {{
    set google_cast_ips {{
        type ipv4_addr
        flags interval
        # Google AS15169 ranges for Cast services
        elements = {{ 172.217.0.0/16, 216.58.0.0/16, 142.250.0.0/15,
                     74.125.0.0/16, 64.233.160.0/19 }}
    }}

    chain forward {{
        # Allow Cast device to Google services
        ip saddr {ip_address} ip daddr @google_cast_ips tcp dport {{ 443, 8009 }} \\
            ct state new,established accept \\
            comment "[SECUBOX-CAST] Google Radio - Cast sessions"

        ip saddr {ip_address} ip daddr @google_cast_ips udp dport {{ 443, 5353 }} \\
            accept \\
            comment "[SECUBOX-CAST] Google Radio - QUIC + mDNS"

        # Allow local Cast discovery
        ip saddr {ip_address} udp dport 5353 accept \\
            comment "[SECUBOX-CAST] mDNS discovery"

        ip saddr {ip_address} tcp dport {{ 8008, 8009, 8443 }} accept \\
            comment "[SECUBOX-CAST] Local Cast control"
    }}
}}
'''


def generate_unbound_passthrough() -> str:
    """Generate Unbound configuration for Cast domains."""
    return '''# Google Cast DNS Passthrough
# File: /etc/unbound/conf.d/cast-passthrough.conf
# Apply: systemctl reload unbound

server:
    local-zone: "cast.googleapis.com." transparent
    local-zone: "clients1.google.com." transparent
    local-zone: "gvt2.com." transparent
    local-zone: "googlecast.com." transparent
    local-zone: "clouddevices.googleapis.com." transparent
    local-zone: "play.google.com." transparent
'''


def generate_crowdsec_whitelist(ip_address: str) -> str:
    """Generate CrowdSec whitelist command."""
    return f'''# CrowdSec Whitelist for Google Cast Device
cscli decisions add --ip {ip_address} --type whitelist --duration 0 \\
    --reason "Google Radio - Cast device - IoT Guard whitelist"

# Verify whitelist
cscli decisions list | grep {ip_address}
'''


@app.get("/cast/devices")
async def find_cast_devices():
    """Find Google Cast/Chromecast devices on the network."""
    devices = find_google_cast_devices()
    return {
        "devices": devices,
        "count": len(devices),
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }


@app.get("/cast/diagnose/{ip_address}", dependencies=[Depends(require_jwt)])
async def diagnose_cast_device(ip_address: str):
    """Run full diagnostic on a Cast device.

    Checks:
    - CrowdSec bans/alerts
    - Suricata alerts
    - DNS blocks (Unbound)
    - nftables DROP rules
    """
    # Find MAC address
    mac_address = ""
    try:
        result = subprocess.run(
            ["ip", "neigh", "show", ip_address],
            capture_output=True, text=True, timeout=10
        )
        parts = result.stdout.strip().split()
        if "lladdr" in parts:
            idx = parts.index("lladdr")
            mac_address = parts[idx + 1].lower()
    except Exception:
        pass

    issues = []
    recommendations = []
    diagnostic_vector = None

    # Check CrowdSec
    cs_status = check_crowdsec_for_ip(ip_address)
    if cs_status.get("banned"):
        issues.append(f"Device is BANNED in CrowdSec: {cs_status['decisions']}")
        recommendations.append("Run: cscli decisions add --ip {ip} --type whitelist --duration 0")
        diagnostic_vector = "V3"

    if cs_status.get("alerts"):
        issues.append(f"CrowdSec alerts: {cs_status['alerts'][:5]}")

    # Check Suricata
    suricata_alerts = check_suricata_alerts(ip_address)
    if suricata_alerts:
        issues.append(f"Suricata alerts detected: {len(suricata_alerts)}")
        diagnostic_vector = diagnostic_vector or "V3"

    # Check DNS blocks
    dns_blocks = check_dns_blocks()
    if dns_blocks:
        issues.append(f"DNS blocks on Cast domains: {dns_blocks[:5]}")
        recommendations.append("Add Unbound passthrough for Cast domains")
        diagnostic_vector = diagnostic_vector or "V3"

    # Check nftables
    nft_drops = check_nftables_drops(ip_address)
    if nft_drops:
        issues.append(f"nftables DROP rules may affect device: {len(nft_drops)}")
        recommendations.append("Add Cast whitelist to nftables")

    # Generate recommendations
    if not recommendations and issues:
        if diagnostic_vector == "V3":
            recommendations = [
                "Check TCP RST packets with tcpdump",
                "Verify TLS interception is not active for device",
                "Review Suricata rules for false positives"
            ]

    return CastDiagnostic(
        mac_address=mac_address,
        ip_address=ip_address,
        device_name=None,
        is_google_device=is_google_device(mac_address) if mac_address else False,
        diagnostic_vector=diagnostic_vector,
        issues_found=issues,
        crowdsec_status=cs_status,
        suricata_alerts=suricata_alerts,
        dns_blocks=dns_blocks,
        nftables_drops=nft_drops,
        recommendations=recommendations,
        timestamp=datetime.utcnow().isoformat() + "Z"
    )


@app.post("/cast/whitelist/{ip_address}", dependencies=[Depends(require_jwt)])
async def whitelist_cast_device(ip_address: str, apply_crowdsec: bool = True):
    """Whitelist a Cast device in CrowdSec.

    Args:
        ip_address: Device IP address
        apply_crowdsec: Whether to apply CrowdSec whitelist immediately
    """
    result = {"ip_address": ip_address, "actions": []}

    # Apply CrowdSec whitelist
    if apply_crowdsec:
        try:
            proc = subprocess.run(
                ["cscli", "decisions", "add", "--ip", ip_address,
                 "--type", "whitelist", "--duration", "0",
                 "--reason", "Google Cast device - IoT Guard whitelist"],
                capture_output=True, text=True, timeout=30
            )
            if proc.returncode == 0:
                result["actions"].append("CrowdSec whitelist applied")
            else:
                result["actions"].append(f"CrowdSec error: {proc.stderr}")
        except Exception as e:
            result["actions"].append(f"CrowdSec failed: {e}")

    # Generate config files
    result["nftables_config"] = generate_whitelist_nft(ip_address)
    result["unbound_config"] = generate_unbound_passthrough()
    result["crowdsec_commands"] = generate_crowdsec_whitelist(ip_address)

    return result


@app.get("/cast/capture/{ip_address}", dependencies=[Depends(require_jwt)])
async def start_cast_capture(ip_address: str, duration: int = 60):
    """Start a packet capture for Cast device debugging.

    Args:
        ip_address: Device IP to capture
        duration: Capture duration in seconds (max 300)
    """
    duration = min(duration, 300)
    capture_file = f"/tmp/cast_debug_{ip_address.replace('.', '_')}_{int(time.time())}.pcap"

    try:
        # Start tcpdump in background
        proc = subprocess.Popen(
            ["timeout", str(duration), "tcpdump", "-i", "any",
             f"host {ip_address}", "-w", capture_file],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )

        return {
            "status": "capturing",
            "ip_address": ip_address,
            "capture_file": capture_file,
            "duration": duration,
            "pid": proc.pid,
            "message": f"Capture will run for {duration}s. Retrieve with /cast/capture/download/{capture_file}"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start capture: {e}")


@app.get("/cast/config/nftables/{ip_address}")
async def get_nftables_config(ip_address: str):
    """Generate nftables whitelist config for Cast device."""
    return {
        "config": generate_whitelist_nft(ip_address),
        "path": "/etc/secubox/firewall/shadow/cast-whitelist.nft",
        "apply_command": "secubox-params swap --module firewall --validate-zkp"
    }


@app.get("/cast/config/unbound")
async def get_unbound_config():
    """Generate Unbound passthrough config for Cast domains."""
    return {
        "config": generate_unbound_passthrough(),
        "path": "/etc/unbound/conf.d/cast-passthrough.conf",
        "apply_command": "systemctl reload unbound"
    }


# ============================================================================
# Startup
# ============================================================================

@app.on_event("startup")
async def startup():
    """Initialize on startup."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    logger.info("IoT Guard started with Cast Debug module")
