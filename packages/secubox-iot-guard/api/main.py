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
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, List, Any
from enum import Enum

from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel, Field

from secubox_core.auth import require_jwt
from secubox_core.config import get_config

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
# Startup
# ============================================================================

@app.on_event("startup")
async def startup():
    """Initialize on startup."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    logger.info("IoT Guard started")
