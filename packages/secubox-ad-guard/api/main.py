"""SecuBox Ad Guard - Ad/Tracker Detection & Device Statistics
Detects advertising networks, tracking domains, and provides per-device statistics.

Features:
- Ad network detection via DPI (nDPId/netifyd integration)
- Tracking domain classification
- Device-type statistics (IoT, phones, computers, smart TVs)
- Delayed/scheduled blacklisting
- Blocklist management (hosts, domains, regex)
- Whitelist support for bypass rules
- Real-time and historical statistics
- Stats caching with configurable TTL
- Automatic detection history cleanup
- Webhook notifications on blocking events
"""
import os
import re
import json
import time
import logging
import sqlite3
import subprocess
import asyncio
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, List, Any, Set, Callable
from enum import Enum
from collections import defaultdict
from functools import wraps

from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
import httpx

from secubox_core.auth import require_jwt
from secubox_core.config import get_config

# Configuration
CONFIG_PATH = Path("/etc/secubox/ad-guard.toml")
DATA_DIR = Path("/var/lib/secubox/ad-guard")
DB_FILE = DATA_DIR / "ad-guard.db"
BLOCKLIST_DIR = DATA_DIR / "blocklists"
STATS_FILE = DATA_DIR / "stats.json"
WHITELIST_FILE = DATA_DIR / "whitelist.json"
WEBHOOKS_FILE = DATA_DIR / "webhooks.json"

# Blocklist sources
BLOCKLIST_SOURCES = {
    "adaway": "https://adaway.org/hosts.txt",
    "stevenblack": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "energized": "https://energized.pro/unified/formats/hosts.txt",
    "oisd": "https://small.oisd.nl/domainswild",
    "hagezi": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/pro.txt",
}

# Stats cache configuration
STATS_CACHE_TTL = 60  # seconds
DETECTION_RETENTION_DAYS = 30  # days to keep detection history

app = FastAPI(title="SecuBox Ad Guard", version="1.0.0")
logger = logging.getLogger("secubox.ad-guard")


class DeviceType(str, Enum):
    UNKNOWN = "unknown"
    COMPUTER = "computer"
    PHONE = "phone"
    TABLET = "tablet"
    SMART_TV = "smart_tv"
    IOT = "iot"
    GAME_CONSOLE = "game_console"
    STREAMING = "streaming"


class BlockAction(str, Enum):
    BLOCK = "block"
    DELAY = "delay"  # Queue for later blocking
    MONITOR = "monitor"  # Log only
    ALLOW = "allow"  # Whitelist


class AdCategory(str, Enum):
    ADVERTISING = "advertising"
    TRACKING = "tracking"
    ANALYTICS = "analytics"
    TELEMETRY = "telemetry"
    SOCIAL = "social"
    MALWARE = "malware"
    CRYPTOMINER = "cryptominer"


class BlocklistEntry(BaseModel):
    domain: str
    category: AdCategory
    source: str
    added_at: str
    hits: int = 0
    last_hit: Optional[str] = None


class DeviceStats(BaseModel):
    mac_address: str
    ip_address: Optional[str] = None
    hostname: Optional[str] = None
    device_type: DeviceType
    total_requests: int = 0
    blocked_requests: int = 0
    ad_requests: int = 0
    tracker_requests: int = 0
    top_blocked_domains: List[Dict[str, Any]] = []
    last_seen: str
    block_rate: float = 0.0


class DelayedBlock(BaseModel):
    domain: str
    category: AdCategory
    reason: str
    requested_at: str
    scheduled_at: str  # When to actually block
    approved: bool = False
    approved_by: Optional[str] = None


class AdDetection(BaseModel):
    timestamp: str
    client_ip: str
    client_mac: Optional[str] = None
    device_type: DeviceType
    domain: str
    category: AdCategory
    action: BlockAction
    matched_rule: Optional[str] = None


class WhitelistEntry(BaseModel):
    domain: str
    reason: Optional[str] = None
    added_at: str
    added_by: str = "admin"
    expires_at: Optional[str] = None  # Optional expiration


class WebhookConfig(BaseModel):
    url: str
    events: List[str] = ["block", "detect"]  # Events to trigger on
    enabled: bool = True
    secret: Optional[str] = None  # Optional HMAC secret
    timeout: float = 5.0


class CategoryStats(BaseModel):
    category: str
    total_hits: int
    unique_domains: int
    top_domains: List[Dict[str, Any]]


class StatsCache:
    """Thread-safe stats cache with TTL."""

    def __init__(self, ttl_seconds: int = 60):
        self.ttl = ttl_seconds
        self._cache: Dict[str, Any] = {}
        self._timestamps: Dict[str, float] = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            if key not in self._cache:
                return None
            if time.time() - self._timestamps.get(key, 0) > self.ttl:
                del self._cache[key]
                del self._timestamps[key]
                return None
            return self._cache[key]

    def set(self, key: str, value: Any):
        with self._lock:
            self._cache[key] = value
            self._timestamps[key] = time.time()

    def invalidate(self, key: str = None):
        with self._lock:
            if key:
                self._cache.pop(key, None)
                self._timestamps.pop(key, None)
            else:
                self._cache.clear()
                self._timestamps.clear()


# Global stats cache
stats_cache = StatsCache(STATS_CACHE_TTL)


class AdGuard:
    """Ad and tracker detection with device statistics."""

    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self.db_file = data_dir / "ad-guard.db"
        self.blocklist_dir = data_dir / "blocklists"
        self._ensure_dirs()
        self._init_db()
        self._load_blocklists()

        # Known ad/tracker domain patterns
        self.ad_patterns = [
            r"^ads?\d*\.",
            r"^adserv",
            r"^adtrack",
            r"^doubleclick\.",
            r"^googleadservices\.",
            r"^googlesyndication\.",
            r"^facebook.*pixel",
            r"^pixel\.",
            r"^tracking\.",
            r"^telemetry\.",
            r"^analytics\.",
            r"^stats\d*\.",
            r"^beacon\.",
            r"^metric",
            r"\.adsystem\.",
            r"\.adserver\.",
            r"\.doubleclick\.",
            r"\.googlesyndication\.",
            r"\.moatads\.",
            r"\.amazon-adsystem\.",
        ]
        self._compiled_patterns = [re.compile(p, re.IGNORECASE) for p in self.ad_patterns]

        # Device type fingerprints (OUI + hostname patterns)
        self.device_fingerprints = {
            DeviceType.SMART_TV: {
                "oui": ["samsung", "lg", "sony", "vizio", "tcl", "hisense", "roku"],
                "hostname": ["tv", "smarttv", "roku", "firetv", "appletv", "chromecast"]
            },
            DeviceType.PHONE: {
                "oui": ["apple", "samsung", "huawei", "xiaomi", "oneplus", "google"],
                "hostname": ["iphone", "android", "pixel", "galaxy"]
            },
            DeviceType.IOT: {
                "oui": ["espressif", "tuya", "shenzhen", "amazon", "ring", "nest"],
                "hostname": ["echo", "alexa", "nest", "ring", "hue", "wemo", "smartthings"]
            },
            DeviceType.GAME_CONSOLE: {
                "oui": ["sony", "microsoft", "nintendo"],
                "hostname": ["playstation", "xbox", "switch", "ps4", "ps5"]
            },
            DeviceType.STREAMING: {
                "oui": ["roku", "amazon"],
                "hostname": ["roku", "firestick", "shield", "appletv"]
            }
        }

    def _ensure_dirs(self):
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.blocklist_dir.mkdir(parents=True, exist_ok=True)

    def _init_db(self):
        """Initialize SQLite database."""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()

        # Blocklist table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS blocklist (
                domain TEXT PRIMARY KEY,
                category TEXT,
                source TEXT,
                added_at TEXT,
                hits INTEGER DEFAULT 0,
                last_hit TEXT
            )
        """)

        # Whitelist table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS whitelist (
                domain TEXT PRIMARY KEY,
                reason TEXT,
                added_at TEXT,
                added_by TEXT DEFAULT 'admin',
                expires_at TEXT
            )
        """)

        # Device stats table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                mac_address TEXT PRIMARY KEY,
                ip_address TEXT,
                hostname TEXT,
                device_type TEXT DEFAULT 'unknown',
                total_requests INTEGER DEFAULT 0,
                blocked_requests INTEGER DEFAULT 0,
                ad_requests INTEGER DEFAULT 0,
                tracker_requests INTEGER DEFAULT 0,
                first_seen TEXT,
                last_seen TEXT
            )
        """)

        # Detection log table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS detections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                client_ip TEXT,
                client_mac TEXT,
                device_type TEXT,
                domain TEXT,
                category TEXT,
                action TEXT,
                matched_rule TEXT
            )
        """)

        # Per-device domain stats
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS device_domains (
                mac_address TEXT,
                domain TEXT,
                category TEXT,
                hits INTEGER DEFAULT 0,
                last_hit TEXT,
                PRIMARY KEY (mac_address, domain)
            )
        """)

        # Delayed blocks queue
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS delayed_blocks (
                domain TEXT PRIMARY KEY,
                category TEXT,
                reason TEXT,
                requested_at TEXT,
                scheduled_at TEXT,
                approved INTEGER DEFAULT 0,
                approved_by TEXT
            )
        """)

        # Indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_detections_time ON detections(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_detections_mac ON detections(client_mac)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_device_domains_mac ON device_domains(mac_address)")

        conn.commit()
        conn.close()

    def _load_blocklists(self):
        """Load blocklists and whitelists into memory for fast lookup."""
        self.blocked_domains: Set[str] = set()
        self.whitelisted_domains: Set[str] = set()

        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()

        # Load blocklist
        cursor.execute("SELECT domain FROM blocklist")
        for row in cursor.fetchall():
            self.blocked_domains.add(row[0].lower())

        # Load whitelist (excluding expired entries)
        now = datetime.utcnow().isoformat() + "Z"
        cursor.execute("""
            SELECT domain FROM whitelist
            WHERE expires_at IS NULL OR expires_at > ?
        """, (now,))
        for row in cursor.fetchall():
            self.whitelisted_domains.add(row[0].lower())

        conn.close()

        logger.info(f"Loaded {len(self.blocked_domains)} blocked, {len(self.whitelisted_domains)} whitelisted domains")

    def _load_webhooks(self) -> List[WebhookConfig]:
        """Load webhook configurations."""
        if WEBHOOKS_FILE.exists():
            try:
                with open(WEBHOOKS_FILE) as f:
                    data = json.load(f)
                    return [WebhookConfig(**wh) for wh in data]
            except Exception as e:
                logger.error(f"Failed to load webhooks: {e}")
        return []

    def _save_webhooks(self, webhooks: List[WebhookConfig]):
        """Save webhook configurations."""
        try:
            with open(WEBHOOKS_FILE, 'w') as f:
                json.dump([wh.dict() for wh in webhooks], f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save webhooks: {e}")

    async def _send_webhook(self, event: str, data: Dict[str, Any]):
        """Send webhook notification for an event."""
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
                    await client.post(
                        wh.url,
                        json=payload,
                        headers=headers,
                        timeout=wh.timeout
                    )
            except Exception as e:
                logger.warning(f"Webhook failed for {wh.url}: {e}")

    async def update_blocklists(self, sources: List[str] = None) -> Dict[str, int]:
        """Download and update blocklists from sources."""
        if sources is None:
            sources = list(BLOCKLIST_SOURCES.keys())

        results = {}
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        now = datetime.utcnow().isoformat() + "Z"

        for source in sources:
            if source not in BLOCKLIST_SOURCES:
                continue

            url = BLOCKLIST_SOURCES[source]
            count = 0

            try:
                async with httpx.AsyncClient() as client:
                    response = await client.get(url, timeout=60.0)
                    if response.status_code == 200:
                        for line in response.text.split("\n"):
                            line = line.strip()
                            if not line or line.startswith("#"):
                                continue

                            # Parse hosts file format or plain domain
                            parts = line.split()
                            if len(parts) >= 2 and parts[0] in ["0.0.0.0", "127.0.0.1"]:
                                domain = parts[1].lower()
                            elif len(parts) == 1 and "." in parts[0]:
                                domain = parts[0].lower()
                            else:
                                continue

                            # Skip localhost entries
                            if domain in ["localhost", "localhost.localdomain", "local"]:
                                continue

                            # Determine category
                            category = self._categorize_domain(domain)

                            cursor.execute("""
                                INSERT OR IGNORE INTO blocklist (domain, category, source, added_at)
                                VALUES (?, ?, ?, ?)
                            """, (domain, category.value, source, now))
                            count += 1

                        results[source] = count

            except Exception as e:
                logger.error(f"Failed to update {source}: {e}")
                results[source] = -1

        conn.commit()
        conn.close()

        # Reload in-memory set
        self._load_blocklists()

        return results

    def _categorize_domain(self, domain: str) -> AdCategory:
        """Categorize a domain based on patterns."""
        domain_lower = domain.lower()

        if any(x in domain_lower for x in ["track", "pixel", "beacon"]):
            return AdCategory.TRACKING
        if any(x in domain_lower for x in ["analytics", "metric", "stats"]):
            return AdCategory.ANALYTICS
        if any(x in domain_lower for x in ["telemetry", "crash", "report"]):
            return AdCategory.TELEMETRY
        if any(x in domain_lower for x in ["facebook", "twitter", "linkedin", "social"]):
            return AdCategory.SOCIAL
        if any(x in domain_lower for x in ["miner", "coinhive", "crypto"]):
            return AdCategory.CRYPTOMINER

        return AdCategory.ADVERTISING

    def classify_device(self, mac: str, hostname: str = None, manufacturer: str = None) -> DeviceType:
        """Classify device type based on MAC OUI and hostname."""
        combined = f"{hostname or ''} {manufacturer or ''}".lower()

        for device_type, fingerprints in self.device_fingerprints.items():
            for oui in fingerprints.get("oui", []):
                if oui in combined:
                    return device_type
            for pattern in fingerprints.get("hostname", []):
                if pattern in combined:
                    return device_type

        return DeviceType.UNKNOWN

    def is_whitelisted(self, domain: str) -> bool:
        """Check if domain is whitelisted."""
        domain_lower = domain.lower()

        # Direct match
        if domain_lower in self.whitelisted_domains:
            return True

        # Check parent domains (e.g., whitelist example.com covers sub.example.com)
        parts = domain_lower.split(".")
        for i in range(1, len(parts)):
            parent = ".".join(parts[i:])
            if parent in self.whitelisted_domains:
                return True

        return False

    def is_ad_domain(self, domain: str) -> tuple[bool, Optional[AdCategory], Optional[str]]:
        """Check if domain is an ad/tracker."""
        domain_lower = domain.lower()

        # Check whitelist first - whitelisted domains bypass blocking
        if self.is_whitelisted(domain_lower):
            return False, None, "whitelisted"

        # Check blocklist
        if domain_lower in self.blocked_domains:
            return True, self._categorize_domain(domain_lower), "blocklist"

        # Check parent domains
        parts = domain_lower.split(".")
        for i in range(1, len(parts)):
            parent = ".".join(parts[i:])
            if parent in self.blocked_domains:
                return True, self._categorize_domain(parent), f"blocklist:{parent}"

        # Check patterns
        for pattern in self._compiled_patterns:
            if pattern.search(domain_lower):
                return True, self._categorize_domain(domain_lower), f"pattern:{pattern.pattern}"

        return False, None, None

    def add_to_whitelist(
        self,
        domain: str,
        reason: str = None,
        added_by: str = "admin",
        expires_hours: int = None
    ) -> WhitelistEntry:
        """Add domain to whitelist."""
        now = datetime.utcnow()
        expires_at = None
        if expires_hours:
            expires_at = (now + timedelta(hours=expires_hours)).isoformat() + "Z"

        entry = WhitelistEntry(
            domain=domain.lower(),
            reason=reason,
            added_at=now.isoformat() + "Z",
            added_by=added_by,
            expires_at=expires_at
        )

        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO whitelist (domain, reason, added_at, added_by, expires_at)
            VALUES (?, ?, ?, ?, ?)
        """, (entry.domain, entry.reason, entry.added_at, entry.added_by, entry.expires_at))
        conn.commit()
        conn.close()

        # Update in-memory set
        self.whitelisted_domains.add(entry.domain)
        stats_cache.invalidate()

        return entry

    def remove_from_whitelist(self, domain: str) -> bool:
        """Remove domain from whitelist."""
        domain_lower = domain.lower()
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM whitelist WHERE domain = ?", (domain_lower,))
        affected = cursor.rowcount
        conn.commit()
        conn.close()

        if affected > 0:
            self.whitelisted_domains.discard(domain_lower)
            stats_cache.invalidate()

        return affected > 0

    def get_whitelist(self) -> List[WhitelistEntry]:
        """Get all whitelisted domains."""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute("SELECT domain, reason, added_at, added_by, expires_at FROM whitelist ORDER BY added_at DESC")

        entries = []
        for row in cursor.fetchall():
            entries.append(WhitelistEntry(
                domain=row[0],
                reason=row[1],
                added_at=row[2],
                added_by=row[3],
                expires_at=row[4]
            ))

        conn.close()
        return entries

    def cleanup_expired_whitelist(self) -> int:
        """Remove expired whitelist entries."""
        now = datetime.utcnow().isoformat() + "Z"
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute("""
            DELETE FROM whitelist WHERE expires_at IS NOT NULL AND expires_at < ?
        """, (now,))
        affected = cursor.rowcount
        conn.commit()
        conn.close()

        if affected > 0:
            self._load_blocklists()  # Reload to sync in-memory set
            stats_cache.invalidate()

        return affected

    def record_detection(
        self,
        client_ip: str,
        domain: str,
        client_mac: str = None,
        device_type: DeviceType = DeviceType.UNKNOWN,
        action: BlockAction = BlockAction.BLOCK
    ) -> AdDetection:
        """Record an ad/tracker detection."""
        is_ad, category, matched_rule = self.is_ad_domain(domain)

        if not is_ad:
            category = AdCategory.ADVERTISING  # Default if manually recorded

        now = datetime.utcnow().isoformat() + "Z"

        detection = AdDetection(
            timestamp=now,
            client_ip=client_ip,
            client_mac=client_mac,
            device_type=device_type,
            domain=domain,
            category=category,
            action=action,
            matched_rule=matched_rule
        )

        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()

        # Record detection
        cursor.execute("""
            INSERT INTO detections (timestamp, client_ip, client_mac, device_type, domain, category, action, matched_rule)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (now, client_ip, client_mac, device_type.value, domain, category.value, action.value, matched_rule))

        # Update blocklist hit count
        cursor.execute("""
            UPDATE blocklist SET hits = hits + 1, last_hit = ? WHERE domain = ?
        """, (now, domain.lower()))

        # Update device stats
        if client_mac:
            cursor.execute("""
                INSERT INTO devices (mac_address, ip_address, device_type, total_requests, blocked_requests, ad_requests, first_seen, last_seen)
                VALUES (?, ?, ?, 1, ?, ?, ?, ?)
                ON CONFLICT(mac_address) DO UPDATE SET
                    ip_address = ?,
                    total_requests = total_requests + 1,
                    blocked_requests = blocked_requests + ?,
                    ad_requests = ad_requests + 1,
                    last_seen = ?
            """, (
                client_mac, client_ip, device_type.value,
                1 if action == BlockAction.BLOCK else 0,
                1 if category == AdCategory.ADVERTISING else 0,
                now, now,
                client_ip,
                1 if action == BlockAction.BLOCK else 0,
                now
            ))

            # Update per-device domain stats
            cursor.execute("""
                INSERT INTO device_domains (mac_address, domain, category, hits, last_hit)
                VALUES (?, ?, ?, 1, ?)
                ON CONFLICT(mac_address, domain) DO UPDATE SET
                    hits = hits + 1,
                    last_hit = ?
            """, (client_mac, domain.lower(), category.value, now, now))

        conn.commit()
        conn.close()

        return detection

    def get_device_stats(self, mac_address: str = None) -> List[DeviceStats]:
        """Get statistics per device."""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()

        if mac_address:
            cursor.execute("SELECT * FROM devices WHERE mac_address = ?", (mac_address,))
        else:
            cursor.execute("SELECT * FROM devices ORDER BY blocked_requests DESC LIMIT 100")

        devices = []
        for row in cursor.fetchall():
            mac = row[0]

            # Get top blocked domains for this device
            cursor.execute("""
                SELECT domain, category, hits FROM device_domains
                WHERE mac_address = ?
                ORDER BY hits DESC LIMIT 10
            """, (mac,))
            top_domains = [
                {"domain": r[0], "category": r[1], "hits": r[2]}
                for r in cursor.fetchall()
            ]

            total = row[4] or 1
            blocked = row[5] or 0

            devices.append(DeviceStats(
                mac_address=mac,
                ip_address=row[1],
                hostname=row[2],
                device_type=DeviceType(row[3]) if row[3] else DeviceType.UNKNOWN,
                total_requests=total,
                blocked_requests=blocked,
                ad_requests=row[6] or 0,
                tracker_requests=row[7] or 0,
                top_blocked_domains=top_domains,
                last_seen=row[9] or "",
                block_rate=round(blocked / total * 100, 2) if total > 0 else 0
            ))

        conn.close()
        return devices

    def get_stats_by_device_type(self) -> Dict[str, Any]:
        """Get aggregated statistics by device type."""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT device_type,
                   COUNT(*) as device_count,
                   SUM(total_requests) as total_requests,
                   SUM(blocked_requests) as blocked_requests,
                   SUM(ad_requests) as ad_requests
            FROM devices
            GROUP BY device_type
            ORDER BY blocked_requests DESC
        """)

        stats = {}
        for row in cursor.fetchall():
            device_type = row[0] or "unknown"
            total = row[2] or 1
            blocked = row[3] or 0
            stats[device_type] = {
                "device_count": row[1],
                "total_requests": total,
                "blocked_requests": blocked,
                "ad_requests": row[4] or 0,
                "block_rate": round(blocked / total * 100, 2) if total > 0 else 0
            }

        conn.close()
        return stats

    def add_delayed_block(self, domain: str, reason: str, delay_hours: int = 24) -> DelayedBlock:
        """Add domain to delayed blocking queue."""
        now = datetime.utcnow()
        scheduled = now + timedelta(hours=delay_hours)

        entry = DelayedBlock(
            domain=domain.lower(),
            category=self._categorize_domain(domain),
            reason=reason,
            requested_at=now.isoformat() + "Z",
            scheduled_at=scheduled.isoformat() + "Z"
        )

        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO delayed_blocks (domain, category, reason, requested_at, scheduled_at)
            VALUES (?, ?, ?, ?, ?)
        """, (entry.domain, entry.category.value, entry.reason, entry.requested_at, entry.scheduled_at))
        conn.commit()
        conn.close()

        return entry

    def process_delayed_blocks(self) -> int:
        """Process delayed blocks that are due."""
        now = datetime.utcnow().isoformat() + "Z"
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()

        # Find due blocks
        cursor.execute("""
            SELECT domain, category FROM delayed_blocks
            WHERE scheduled_at <= ? AND approved = 1
        """, (now,))

        count = 0
        for row in cursor.fetchall():
            domain, category = row

            # Add to blocklist
            cursor.execute("""
                INSERT OR IGNORE INTO blocklist (domain, category, source, added_at)
                VALUES (?, ?, 'delayed', ?)
            """, (domain, category, now))

            # Remove from queue
            cursor.execute("DELETE FROM delayed_blocks WHERE domain = ?", (domain,))
            count += 1

        conn.commit()
        conn.close()

        if count > 0:
            self._load_blocklists()

        return count

    def get_delayed_blocks(self) -> List[DelayedBlock]:
        """Get pending delayed blocks."""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM delayed_blocks ORDER BY scheduled_at")

        blocks = []
        for row in cursor.fetchall():
            blocks.append(DelayedBlock(
                domain=row[0],
                category=AdCategory(row[1]),
                reason=row[2],
                requested_at=row[3],
                scheduled_at=row[4],
                approved=bool(row[5]),
                approved_by=row[6]
            ))

        conn.close()
        return blocks

    def approve_delayed_block(self, domain: str, approved_by: str = "admin") -> bool:
        """Approve a delayed block."""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE delayed_blocks SET approved = 1, approved_by = ?
            WHERE domain = ?
        """, (approved_by, domain.lower()))
        affected = cursor.rowcount
        conn.commit()
        conn.close()
        return affected > 0

    def get_top_blocked_domains(self, limit: int = 50) -> List[BlocklistEntry]:
        """Get most frequently blocked domains."""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT domain, category, source, added_at, hits, last_hit
            FROM blocklist
            WHERE hits > 0
            ORDER BY hits DESC
            LIMIT ?
        """, (limit,))

        entries = []
        for row in cursor.fetchall():
            entries.append(BlocklistEntry(
                domain=row[0],
                category=AdCategory(row[1]) if row[1] else AdCategory.ADVERTISING,
                source=row[2] or "unknown",
                added_at=row[3] or "",
                hits=row[4] or 0,
                last_hit=row[5]
            ))

        conn.close()
        return entries

    def get_stats(self) -> Dict[str, Any]:
        """Get overall ad guard statistics (cached)."""
        # Check cache first
        cached = stats_cache.get("overall_stats")
        if cached:
            return cached

        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM blocklist")
        blocklist_count = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM whitelist")
        whitelist_count = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM devices")
        device_count = cursor.fetchone()[0]

        cursor.execute("SELECT SUM(blocked_requests) FROM devices")
        total_blocked = cursor.fetchone()[0] or 0

        cursor.execute("SELECT COUNT(*) FROM delayed_blocks WHERE approved = 0")
        pending_blocks = cursor.fetchone()[0]

        # Last 24h stats
        yesterday = (datetime.utcnow() - timedelta(hours=24)).isoformat() + "Z"
        cursor.execute("""
            SELECT COUNT(*) FROM detections WHERE timestamp >= ?
        """, (yesterday,))
        detections_24h = cursor.fetchone()[0]

        # Category breakdown for last 24h
        cursor.execute("""
            SELECT category, COUNT(*) FROM detections
            WHERE timestamp >= ?
            GROUP BY category
            ORDER BY COUNT(*) DESC
        """, (yesterday,))
        category_breakdown = {row[0]: row[1] for row in cursor.fetchall()}

        conn.close()

        result = {
            "blocklist_domains": blocklist_count,
            "whitelist_domains": whitelist_count,
            "monitored_devices": device_count,
            "total_blocked": total_blocked,
            "detections_24h": detections_24h,
            "pending_delayed_blocks": pending_blocks,
            "category_breakdown_24h": category_breakdown,
            "cached_at": datetime.utcnow().isoformat() + "Z"
        }

        stats_cache.set("overall_stats", result)
        return result

    def get_category_stats(self, days: int = 7) -> List[CategoryStats]:
        """Get detailed statistics by category."""
        cache_key = f"category_stats_{days}"
        cached = stats_cache.get(cache_key)
        if cached:
            return cached

        since = (datetime.utcnow() - timedelta(days=days)).isoformat() + "Z"
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()

        # Get per-category stats
        cursor.execute("""
            SELECT category, COUNT(*) as total_hits, COUNT(DISTINCT domain) as unique_domains
            FROM detections
            WHERE timestamp >= ?
            GROUP BY category
            ORDER BY total_hits DESC
        """, (since,))

        stats = []
        for row in cursor.fetchall():
            category = row[0]

            # Get top domains for this category
            cursor.execute("""
                SELECT domain, COUNT(*) as hits FROM detections
                WHERE category = ? AND timestamp >= ?
                GROUP BY domain
                ORDER BY hits DESC LIMIT 10
            """, (category, since))

            top_domains = [{"domain": r[0], "hits": r[1]} for r in cursor.fetchall()]

            stats.append(CategoryStats(
                category=category,
                total_hits=row[1],
                unique_domains=row[2],
                top_domains=top_domains
            ))

        conn.close()
        stats_cache.set(cache_key, stats)
        return stats

    def cleanup_old_detections(self, days: int = DETECTION_RETENTION_DAYS) -> int:
        """Clean up detection history older than specified days."""
        cutoff = (datetime.utcnow() - timedelta(days=days)).isoformat() + "Z"
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()

        # Delete old detections
        cursor.execute("DELETE FROM detections WHERE timestamp < ?", (cutoff,))
        deleted_detections = cursor.rowcount

        # Also cleanup device_domains with no recent hits
        cursor.execute("DELETE FROM device_domains WHERE last_hit < ?", (cutoff,))
        deleted_domain_stats = cursor.rowcount

        conn.commit()
        conn.close()

        if deleted_detections > 0:
            stats_cache.invalidate()
            logger.info(f"Cleaned up {deleted_detections} old detections, {deleted_domain_stats} domain stats")

        return deleted_detections

    def get_db_stats(self) -> Dict[str, Any]:
        """Get database statistics for monitoring."""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()

        # Table sizes
        tables = ["blocklist", "whitelist", "devices", "detections", "device_domains", "delayed_blocks"]
        sizes = {}
        for table in tables:
            cursor.execute(f"SELECT COUNT(*) FROM {table}")
            sizes[table] = cursor.fetchone()[0]

        # Database file size
        db_size = self.db_file.stat().st_size if self.db_file.exists() else 0

        # Oldest detection
        cursor.execute("SELECT MIN(timestamp) FROM detections")
        oldest = cursor.fetchone()[0]

        conn.close()

        return {
            "table_counts": sizes,
            "db_size_bytes": db_size,
            "db_size_mb": round(db_size / (1024 * 1024), 2),
            "oldest_detection": oldest,
            "in_memory_blocked": len(self.blocked_domains),
            "in_memory_whitelisted": len(self.whitelisted_domains)
        }


# Global instance
guard = AdGuard(DATA_DIR)


# ============================================================================
# API Endpoints
# ============================================================================

@app.get("/status")
async def status():
    """Public status endpoint."""
    stats = guard.get_stats()
    return {
        "module": "ad-guard",
        "status": "ok",
        "version": "1.0.0",
        "blocklist_domains": stats["blocklist_domains"],
        "detections_24h": stats["detections_24h"]
    }


@app.get("/health")
async def health():
    """Health check."""
    return {"status": "healthy"}


@app.get("/stats", dependencies=[Depends(require_jwt)])
async def get_stats():
    """Get ad guard statistics."""
    return guard.get_stats()


@app.get("/stats/by-device-type", dependencies=[Depends(require_jwt)])
async def get_stats_by_device_type():
    """Get statistics grouped by device type."""
    return guard.get_stats_by_device_type()


@app.get("/devices", dependencies=[Depends(require_jwt)])
async def list_devices():
    """List device statistics."""
    devices = guard.get_device_stats()
    return {"devices": devices, "count": len(devices)}


@app.get("/devices/{mac_address}", dependencies=[Depends(require_jwt)])
async def get_device(mac_address: str):
    """Get specific device statistics."""
    devices = guard.get_device_stats(mac_address)
    if not devices:
        raise HTTPException(status_code=404, detail="Device not found")
    return devices[0]


@app.post("/detect", dependencies=[Depends(require_jwt)])
async def record_detection(
    background_tasks: BackgroundTasks,
    client_ip: str,
    domain: str,
    client_mac: str = None,
    device_type: DeviceType = DeviceType.UNKNOWN
):
    """Record an ad/tracker detection."""
    detection = guard.record_detection(client_ip, domain, client_mac, device_type)

    # Send webhook notification in background
    event = "block" if detection.action == BlockAction.BLOCK else "detect"
    background_tasks.add_task(
        guard._send_webhook,
        event,
        {
            "domain": detection.domain,
            "category": detection.category.value if detection.category else None,
            "client_ip": detection.client_ip,
            "client_mac": detection.client_mac,
            "action": detection.action.value
        }
    )

    # Invalidate stats cache on new detection
    stats_cache.invalidate("overall_stats")

    return detection


@app.get("/check/{domain}")
async def check_domain(domain: str):
    """Check if a domain is blocked (public endpoint)."""
    is_ad, category, rule = guard.is_ad_domain(domain)
    return {
        "domain": domain,
        "blocked": is_ad,
        "category": category.value if category else None,
        "matched_rule": rule
    }


@app.get("/blocklist/top", dependencies=[Depends(require_jwt)])
async def get_top_blocked(limit: int = 50):
    """Get most frequently blocked domains."""
    return {"domains": guard.get_top_blocked_domains(limit)}


@app.post("/blocklist/update", dependencies=[Depends(require_jwt)])
async def update_blocklists(sources: List[str] = None):
    """Update blocklists from sources."""
    results = await guard.update_blocklists(sources)
    return {"updated": results}


@app.post("/blocklist/add", dependencies=[Depends(require_jwt)])
async def add_to_blocklist(domain: str, category: AdCategory = AdCategory.ADVERTISING):
    """Add domain to blocklist immediately."""
    conn = sqlite3.connect(guard.db_file)
    cursor = conn.cursor()
    now = datetime.utcnow().isoformat() + "Z"
    cursor.execute("""
        INSERT OR REPLACE INTO blocklist (domain, category, source, added_at)
        VALUES (?, ?, 'manual', ?)
    """, (domain.lower(), category.value, now))
    conn.commit()
    conn.close()
    guard._load_blocklists()
    return {"status": "added", "domain": domain}


@app.delete("/blocklist/{domain}", dependencies=[Depends(require_jwt)])
async def remove_from_blocklist(domain: str):
    """Remove domain from blocklist."""
    conn = sqlite3.connect(guard.db_file)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM blocklist WHERE domain = ?", (domain.lower(),))
    affected = cursor.rowcount
    conn.commit()
    conn.close()
    if affected == 0:
        raise HTTPException(status_code=404, detail="Domain not in blocklist")
    guard._load_blocklists()
    return {"status": "removed"}


@app.get("/delayed", dependencies=[Depends(require_jwt)])
async def list_delayed_blocks():
    """List pending delayed blocks."""
    return {"delayed": guard.get_delayed_blocks()}


@app.post("/delayed", dependencies=[Depends(require_jwt)])
async def add_delayed_block(domain: str, reason: str, delay_hours: int = 24):
    """Add domain to delayed blocking queue."""
    entry = guard.add_delayed_block(domain, reason, delay_hours)
    return {"status": "queued", "entry": entry}


@app.post("/delayed/{domain}/approve", dependencies=[Depends(require_jwt)])
async def approve_delayed(domain: str):
    """Approve a delayed block."""
    if not guard.approve_delayed_block(domain):
        raise HTTPException(status_code=404, detail="Delayed block not found")
    return {"status": "approved"}


@app.post("/delayed/process", dependencies=[Depends(require_jwt)])
async def process_delayed():
    """Process due delayed blocks."""
    count = guard.process_delayed_blocks()
    return {"processed": count}


# ============================================================================
# Whitelist Endpoints
# ============================================================================

@app.get("/whitelist", dependencies=[Depends(require_jwt)])
async def get_whitelist():
    """Get all whitelisted domains."""
    entries = guard.get_whitelist()
    return {"whitelist": entries, "count": len(entries)}


@app.post("/whitelist", dependencies=[Depends(require_jwt)])
async def add_to_whitelist(
    domain: str,
    reason: str = None,
    expires_hours: int = None
):
    """Add domain to whitelist."""
    entry = guard.add_to_whitelist(domain, reason, expires_hours=expires_hours)
    return {"status": "added", "entry": entry}


@app.delete("/whitelist/{domain}", dependencies=[Depends(require_jwt)])
async def remove_from_whitelist(domain: str):
    """Remove domain from whitelist."""
    if not guard.remove_from_whitelist(domain):
        raise HTTPException(status_code=404, detail="Domain not in whitelist")
    return {"status": "removed"}


@app.post("/whitelist/cleanup", dependencies=[Depends(require_jwt)])
async def cleanup_expired_whitelist():
    """Remove expired whitelist entries."""
    count = guard.cleanup_expired_whitelist()
    return {"removed": count}


@app.get("/check/whitelist/{domain}")
async def check_whitelist(domain: str):
    """Check if domain is whitelisted (public endpoint)."""
    return {
        "domain": domain,
        "whitelisted": guard.is_whitelisted(domain)
    }


# ============================================================================
# Category Stats Endpoints
# ============================================================================

@app.get("/stats/categories", dependencies=[Depends(require_jwt)])
async def get_category_stats(days: int = 7):
    """Get statistics by category."""
    stats = guard.get_category_stats(days)
    return {"categories": stats, "period_days": days}


@app.get("/stats/db", dependencies=[Depends(require_jwt)])
async def get_db_stats():
    """Get database statistics for monitoring."""
    return guard.get_db_stats()


# ============================================================================
# Webhook Endpoints
# ============================================================================

@app.get("/webhooks", dependencies=[Depends(require_jwt)])
async def list_webhooks():
    """List configured webhooks."""
    webhooks = guard._load_webhooks()
    return {"webhooks": [wh.dict() for wh in webhooks]}


class AddWebhookRequest(BaseModel):
    url: str
    events: List[str] = ["block", "detect"]
    secret: Optional[str] = None
    timeout: float = 5.0


@app.post("/webhooks", dependencies=[Depends(require_jwt)])
async def add_webhook(request: AddWebhookRequest):
    """Add a webhook configuration."""
    webhooks = guard._load_webhooks()

    # Check for duplicate URL
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
    guard._save_webhooks(webhooks)

    return {"status": "added", "webhook": new_webhook.dict()}


@app.delete("/webhooks", dependencies=[Depends(require_jwt)])
async def remove_webhook(url: str):
    """Remove a webhook by URL."""
    webhooks = guard._load_webhooks()
    original_count = len(webhooks)
    webhooks = [wh for wh in webhooks if wh.url != url]

    if len(webhooks) == original_count:
        raise HTTPException(status_code=404, detail="Webhook not found")

    guard._save_webhooks(webhooks)
    return {"status": "removed"}


@app.post("/webhooks/test", dependencies=[Depends(require_jwt)])
async def test_webhook(url: str):
    """Test a webhook by sending a test event."""
    await guard._send_webhook("test", {
        "message": "This is a test event from SecuBox Ad Guard",
        "source": "manual_test"
    })
    return {"status": "sent"}


# ============================================================================
# Maintenance Endpoints
# ============================================================================

@app.post("/maintenance/cleanup", dependencies=[Depends(require_jwt)])
async def cleanup_old_data(days: int = 30):
    """Clean up old detection history."""
    deleted = guard.cleanup_old_detections(days)
    expired = guard.cleanup_expired_whitelist()
    return {
        "deleted_detections": deleted,
        "expired_whitelist_removed": expired
    }


@app.post("/maintenance/cache/clear", dependencies=[Depends(require_jwt)])
async def clear_cache():
    """Clear stats cache."""
    stats_cache.invalidate()
    return {"status": "cleared"}


@app.post("/maintenance/reload", dependencies=[Depends(require_jwt)])
async def reload_lists():
    """Reload blocklists and whitelists from database."""
    guard._load_blocklists()
    stats_cache.invalidate()
    return {
        "blocked_count": len(guard.blocked_domains),
        "whitelisted_count": len(guard.whitelisted_domains)
    }


# ============================================================================
# Startup
# ============================================================================

# Background task for periodic cleanup
async def periodic_cleanup():
    """Run periodic cleanup tasks."""
    while True:
        try:
            await asyncio.sleep(3600)  # Run every hour
            guard.cleanup_old_detections()
            guard.cleanup_expired_whitelist()
            logger.debug("Periodic cleanup completed")
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Periodic cleanup error: {e}")


cleanup_task: Optional[asyncio.Task] = None


@app.on_event("startup")
async def startup():
    """Initialize on startup."""
    global cleanup_task
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    # Start background cleanup task
    cleanup_task = asyncio.create_task(periodic_cleanup())
    logger.info("Ad Guard started with background cleanup")


@app.on_event("shutdown")
async def shutdown():
    """Cleanup on shutdown."""
    global cleanup_task
    if cleanup_task:
        cleanup_task.cancel()
        try:
            await cleanup_task
        except asyncio.CancelledError:
            pass
    logger.info("Ad Guard stopped")
