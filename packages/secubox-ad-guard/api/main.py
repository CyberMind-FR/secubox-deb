# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""SecuBox Ad Guard - Ad/Tracker Detection & Device Statistics
Detects advertising networks, tracking domains, and provides per-device statistics.

Features:
- Ad/tracker detection by DNS (blocklists compiled by secubox-dns-listes, per-device counters of dnstv)
- Per-device DPI for TV Privacy devices only (sbxdpi, lot 4 #3374: api/dnstv_dpi.py); ad-guard reads no nDPId feed
- Tracking domain classification
- Device statistics from the real inventory (dnstv devices by MAC, profiles from the NAC evidence, lot 1 #3374)
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
import stat
import subprocess
import asyncio
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, List, Any, Set, Callable
from enum import Enum
from collections import defaultdict
from functools import wraps

from fastapi import FastAPI, Depends, HTTPException
from secubox_core.auth import require_lecture
from pydantic import BaseModel, ConfigDict, Field, StrictInt
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

app = FastAPI(title="SecuBox Ad Guard", version="1.2.0")
logger = logging.getLogger("secubox.ad-guard")

# POC « DNS AdBlock TV » (#1943) : mesure du filtrage DNS par appareil (OBSERVE / BLOCK). Isolé : ses routes sont sous /adblock-tv,
# son état dans /var/lib/secubox/ad-guard/dnstv, et il ne fait RIEN tant qu'on ne l'active pas.
try:
    from . import direct, dnstv, stats_standard
    from .dnstv_routes import router as _tv_router
except ImportError:                                  # lancé hors paquet (tests, uvicorn api.main) : import absolu
    from api import direct, dnstv, stats_standard
    from api.dnstv_routes import router as _tv_router
app.include_router(_tv_router)
# lot 3 SBX TV PRIVACY (#3374) : routeur séparé, même préfixe /adblock-tv (déclaré dans son module, lu par les gardes du pilotage)
try:
    from .dnstv_lot3_routes import router as _tv_lot3_router
except ImportError:                                  # lancé hors paquet
    from api.dnstv_lot3_routes import router as _tv_lot3_router
app.include_router(_tv_lot3_router)
# lot 4 SBX TV PRIVACY (#3374) : DPI par appareil, même préfixe /adblock-tv
try:
    from .dnstv_lot4_routes import router as _tv_lot4_router
except ImportError:                                  # lancé hors paquet
    from api.dnstv_lot4_routes import router as _tv_lot4_router
app.include_router(_tv_lot4_router)
# lot 5b SBX TV PRIVACY (#3374) : assistant de détection en direct, même préfixe /adblock-tv
try:
    from .dnstv_lot5_routes import router as _tv_lot5_router
except ImportError:                                  # lancé hors paquet
    from api.dnstv_lot5_routes import router as _tv_lot5_router
app.include_router(_tv_lot5_router)
# #3666 : indices du maillage (interrupteurs publier / recevoir), même préfixe /adblock-tv
try:
    from .dnstv_indices_routes import router as _tv_indices_router
except ImportError:                                  # lancé hors paquet
    from api.dnstv_indices_routes import router as _tv_indices_router
app.include_router(_tv_indices_router)


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
        # Lot 6 (#3374) : plus de classeur par sous-chaînes (« samsung » prenait un téléphone pour une TV) ; le type vient des
        # profils du lot 1 (preuves du NAC), voir `_inventaire_reel`.

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

        # Ancienne table des appareils : plus alimentée ni lue pour l'inventaire depuis le lot 6 (#3374). Conservée telle quelle (aucune
        # migration destructive sur les box déjà installées) ; seuls les compteurs de /stats et /stats/db la lisent encore (0 ligne).
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

@app.get("/status", dependencies=[Depends(require_lecture)])
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


@app.get("/statut-direct", dependencies=[Depends(require_lecture)])
def statut_direct():
    """État en direct pour la bande d'état de la page (#2706) : résolveur, puits DNS, listes, capteur DNS, flux, clients actifs. Lecture seule ; cache de 5 s."""
    return direct.etat_direct_cache(lambda: dnstv.Magasin(dnstv.DOSSIER_ETAT / "dnstv.db"))


@app.get("/health")
async def health():
    """Health check."""
    return {"status": "healthy"}


_TOOLBOX_DB = "/var/lib/secubox/toolbox/toolbox.db"


def _stats_toolbox():
    """Blocages du MITM et appareils R3 d'après la base du toolbox, EN LECTURE SEULE ; None si elle n'est pas lisible (le toolbox est passé sous son propre
    utilisateur, dossier en 0750 : ce module ne peut plus l'ouvrir). Jamais un zéro inventé (#1963)."""
    try:
        c = sqlite3.connect(f"file:{_TOOLBOX_DB}?mode=ro", uri=True, timeout=5)
        try:
            return {"mitm_blocks_total": int(c.execute("SELECT COALESCE(SUM(hits),0) FROM ad_block_stats").fetchone()[0]),
                    "toolbox_clients": int(c.execute("SELECT COUNT(*) FROM clients").fetchone()[0])}
        finally:
            c.close()
    except Exception:
        return None


@app.get("/stats", dependencies=[Depends(require_jwt)])
async def get_stats():
    """Ad-guard statistics — AUGMENTED with the REAL board-wide blocking (#740).

    The module's own SQLite blocklist is empty (the curated blocking lives in the
    Unbound DNS sinkhole + the toolbox autolearn/MITM), so the dashboard used to
    read all-zeros. Reflect reality: blocklist = sinkhole NXDOMAIN domains +
    auto-learned trackers; devices + MITM block tally from the toolbox store.
    """
    s = dict(guard.get_stats() or {})              # COPIE : le dictionnaire du module est mis en cache, y écrire fausserait les appels suivants (#1963)
    # DNS sinkhole universe.
    sink = 0
    try:
        import json as _j
        from pathlib import Path as _Pp
        sink = int(_j.loads(_Pp("/var/lib/secubox/ad-guard/sinkhole-status.json")
                            .read_text()).get("blocked", 0))
    except Exception:
        pass
    learned = _learn_count(_LEARNED_F) or 0
    s["sinkhole_domains"] = sink
    s["learned_trackers"] = learned
    s["blocklist_domains"] = sink + learned
    # Le blocage réel est celui du puits DNS : ses compteurs (dnsfeed) donnent les chiffres de la partie standard (#1963). Source illisible : « dns_lisible: false ».
    try:
        magasin = dnstv.Magasin(dnstv.DOSSIER_ETAT / "dnstv.db")
        itf = dnstv.interface_lan()
        voisins = dnstv.lire_voisins(interface=itf) if itf else {}
        exclus = dnstv.adresses_locales() | dnstv.passerelles()
        jour = dnstv._jour(int(time.time()))
        debut = time.mktime(time.strptime(jour, "%Y-%m-%d")) - time.timezone              # minuit UTC du jour courant
        actifs = [c["client"] for c in magasin.par_client() if c["derniere_vue"] >= debut]
        dns = stats_standard.stats_dns(magasin.statistiques(depuis_jour=jour), actifs, voisins, exclus)
        s.update(dns)
        s["detections_24h"] = dns["dns_bloquees_jour"]                    # le champ que lit la carte « Bloqués »
        s["monitored_devices"] = dns["dns_appareils_jour"]
    except Exception:
        s["dns_lisible"] = False
        s.pop("detections_24h", None)                             # ces deux champs viennent de la base propre du module (inutilisée) : un 0 serait trompeur
        s.pop("monitored_devices", None)
    # Données du toolbox (blocages du MITM, appareils R3) : lisibles seulement si les droits le permettent. Sinon : absentes, jamais 0.
    tb = _stats_toolbox()
    s["toolbox_lisible"] = tb is not None
    if tb is not None:
        s.update(tb)
        s["blocked_24h"] = tb["mitm_blocks_total"]
    return s


# ── Inventaire des appareils (lot 6 SBX TV PRIVACY, #3374) ──────────────────────────────────────────────────────────────────
# `/devices` et `/stats/by-device-type` lisaient la table `devices`, que seul `POST /detect` (jamais appelé, retiré) alimentait : la page
# « Appareils » restait vide. Ils lisent désormais l'inventaire réel : les appareils déclarés de TV Privacy, regroupés par MAC, typés par les
# profils du lot 1 (preuves du NAC, jamais un nom ni une sous-chaîne), comptés par les compteurs DNS de dnstv.
_TYPE_DE_PROFIL = {"SAMSUNG_TIZEN": "smart_tv", "LG_WEBOS": "smart_tv", "ANDROID_TV": "smart_tv", "GENERIC_SMART_TV": "smart_tv",
                   "FREEBOX_PLAYER": "streaming", "APPLE_TV": "streaming", "GOOGLE_TV": "streaming"}
_NOTE_INVENTAIRE = ("Inventaire tiré des appareils déclarés dans TV Privacy (regroupés par adresse MAC, profil déduit des preuves du NAC). "
                    "Un appareil non déclaré n'y figure pas : l'inventaire complet du réseau est celui du NAC.")


def _inventaire_reel() -> Dict[str, Any]:
    try:
        from . import dnstv_routes as _tvr
    except ImportError:                                  # lancé hors paquet
        from api import dnstv_routes as _tvr
    _tvr._migrer()                                       # comme /adblock-tv/appareils : état v1 migré par MAC avant lecture
    etat, erreur = dnstv.lire_etat()
    if erreur or not etat:
        return {"devices": [], "count": 0, "source": "dnstv", "lisible": False,
                "note": f"Inventaire illisible ({erreur or 'état absent'}) : rien n'est affiché plutôt qu'un zéro trompeur."}
    vue = _tvr._vue_appareils(etat)
    try:
        magasin = dnstv.Magasin(dnstv.DOSSIER_ETAT / "dnstv.db")
    except Exception:                                    # noqa: BLE001 — base absente : appareils listés, compteurs inconnus
        magasin = None
    out = []
    for a in vue:
        total = bloquees = pubs = pistage = 0
        compte = magasin is not None
        for ip in a["ips"]:
            if magasin is None:
                break
            try:
                st = magasin.statistiques(client=ip)
            except Exception:                            # noqa: BLE001
                compte = False
                break
            total += int(st["requetes"] or 0)
            bloquees += int(st["par_decision"].get("BLOCKED") or 0)
            pubs += int(st["par_categorie"].get("advertising") or 0)
            pistage += int(st["par_categorie"].get("tracking") or 0)
        out.append({"mac_address": a["mac"] or "", "ip_address": a["ips"][0] if a["ips"] else None, "hostname": a["nom"],
                    "device_type": _TYPE_DE_PROFIL.get(a["profil"], "unknown"), "profil": a["profil"],
                    "profil_confiance": a["profil_confiance"], "total_requests": total if compte else None,
                    "blocked_requests": bloquees if compte else None, "ad_requests": pubs if compte else None,
                    "tracker_requests": pistage if compte else None,
                    "block_rate": (round(bloquees / total * 100, 2) if total else 0) if compte else None})
    out.sort(key=lambda d: -(d["blocked_requests"] or 0))
    return {"devices": out, "count": len(out), "source": "dnstv", "lisible": True, "note": "" if out else _NOTE_INVENTAIRE}


@app.get("/stats/by-device-type", dependencies=[Depends(require_jwt)])
async def get_stats_by_device_type():
    """Statistiques par type d'appareil, sur l'inventaire réel (lot 6, #3374)."""
    inv = await asyncio.to_thread(_inventaire_reel)
    stats: Dict[str, Dict[str, Any]] = {}
    for d in inv["devices"]:
        s = stats.setdefault(d["device_type"], {"device_count": 0, "total_requests": 0, "blocked_requests": 0, "ad_requests": 0})
        s["device_count"] += 1
        for k in ("total_requests", "blocked_requests", "ad_requests"):
            s[k] += d[k] or 0
    for s in stats.values():
        s["block_rate"] = round(s["blocked_requests"] / s["total_requests"] * 100, 2) if s["total_requests"] else 0
    return stats


@app.get("/devices", dependencies=[Depends(require_jwt)])
async def list_devices():
    """Appareils de l'inventaire réel (TV Privacy par MAC, profils du NAC) et leurs compteurs DNS."""
    return await asyncio.to_thread(_inventaire_reel)


@app.get("/devices/{mac_address}", dependencies=[Depends(require_jwt)])
async def get_device(mac_address: str):
    """Un appareil de l'inventaire réel, par MAC."""
    inv = await asyncio.to_thread(_inventaire_reel)
    for d in inv["devices"]:
        if d["mac_address"] and d["mac_address"] == mac_address.lower():
            return d
    raise HTTPException(status_code=404, detail="Device not found")


@app.get("/check/{domain}", dependencies=[Depends(require_lecture)])
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


@app.get("/check/whitelist/{domain}", dependencies=[Depends(require_lecture)])
async def check_whitelist(domain: str):
    """Check if domain is whitelisted (public endpoint)."""
    return {
        "domain": domain,
        "whitelisted": guard.is_whitelisted(domain)
    }


# ── Auto-learning (#740 volet 5) — surface the toolbox autolearn ─────────────
import sys as _sys
import json as _json
import subprocess as _sp
from pathlib import Path as _P

for _tp in ("/usr/lib/secubox/toolbox", "/usr/lib/python3/dist-packages"):
    if _tp not in _sys.path:
        _sys.path.append(_tp)

_LEARNED_F = _P("/var/lib/secubox/toolbox/learned-trackers.txt")
_PURE_F = _P("/var/lib/secubox/toolbox/pure-trackers.txt")
_ADALLOW_F = _P("/var/lib/secubox/toolbox/ad-allowlist.txt")
_FILTERS_F = _P("/etc/secubox/toolbox/filters.json")
_LEARN_DEFAULTS = {
    "autolearn_ad_min_sites": 2, "autolearn_social_min_sites": 3,
    "autolearn_min_sites": 2, "autolearn_social_window_hours": 168,
    "autolearn_ti_min_weight": 40,
}


def _learn_count(p: _P):
    """Nombre de lignes utiles d'un fichier du toolbox, ou None s'il est ILLISIBLE (droits, absence) : jamais un zéro qui laisse croire qu'il n'y a rien (#1963)."""
    try:
        return sum(1 for ln in p.read_text().splitlines()
                   if ln.strip() and not ln.startswith("#"))
    except Exception:
        return None


@app.get("/learn/status", dependencies=[Depends(require_jwt)])
async def learn_status():
    """Auto-learning state: learned/pure/allowlist counts + tunable thresholds."""
    f = {}
    try:
        import json as _jf
        brut = _jf.loads(_FILTERS_F.read_text())              # le fichier de réglages du toolbox est lisible ; l'import du paquet toolbox ne l'est pas toujours
        f = brut if isinstance(brut, dict) else {}
    except Exception:
        f = {}
    thr = {k: f.get(k, d) for k, d in _LEARN_DEFAULTS.items()}
    compteurs = {"learned": _learn_count(_LEARNED_F), "pure": _learn_count(_PURE_F), "allowlist": _learn_count(_ADALLOW_F)}
    return {
        **compteurs,
        "lisible": all(v is not None for v in compteurs.values()),   # faux : les données d'apprentissage du toolbox ne sont pas lisibles par ce module
        "ad_learn": f["ad_learn"] if isinstance(f.get("ad_learn"), bool) else None,      # None = inconnu (jamais un « vert » par défaut)
        "autolearn": f["autolearn"] if isinstance(f.get("autolearn"), bool) else None,
        "thresholds": thr,
    }


@app.get("/learn/trackers", dependencies=[Depends(require_jwt)])
async def learn_trackers(limit: int = 300):
    """The auto-learned tracker hosts (alphabetical, capped)."""
    try:
        items = sorted({ln.strip() for ln in _LEARNED_F.read_text().splitlines()
                        if ln.strip() and not ln.startswith("#")})
    except Exception:
        items = []
    return {"total": len(items), "trackers": items[:limit]}


@app.post("/learn/run", dependencies=[Depends(require_jwt)])
async def learn_run():
    """Trigger one autolearn cycle now (hourly otherwise)."""
    try:
        _sp.Popen(["sudo", "-n", "systemctl", "start",
                   "secubox-toolbox-autolearn.service"])
        return {"status": "started"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


class SeuilsApprentissage(BaseModel):
    """Seuils de l'autolearn du toolbox (lot 6, #3374) : clés connues seulement, entiers stricts et bornés ; au moins une clé."""
    model_config = ConfigDict(extra="forbid")
    autolearn_ad_min_sites: Optional[StrictInt] = Field(None, ge=1, le=100)
    autolearn_social_min_sites: Optional[StrictInt] = Field(None, ge=1, le=100)
    autolearn_min_sites: Optional[StrictInt] = Field(None, ge=1, le=100)
    autolearn_social_window_hours: Optional[StrictInt] = Field(None, ge=1, le=24 * 365)
    autolearn_ti_min_weight: Optional[StrictInt] = Field(None, ge=0, le=100)


_CTL_TV = os.environ.get("SECUBOX_ADGUARD_TV_CTL", "/usr/sbin/secubox-adguard-tv")


def _argv_seuils() -> list:
    """Verbe root EXACT du sudoers (#3393) : l'agrégateur tourne sous `secubox`, qui ne peut pas écrire filters.json (secubox-toolbox 664,
    dossier root 755) et n'entre pas dans le groupe secubox-toolbox."""
    return ["sudo", "-n", _CTL_TV, "seuils"] if os.geteuid() != 0 else [_CTL_TV, "seuils"]


_ECRITURE_REFUSEE = "écriture non autorisée : contrôleur secubox-adguard-tv seuils ou sudo indisponible (rien n'est écrit)"


@app.post("/learn/thresholds")
async def learn_set_thresholds(body: SeuilsApprentissage, jeton=Depends(require_jwt)):
    """Tune autolearn aggressiveness (persisted to filters.json, next cycle). Corps validé (422 sinon) ; l'écriture EN PLACE, le verrou et
    l'audit sont faits par root (`secubox-adguard-tv seuils`, données sur l'entrée standard, revalidées). 409 : filters.json absent, lien
    ou illisible ; 503 : verbe ou sudo indisponible ; 502 : écriture refusée par le contrôleur. Jamais 500."""
    changed = body.model_dump(exclude_none=True)
    if not changed:
        raise HTTPException(status_code=422, detail="aucun seuil donné")
    sub = str(jeton.get("sub") or "inconnu") if isinstance(jeton, dict) else "inconnu"
    acteur = sub if re.fullmatch(r"[A-Za-z0-9_.@-]{1,64}", sub) else "inconnu"
    entree = _json.dumps({"acteur": acteur, "seuils": changed})
    try:
        r = await asyncio.to_thread(subprocess.run, _argv_seuils(), input=entree, capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        logger.warning("learn/thresholds : contrôleur seuils hors délai (verrou tenu ?)")
        raise HTTPException(status_code=503, detail="contrôleur occupé, réessayer") from None
    except OSError as e:
        logger.warning("learn/thresholds : contrôleur seuils injoignable (%s)", type(e).__name__)
        raise HTTPException(status_code=503, detail=_ECRITURE_REFUSEE) from None
    msg = (r.stderr or "").strip()[:300]
    if not msg.startswith(("filters.json", "seuils refusés")):          # seuls les messages connus du contrôleur, jamais une trace
        msg = ""
    if r.returncode == 0:
        return {"status": "ok", "changed": changed, "note": "applies next cycle"}
    if r.returncode == 4 and msg:
        raise HTTPException(status_code=409, detail=msg)
    if r.returncode == 2 and msg:
        raise HTTPException(status_code=422, detail=msg)
    if r.returncode == 1 and msg:
        raise HTTPException(status_code=502, detail=msg)
    logger.warning("learn/thresholds : écriture refusée rc=%s stderr=%r", r.returncode, (r.stderr or "")[:200])
    raise HTTPException(status_code=503, detail=_ECRITURE_REFUSEE)


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
