"""SecuBox CyberFeed API - Threat Intelligence Feed Aggregator

Aggregates threat feeds from multiple sources (abuse.ch, Spamhaus, etc.)
and provides unified blocklist management for IPs, domains, and IoCs.

Features:
- Multi-source feed aggregation
- IP and domain blocklist management
- Threat indicator (IoC) tracking
- Scheduled feed updates
- Feed health monitoring
"""
import asyncio
import os
import json
import re
import hashlib
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, List, Any
from enum import Enum

from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
import httpx

from secubox_core.auth import require_jwt
from secubox_core.config import get_config

# Configuration paths
CONFIG_DIR = Path("/etc/secubox/cyberfeed")
DATA_DIR = Path("/var/lib/secubox/cyberfeed")
CACHE_DIR = DATA_DIR / "cache"
STATE_FILE = DATA_DIR / "state.json"

app = FastAPI(title="SecuBox CyberFeed", version="1.0.0")
config = get_config("cyberfeed")

# Ensure directories exist
try:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
except PermissionError:
    pass


class FeedType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"
    MIXED = "mixed"


class FeedFormat(str, Enum):
    PLAIN = "plain"
    CSV = "csv"
    JSON = "json"
    HOSTS = "hosts"


class FeedStatus(str, Enum):
    ACTIVE = "active"
    ERROR = "error"
    UPDATING = "updating"
    DISABLED = "disabled"


class ThreatFeed(BaseModel):
    name: str
    url: str
    feed_type: FeedType = FeedType.IP
    format: FeedFormat = FeedFormat.PLAIN
    enabled: bool = True
    update_interval: int = 3600  # seconds
    description: Optional[str] = None
    category: Optional[str] = None


class Indicator(BaseModel):
    value: str
    ioc_type: str  # ip, domain, url, hash
    source: str
    first_seen: str
    last_seen: str
    confidence: float = 0.5
    tags: List[str] = []


class FeedManager:
    """Manages threat intelligence feeds and blocklists."""

    # Built-in threat feeds
    BUILTIN_FEEDS = [
        {
            "name": "abuse-ch-feodo",
            "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
            "feed_type": "ip",
            "format": "plain",
            "category": "botnet",
            "description": "Feodo Tracker - Botnet C2 IPs"
        },
        {
            "name": "abuse-ch-sslbl",
            "url": "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
            "feed_type": "ip",
            "format": "plain",
            "category": "malware",
            "description": "SSL Blacklist - Malware C2 IPs"
        },
        {
            "name": "abuse-ch-urlhaus-domain",
            "url": "https://urlhaus.abuse.ch/downloads/hostfile/",
            "feed_type": "domain",
            "format": "hosts",
            "category": "malware",
            "description": "URLhaus - Malware domains"
        },
        {
            "name": "spamhaus-drop",
            "url": "https://www.spamhaus.org/drop/drop.txt",
            "feed_type": "ip",
            "format": "plain",
            "category": "spam",
            "description": "Spamhaus DROP - Do Not Route Or Peer"
        },
        {
            "name": "spamhaus-edrop",
            "url": "https://www.spamhaus.org/drop/edrop.txt",
            "feed_type": "ip",
            "format": "plain",
            "category": "spam",
            "description": "Spamhaus EDROP - Extended DROP"
        },
        {
            "name": "emergingthreats-compromised",
            "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
            "feed_type": "ip",
            "format": "plain",
            "category": "threats",
            "description": "Emerging Threats - Compromised IPs"
        },
        {
            "name": "blocklist-de-all",
            "url": "https://lists.blocklist.de/lists/all.txt",
            "feed_type": "ip",
            "format": "plain",
            "category": "abuse",
            "description": "blocklist.de - All attacks"
        },
        {
            "name": "phishing-army",
            "url": "https://phishing.army/download/phishing_army_blocklist.txt",
            "feed_type": "domain",
            "format": "plain",
            "category": "phishing",
            "description": "Phishing Army - Phishing domains"
        },
        {
            "name": "openphish",
            "url": "https://openphish.com/feed.txt",
            "feed_type": "url",
            "format": "plain",
            "category": "phishing",
            "description": "OpenPhish - Phishing URLs"
        },
        {
            "name": "tor-exit-nodes",
            "url": "https://check.torproject.org/torbulkexitlist",
            "feed_type": "ip",
            "format": "plain",
            "category": "anonymizer",
            "description": "Tor Exit Nodes"
        },
        {
            "name": "cinsscore-badguys",
            "url": "https://cinsscore.com/list/ci-badguys.txt",
            "feed_type": "ip",
            "format": "plain",
            "category": "threats",
            "description": "CINS Score - Bad reputation IPs"
        },
        {
            "name": "alienvault-reputation",
            "url": "https://reputation.alienvault.com/reputation.generic",
            "feed_type": "ip",
            "format": "plain",
            "category": "reputation",
            "description": "AlienVault OTX - IP reputation"
        },
    ]

    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self.cache_dir = data_dir / "cache"
        self.state_file = data_dir / "state.json"
        self._ensure_dirs()
        self._load_state()

    def _ensure_dirs(self):
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _load_state(self):
        """Load persistent state."""
        self.state = {
            "enabled": True,
            "feeds": {},
            "last_update": None,
            "stats": {
                "total_ips": 0,
                "total_domains": 0,
                "total_urls": 0,
                "total_hashes": 0
            }
        }
        if self.state_file.exists():
            try:
                self.state = json.loads(self.state_file.read_text())
            except Exception:
                pass

    def _save_state(self):
        """Save state to disk."""
        try:
            self.state_file.write_text(json.dumps(self.state, indent=2))
        except Exception:
            pass

    def get_feed_info(self, name: str) -> Optional[dict]:
        """Get feed information."""
        # Check custom feeds
        if name in self.state.get("feeds", {}):
            return self.state["feeds"][name]
        # Check builtin feeds
        for feed in self.BUILTIN_FEEDS:
            if feed["name"] == name:
                return feed
        return None

    def list_feeds(self) -> List[dict]:
        """List all available feeds."""
        feeds = []

        # Add builtin feeds
        for feed in self.BUILTIN_FEEDS:
            feed_data = dict(feed)
            feed_data["builtin"] = True

            # Check if enabled in state
            state_feed = self.state.get("feeds", {}).get(feed["name"], {})
            feed_data["enabled"] = state_feed.get("enabled", False)
            feed_data["status"] = state_feed.get("status", "disabled")
            feed_data["last_update"] = state_feed.get("last_update")
            feed_data["entry_count"] = state_feed.get("entry_count", 0)
            feed_data["error"] = state_feed.get("error")

            feeds.append(feed_data)

        # Add custom feeds
        for name, feed in self.state.get("feeds", {}).items():
            if not any(f["name"] == name for f in self.BUILTIN_FEEDS):
                feed_data = dict(feed)
                feed_data["builtin"] = False
                feeds.append(feed_data)

        return feeds

    def add_feed(self, feed: ThreatFeed) -> dict:
        """Add a new custom feed."""
        feed_data = feed.model_dump()
        feed_data["builtin"] = False
        feed_data["status"] = "disabled" if not feed.enabled else "active"
        feed_data["last_update"] = None
        feed_data["entry_count"] = 0

        self.state.setdefault("feeds", {})[feed.name] = feed_data
        self._save_state()

        return feed_data

    def enable_feed(self, name: str, enabled: bool = True) -> bool:
        """Enable or disable a feed."""
        if name not in self.state.get("feeds", {}):
            # Initialize builtin feed in state
            feed_info = None
            for feed in self.BUILTIN_FEEDS:
                if feed["name"] == name:
                    feed_info = dict(feed)
                    break
            if not feed_info:
                return False
            self.state.setdefault("feeds", {})[name] = feed_info

        self.state["feeds"][name]["enabled"] = enabled
        self.state["feeds"][name]["status"] = "active" if enabled else "disabled"
        self._save_state()
        return True

    def remove_feed(self, name: str) -> bool:
        """Remove a custom feed."""
        if name in self.state.get("feeds", {}):
            # Don't allow removing builtin feeds
            if self.state["feeds"][name].get("builtin", False):
                return False
            del self.state["feeds"][name]
            self._save_state()

            # Remove cache file
            cache_file = self.cache_dir / f"{name}.txt"
            cache_file.unlink(missing_ok=True)
            return True
        return False

    async def update_feed(self, name: str) -> dict:
        """Update a single feed."""
        feed_info = self.get_feed_info(name)
        if not feed_info:
            return {"success": False, "error": "Feed not found"}

        # Initialize feed in state if not present
        if name not in self.state.get("feeds", {}):
            self.state.setdefault("feeds", {})[name] = dict(feed_info)

        self.state["feeds"][name]["status"] = "updating"
        self._save_state()

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.get(
                    feed_info["url"],
                    follow_redirects=True,
                    headers={"User-Agent": "SecuBox-CyberFeed/1.0"}
                )
                response.raise_for_status()

                content = response.text
                cache_file = self.cache_dir / f"{name}.txt"
                cache_file.write_text(content)

                # Parse entries
                entries = self._parse_feed(content, feed_info)
                entry_count = len(entries)

                # Update state
                self.state["feeds"][name]["status"] = "active"
                self.state["feeds"][name]["last_update"] = datetime.utcnow().isoformat() + "Z"
                self.state["feeds"][name]["entry_count"] = entry_count
                self.state["feeds"][name]["error"] = None
                self._save_state()

                return {
                    "success": True,
                    "name": name,
                    "entries": entry_count
                }

        except Exception as e:
            self.state["feeds"][name]["status"] = "error"
            self.state["feeds"][name]["error"] = str(e)
            self._save_state()
            return {"success": False, "error": str(e)}

    async def update_all_feeds(self) -> List[dict]:
        """Update all enabled feeds."""
        results = []
        for feed in self.list_feeds():
            if feed.get("enabled", False):
                result = await self.update_feed(feed["name"])
                results.append(result)
        return results

    def _parse_feed(self, content: str, feed_info: dict) -> List[str]:
        """Parse feed content and extract entries."""
        entries = []
        format_type = feed_info.get("format", "plain")
        feed_type = feed_info.get("feed_type", "ip")

        for line in content.split('\n'):
            line = line.strip()

            # Skip comments and empty lines
            if not line or line.startswith('#') or line.startswith(';'):
                continue

            if format_type == "hosts":
                # Format: 0.0.0.0 domain.com or 127.0.0.1 domain.com
                parts = line.split()
                if len(parts) >= 2 and parts[0] in ["0.0.0.0", "127.0.0.1"]:
                    entry = parts[1].lower()
                    if entry not in ["localhost", "localhost.localdomain"]:
                        entries.append(entry)
            elif format_type == "csv":
                # First column is the indicator
                parts = line.split(',')
                if parts:
                    entries.append(parts[0].strip())
            else:
                # Plain format - extract first token, remove comments
                entry = line.split('#')[0].split(';')[0].strip()
                if entry:
                    # For IP feeds, validate IP format
                    if feed_type == "ip":
                        if re.match(r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$', entry):
                            entries.append(entry)
                    else:
                        entries.append(entry)

        return entries

    def get_blocklist_ips(self) -> List[str]:
        """Get aggregated IP blocklist."""
        ips = set()
        for feed in self.list_feeds():
            if not feed.get("enabled", False):
                continue
            if feed.get("feed_type") != "ip":
                continue

            cache_file = self.cache_dir / f"{feed['name']}.txt"
            if cache_file.exists():
                content = cache_file.read_text()
                entries = self._parse_feed(content, feed)
                ips.update(entries)

        return sorted(list(ips))

    def get_blocklist_domains(self) -> List[str]:
        """Get aggregated domain blocklist."""
        domains = set()
        for feed in self.list_feeds():
            if not feed.get("enabled", False):
                continue
            if feed.get("feed_type") != "domain":
                continue

            cache_file = self.cache_dir / f"{feed['name']}.txt"
            if cache_file.exists():
                content = cache_file.read_text()
                entries = self._parse_feed(content, feed)
                domains.update(entries)

        return sorted(list(domains))

    def get_indicators(self, ioc_type: Optional[str] = None, limit: int = 100) -> List[dict]:
        """Get threat indicators (IoCs)."""
        indicators = []
        now = datetime.utcnow().isoformat() + "Z"

        for feed in self.list_feeds():
            if not feed.get("enabled", False):
                continue

            feed_type = feed.get("feed_type", "ip")
            if ioc_type and feed_type != ioc_type:
                continue

            cache_file = self.cache_dir / f"{feed['name']}.txt"
            if not cache_file.exists():
                continue

            content = cache_file.read_text()
            entries = self._parse_feed(content, feed)

            for entry in entries[:limit // len([f for f in self.list_feeds() if f.get("enabled")]) + 1]:
                indicators.append({
                    "value": entry,
                    "ioc_type": feed_type,
                    "source": feed["name"],
                    "category": feed.get("category", "unknown"),
                    "first_seen": feed.get("last_update", now),
                    "last_seen": now
                })

            if len(indicators) >= limit:
                break

        return indicators[:limit]

    def get_stats(self) -> dict:
        """Get aggregated statistics."""
        stats = {
            "total_feeds": 0,
            "active_feeds": 0,
            "total_ips": 0,
            "total_domains": 0,
            "total_urls": 0,
            "feeds_with_errors": 0,
            "last_global_update": self.state.get("last_update")
        }

        for feed in self.list_feeds():
            stats["total_feeds"] += 1
            if feed.get("enabled", False):
                stats["active_feeds"] += 1
                entry_count = feed.get("entry_count", 0)
                if feed.get("feed_type") == "ip":
                    stats["total_ips"] += entry_count
                elif feed.get("feed_type") == "domain":
                    stats["total_domains"] += entry_count
                elif feed.get("feed_type") == "url":
                    stats["total_urls"] += entry_count
            if feed.get("status") == "error":
                stats["feeds_with_errors"] += 1

        return stats

    def check_ip(self, ip: str) -> dict:
        """Check if an IP is in any blocklist."""
        matches = []
        for feed in self.list_feeds():
            if not feed.get("enabled", False) or feed.get("feed_type") != "ip":
                continue

            cache_file = self.cache_dir / f"{feed['name']}.txt"
            if cache_file.exists():
                content = cache_file.read_text()
                entries = self._parse_feed(content, feed)
                if ip in entries:
                    matches.append({
                        "feed": feed["name"],
                        "category": feed.get("category"),
                        "description": feed.get("description")
                    })

        return {
            "ip": ip,
            "blocked": len(matches) > 0,
            "matches": matches
        }

    def check_domain(self, domain: str) -> dict:
        """Check if a domain is in any blocklist."""
        matches = []
        domain = domain.lower()

        for feed in self.list_feeds():
            if not feed.get("enabled", False) or feed.get("feed_type") != "domain":
                continue

            cache_file = self.cache_dir / f"{feed['name']}.txt"
            if cache_file.exists():
                content = cache_file.read_text()
                entries = self._parse_feed(content, feed)
                if domain in entries:
                    matches.append({
                        "feed": feed["name"],
                        "category": feed.get("category"),
                        "description": feed.get("description")
                    })

        return {
            "domain": domain,
            "blocked": len(matches) > 0,
            "matches": matches
        }


# Global instance
feed_manager = FeedManager(DATA_DIR)


# ============================================================================
# API Endpoints
# ============================================================================

@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy", "module": "cyberfeed"}


@app.get("/status")
async def status():
    """Public status endpoint."""
    stats = feed_manager.get_stats()
    return {
        "module": "cyberfeed",
        "status": "ok",
        "version": "1.0.0",
        "active_feeds": stats["active_feeds"],
        "total_ips": stats["total_ips"],
        "total_domains": stats["total_domains"]
    }


@app.get("/stats", dependencies=[Depends(require_jwt)])
async def get_stats():
    """Get aggregated statistics."""
    return feed_manager.get_stats()


@app.get("/feeds", dependencies=[Depends(require_jwt)])
async def list_feeds():
    """List all available feeds."""
    return {"feeds": feed_manager.list_feeds()}


@app.get("/feed/{name}", dependencies=[Depends(require_jwt)])
async def get_feed(name: str):
    """Get feed details."""
    feeds = feed_manager.list_feeds()
    for feed in feeds:
        if feed["name"] == name:
            return feed
    raise HTTPException(status_code=404, detail="Feed not found")


@app.post("/feed/{name}/enable", dependencies=[Depends(require_jwt)])
async def enable_feed(name: str, enabled: bool = True):
    """Enable or disable a feed."""
    if feed_manager.enable_feed(name, enabled):
        return {"success": True, "name": name, "enabled": enabled}
    raise HTTPException(status_code=404, detail="Feed not found")


@app.post("/feed/{name}/update", dependencies=[Depends(require_jwt)])
async def update_feed(name: str, background_tasks: BackgroundTasks):
    """Update a specific feed."""
    result = await feed_manager.update_feed(name)
    if not result["success"]:
        raise HTTPException(status_code=400, detail=result.get("error", "Update failed"))
    return result


@app.post("/feeds/add", dependencies=[Depends(require_jwt)])
async def add_feed(feed: ThreatFeed):
    """Add a custom feed."""
    return feed_manager.add_feed(feed)


@app.delete("/feeds/{name}", dependencies=[Depends(require_jwt)])
async def remove_feed(name: str):
    """Remove a custom feed."""
    if feed_manager.remove_feed(name):
        return {"success": True, "name": name}
    raise HTTPException(status_code=400, detail="Cannot remove feed (builtin or not found)")


@app.post("/feeds/update", dependencies=[Depends(require_jwt)])
async def update_all_feeds():
    """Update all enabled feeds."""
    results = await feed_manager.update_all_feeds()
    return {"results": results}


@app.get("/blocklist/ips", dependencies=[Depends(require_jwt)])
async def get_ip_blocklist(limit: int = 1000, offset: int = 0):
    """Get aggregated IP blocklist."""
    ips = feed_manager.get_blocklist_ips()
    return {
        "total": len(ips),
        "offset": offset,
        "limit": limit,
        "ips": ips[offset:offset + limit]
    }


@app.get("/blocklist/domains", dependencies=[Depends(require_jwt)])
async def get_domain_blocklist(limit: int = 1000, offset: int = 0):
    """Get aggregated domain blocklist."""
    domains = feed_manager.get_blocklist_domains()
    return {
        "total": len(domains),
        "offset": offset,
        "limit": limit,
        "domains": domains[offset:offset + limit]
    }


@app.get("/indicators", dependencies=[Depends(require_jwt)])
async def get_indicators(ioc_type: Optional[str] = None, limit: int = 100):
    """Get threat indicators (IoCs)."""
    indicators = feed_manager.get_indicators(ioc_type, limit)
    return {"indicators": indicators, "count": len(indicators)}


@app.get("/check/ip/{ip}", dependencies=[Depends(require_jwt)])
async def check_ip(ip: str):
    """Check if an IP is in blocklists."""
    return feed_manager.check_ip(ip)


@app.get("/check/domain/{domain}", dependencies=[Depends(require_jwt)])
async def check_domain(domain: str):
    """Check if a domain is in blocklists."""
    return feed_manager.check_domain(domain)


@app.get("/export/ips", dependencies=[Depends(require_jwt)])
async def export_ips(format: str = "plain"):
    """Export IP blocklist in various formats."""
    ips = feed_manager.get_blocklist_ips()

    if format == "nftables":
        content = "define CYBERFEED_IPS = {\n"
        for ip in ips[:500]:  # Limit for nftables
            content += f"    {ip},\n"
        content += "}\n"
    elif format == "hosts":
        content = "# SecuBox CyberFeed IP Blocklist\n"
        for ip in ips:
            content += f"0.0.0.0 {ip}\n"
    else:
        content = "# SecuBox CyberFeed IP Blocklist\n"
        for ip in ips:
            content += f"{ip}\n"

    return {"format": format, "count": len(ips), "content": content}


@app.get("/export/domains", dependencies=[Depends(require_jwt)])
async def export_domains(format: str = "plain"):
    """Export domain blocklist in various formats."""
    domains = feed_manager.get_blocklist_domains()

    if format == "hosts":
        content = "# SecuBox CyberFeed Domain Blocklist\n"
        for domain in domains:
            content += f"0.0.0.0 {domain}\n"
    elif format == "unbound":
        content = "# SecuBox CyberFeed Domain Blocklist\nserver:\n"
        for domain in domains[:5000]:  # Limit for unbound
            content += f'    local-zone: "{domain}" refuse\n'
    elif format == "dnsmasq":
        content = "# SecuBox CyberFeed Domain Blocklist\n"
        for domain in domains:
            content += f"address=/{domain}/\n"
    else:
        content = "# SecuBox CyberFeed Domain Blocklist\n"
        for domain in domains:
            content += f"{domain}\n"

    return {"format": format, "count": len(domains), "content": content}


# ============================================================================
# Startup
# ============================================================================

@app.on_event("startup")
async def startup():
    """Initialize on startup."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
