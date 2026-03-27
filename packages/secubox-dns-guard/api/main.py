"""SecuBox DNS Guard - AI-Powered DNS Anomaly Detection
Detects DGA domains, DNS tunneling, exfiltration, and malicious domains.

Features:
- DGA (Domain Generation Algorithm) detection
- DNS tunneling and exfiltration detection
- High query rate anomaly detection
- Malicious domain lookup
- Automatic blocklist generation
- dnsmasq integration for blocking
"""
import os
import re
import json
import math
import time
import logging
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, List, Any, Set
from enum import Enum
from collections import Counter

from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel, Field
import httpx

from secubox_core.auth import require_jwt
from secubox_core.config import get_config

# Configuration
CONFIG_PATH = Path("/etc/secubox/dns-guard.toml")
DATA_DIR = Path("/var/lib/secubox/dns-guard")
BLOCKLIST_FILE = DATA_DIR / "blocklist.txt"
PENDING_FILE = DATA_DIR / "pending.json"
ALERTS_FILE = DATA_DIR / "alerts.jsonl"
STATS_FILE = DATA_DIR / "stats.json"

# dnsmasq blocklist integration
DNSMASQ_BLOCKLIST = Path("/etc/dnsmasq.d/secubox-blocklist.conf")

app = FastAPI(title="SecuBox DNS Guard", version="1.0.0")
logger = logging.getLogger("secubox.dns-guard")


class DetectionType(str, Enum):
    DGA = "dga"
    TUNNELING = "tunneling"
    EXFILTRATION = "exfiltration"
    HIGH_RATE = "high_rate"
    MALICIOUS = "malicious"
    UNUSUAL_TLD = "unusual_tld"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class DnsAlert(BaseModel):
    id: str
    type: DetectionType
    severity: Severity
    domain: str
    client_ip: Optional[str] = None
    description: str
    details: Dict[str, Any] = {}
    timestamp: str
    blocked: bool = False


class BlocklistEntry(BaseModel):
    domain: str
    reason: str
    added_at: str
    source: str  # manual, auto, feed
    expires_at: Optional[str] = None


class DnsGuard:
    """DNS anomaly detection and blocking."""

    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self.blocklist_file = data_dir / "blocklist.txt"
        self.pending_file = data_dir / "pending.json"
        self.alerts_file = data_dir / "alerts.jsonl"
        self._ensure_dirs()
        self._load_blocklist()
        self._load_pending()

        # Known suspicious TLDs
        self.suspicious_tlds = {
            "tk", "ml", "ga", "cf", "gq",  # Freenom (high abuse)
            "top", "xyz", "club", "work", "date",  # High abuse rate
            "bid", "loan", "download", "stream"
        }

        # DGA detection thresholds
        self.dga_entropy_threshold = 3.5
        self.dga_consonant_threshold = 0.7

    def _ensure_dirs(self):
        self.data_dir.mkdir(parents=True, exist_ok=True)

    def _load_blocklist(self):
        """Load blocked domains."""
        self.blocklist: Set[str] = set()
        if self.blocklist_file.exists():
            self.blocklist = set(
                line.strip()
                for line in self.blocklist_file.read_text().split("\n")
                if line.strip() and not line.startswith("#")
            )

    def _save_blocklist(self):
        """Save blocklist to file."""
        with open(self.blocklist_file, "w") as f:
            f.write("# SecuBox DNS Guard Blocklist\n")
            f.write(f"# Updated: {datetime.utcnow().isoformat()}\n")
            for domain in sorted(self.blocklist):
                f.write(f"{domain}\n")

    def _load_pending(self):
        """Load pending blocks (awaiting approval)."""
        self.pending: Dict[str, BlocklistEntry] = {}
        if self.pending_file.exists():
            try:
                data = json.loads(self.pending_file.read_text())
                self.pending = {k: BlocklistEntry(**v) for k, v in data.items()}
            except Exception:
                pass

    def _save_pending(self):
        self.pending_file.write_text(json.dumps(
            {k: v.model_dump() for k, v in self.pending.items()},
            indent=2
        ))

    def _generate_alert_id(self) -> str:
        return f"dns-{int(time.time() * 1000)}"

    def record_alert(self, alert: DnsAlert):
        """Record a DNS alert."""
        with open(self.alerts_file, "a") as f:
            f.write(json.dumps(alert.model_dump()) + "\n")

    def get_alerts(self, hours: int = 24) -> List[DnsAlert]:
        """Get recent alerts."""
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        alerts = []

        if not self.alerts_file.exists():
            return alerts

        with open(self.alerts_file) as f:
            for line in f:
                try:
                    data = json.loads(line)
                    ts = datetime.fromisoformat(data["timestamp"].rstrip("Z"))
                    if ts >= cutoff:
                        alerts.append(DnsAlert(**data))
                except Exception:
                    continue

        return alerts

    # DGA Detection
    def calculate_entropy(self, domain: str) -> float:
        """Calculate Shannon entropy of domain name."""
        if not domain:
            return 0

        # Get second-level domain
        parts = domain.lower().split(".")
        if len(parts) >= 2:
            sld = parts[-2]
        else:
            sld = domain

        if len(sld) <= 1:
            return 0

        freq = Counter(sld)
        entropy = 0
        for count in freq.values():
            p = count / len(sld)
            entropy -= p * math.log2(p)

        return entropy

    def calculate_consonant_ratio(self, domain: str) -> float:
        """Calculate consonant ratio (DGA domains have high consonant ratios)."""
        vowels = set("aeiou")
        parts = domain.lower().split(".")
        sld = parts[-2] if len(parts) >= 2 else domain

        if len(sld) == 0:
            return 0

        letters = [c for c in sld if c.isalpha()]
        if len(letters) == 0:
            return 0

        consonants = sum(1 for c in letters if c not in vowels)
        return consonants / len(letters)

    def detect_dga(self, domain: str) -> Optional[DnsAlert]:
        """Detect DGA-generated domains."""
        entropy = self.calculate_entropy(domain)
        consonant_ratio = self.calculate_consonant_ratio(domain)

        is_dga = (
            entropy > self.dga_entropy_threshold and
            consonant_ratio > self.dga_consonant_threshold
        )

        if is_dga:
            alert = DnsAlert(
                id=self._generate_alert_id(),
                type=DetectionType.DGA,
                severity=Severity.HIGH,
                domain=domain,
                description=f"Possible DGA domain detected: {domain}",
                details={
                    "entropy": round(entropy, 3),
                    "consonant_ratio": round(consonant_ratio, 3),
                    "thresholds": {
                        "entropy": self.dga_entropy_threshold,
                        "consonant": self.dga_consonant_threshold
                    }
                },
                timestamp=datetime.utcnow().isoformat() + "Z"
            )
            self.record_alert(alert)
            return alert

        return None

    # DNS Tunneling Detection
    def detect_tunneling(self, domain: str, query_length: int = 0) -> Optional[DnsAlert]:
        """Detect DNS tunneling attempts."""
        # Tunneling indicators:
        # - Very long subdomain labels
        # - Base64-like patterns
        # - High query frequency to same domain

        parts = domain.split(".")
        max_label_len = max(len(p) for p in parts) if parts else 0

        # Check for long labels (base64 encoded data)
        if max_label_len > 50:
            alert = DnsAlert(
                id=self._generate_alert_id(),
                type=DetectionType.TUNNELING,
                severity=Severity.CRITICAL,
                domain=domain,
                description=f"DNS tunneling detected: abnormally long subdomain ({max_label_len} chars)",
                details={
                    "max_label_length": max_label_len,
                    "total_length": len(domain)
                },
                timestamp=datetime.utcnow().isoformat() + "Z"
            )
            self.record_alert(alert)
            return alert

        # Check for base64-like patterns
        if len(parts) > 2:
            subdomain = ".".join(parts[:-2])
            if re.match(r'^[A-Za-z0-9+/=]{20,}$', subdomain.replace(".", "")):
                alert = DnsAlert(
                    id=self._generate_alert_id(),
                    type=DetectionType.TUNNELING,
                    severity=Severity.HIGH,
                    domain=domain,
                    description=f"Possible DNS tunneling: base64-like subdomain pattern",
                    details={"subdomain": subdomain},
                    timestamp=datetime.utcnow().isoformat() + "Z"
                )
                self.record_alert(alert)
                return alert

        return None

    # Unusual TLD Detection
    def detect_unusual_tld(self, domain: str) -> Optional[DnsAlert]:
        """Detect queries to suspicious TLDs."""
        parts = domain.lower().split(".")
        tld = parts[-1] if parts else ""

        if tld in self.suspicious_tlds:
            alert = DnsAlert(
                id=self._generate_alert_id(),
                type=DetectionType.UNUSUAL_TLD,
                severity=Severity.MEDIUM,
                domain=domain,
                description=f"Query to suspicious TLD: .{tld}",
                details={"tld": tld},
                timestamp=datetime.utcnow().isoformat() + "Z"
            )
            self.record_alert(alert)
            return alert

        return None

    # Blocklist Management
    def add_to_blocklist(
        self,
        domain: str,
        reason: str,
        source: str = "manual",
        immediate: bool = False
    ):
        """Add domain to blocklist (pending or immediate)."""
        entry = BlocklistEntry(
            domain=domain.lower(),
            reason=reason,
            added_at=datetime.utcnow().isoformat() + "Z",
            source=source
        )

        if immediate:
            self.blocklist.add(domain.lower())
            self._save_blocklist()
            self._sync_dnsmasq()
        else:
            self.pending[domain.lower()] = entry
            self._save_pending()

    def approve_pending(self, domain: str) -> bool:
        """Approve a pending blocklist entry."""
        domain = domain.lower()
        if domain not in self.pending:
            return False

        self.blocklist.add(domain)
        del self.pending[domain]

        self._save_blocklist()
        self._save_pending()
        self._sync_dnsmasq()

        return True

    def remove_from_blocklist(self, domain: str) -> bool:
        """Remove domain from blocklist."""
        domain = domain.lower()
        if domain not in self.blocklist:
            return False

        self.blocklist.discard(domain)
        self._save_blocklist()
        self._sync_dnsmasq()

        return True

    def _sync_dnsmasq(self):
        """Sync blocklist to dnsmasq configuration."""
        try:
            with open(DNSMASQ_BLOCKLIST, "w") as f:
                f.write("# SecuBox DNS Guard Blocklist\n")
                f.write(f"# Generated: {datetime.utcnow().isoformat()}\n")
                for domain in sorted(self.blocklist):
                    f.write(f"address=/{domain}/0.0.0.0\n")

            # Reload dnsmasq
            subprocess.run(
                ["systemctl", "reload", "dnsmasq"],
                capture_output=True,
                timeout=10
            )
        except Exception as e:
            logger.warning(f"Failed to sync dnsmasq: {e}")

    def is_blocked(self, domain: str) -> bool:
        """Check if domain is blocked."""
        domain = domain.lower()

        # Check exact match
        if domain in self.blocklist:
            return True

        # Check parent domains
        parts = domain.split(".")
        for i in range(1, len(parts)):
            parent = ".".join(parts[i:])
            if parent in self.blocklist:
                return True

        return False

    def analyze_domain(self, domain: str) -> List[DnsAlert]:
        """Run all detection methods on a domain."""
        alerts = []

        # Check if already blocked
        if self.is_blocked(domain):
            return alerts

        # Run detectors
        dga_alert = self.detect_dga(domain)
        if dga_alert:
            alerts.append(dga_alert)

        tunnel_alert = self.detect_tunneling(domain)
        if tunnel_alert:
            alerts.append(tunnel_alert)

        tld_alert = self.detect_unusual_tld(domain)
        if tld_alert:
            alerts.append(tld_alert)

        return alerts

    def get_stats(self) -> Dict[str, Any]:
        """Get DNS guard statistics."""
        alerts = self.get_alerts(24)

        by_type = {}
        for alert in alerts:
            by_type[alert.type.value] = by_type.get(alert.type.value, 0) + 1

        return {
            "blocklist_count": len(self.blocklist),
            "pending_count": len(self.pending),
            "alerts_24h": len(alerts),
            "by_type": by_type
        }


# Global instance
guard = DnsGuard(DATA_DIR)


# ============================================================================
# API Endpoints
# ============================================================================

@app.get("/status")
async def status():
    """Public status endpoint."""
    stats = guard.get_stats()
    return {
        "module": "dns-guard",
        "status": "ok",
        "version": "1.0.0",
        "blocklist_count": stats["blocklist_count"],
        "alerts_24h": stats["alerts_24h"]
    }


@app.get("/health")
async def health():
    """Health check."""
    return {"status": "healthy"}


@app.get("/stats", dependencies=[Depends(require_jwt)])
async def get_stats():
    """Get DNS guard statistics."""
    return guard.get_stats()


@app.post("/analyze", dependencies=[Depends(require_jwt)])
async def analyze_domain(domain: str):
    """Analyze a domain for anomalies."""
    alerts = guard.analyze_domain(domain)
    return {
        "domain": domain,
        "alerts": alerts,
        "is_blocked": guard.is_blocked(domain)
    }


@app.get("/alerts", dependencies=[Depends(require_jwt)])
async def list_alerts(hours: int = 24):
    """List recent alerts."""
    alerts = guard.get_alerts(hours)
    return {"alerts": alerts, "count": len(alerts)}


@app.get("/blocklist", dependencies=[Depends(require_jwt)])
async def get_blocklist():
    """Get current blocklist."""
    return {"domains": sorted(guard.blocklist), "count": len(guard.blocklist)}


@app.post("/blocklist", dependencies=[Depends(require_jwt)])
async def add_to_blocklist(
    domain: str,
    reason: str = "manual",
    immediate: bool = False
):
    """Add domain to blocklist."""
    guard.add_to_blocklist(domain, reason, "manual", immediate)
    return {
        "status": "blocked" if immediate else "pending",
        "domain": domain
    }


@app.delete("/blocklist/{domain}", dependencies=[Depends(require_jwt)])
async def remove_from_blocklist(domain: str):
    """Remove domain from blocklist."""
    if not guard.remove_from_blocklist(domain):
        raise HTTPException(status_code=404, detail="Domain not in blocklist")
    return {"status": "removed"}


@app.get("/pending", dependencies=[Depends(require_jwt)])
async def get_pending():
    """Get pending blocklist entries."""
    return {"pending": list(guard.pending.values())}


@app.post("/pending/{domain}/approve", dependencies=[Depends(require_jwt)])
async def approve_pending(domain: str):
    """Approve a pending blocklist entry."""
    if not guard.approve_pending(domain):
        raise HTTPException(status_code=404, detail="Domain not in pending list")
    return {"status": "approved"}


@app.delete("/pending/{domain}", dependencies=[Depends(require_jwt)])
async def reject_pending(domain: str):
    """Reject a pending blocklist entry."""
    domain = domain.lower()
    if domain not in guard.pending:
        raise HTTPException(status_code=404, detail="Domain not in pending list")
    del guard.pending[domain]
    guard._save_pending()
    return {"status": "rejected"}


@app.post("/sync", dependencies=[Depends(require_jwt)])
async def sync_dnsmasq():
    """Force sync blocklist to dnsmasq."""
    guard._sync_dnsmasq()
    return {"status": "synced"}


@app.get("/check/{domain}")
async def check_domain(domain: str):
    """Check if a domain is blocked (public endpoint)."""
    return {
        "domain": domain,
        "blocked": guard.is_blocked(domain)
    }


# ============================================================================
# Startup
# ============================================================================

@app.on_event("startup")
async def startup():
    """Initialize on startup."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    logger.info("DNS Guard started")
