"""SecuBox Threats API - Unified Security Threats Dashboard

Features:
- Unified threat dashboard
- Aggregated alerts from all security modules
- Threat intelligence feeds
- IOC management (IPs, domains, hashes)
- Threat timeline
- Risk scoring
- Incident tracking
- Report generation
- Stats caching with TTL
- Background monitoring
"""

import asyncio
import subprocess
import json
import hashlib
import time
import threading
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from secubox_core.auth import require_jwt
from secubox_core.config import get_config

app = FastAPI(title="SecuBox Threats", version="1.0.0")

# Data directories
DATA_DIR = Path("/var/lib/secubox/threats")
THREATS_FILE = DATA_DIR / "threats.json"
ALERTS_FILE = DATA_DIR / "alerts.json"
IOCS_FILE = DATA_DIR / "iocs.json"
FEEDS_FILE = DATA_DIR / "feeds.json"
INCIDENTS_FILE = DATA_DIR / "incidents.json"
REPORTS_FILE = DATA_DIR / "reports.json"
SCORES_FILE = DATA_DIR / "scores.json"
CONFIG_FILE = Path("/etc/secubox/threats.toml")
CACHE_FILE = DATA_DIR / "cache.json"

# Ensure directories exist
DATA_DIR.mkdir(parents=True, exist_ok=True)


class StatsCache:
    """Thread-safe stats cache with TTL."""
    def __init__(self, ttl_seconds: int = 30):
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

    def invalidate(self, key: str = None):
        with self._lock:
            if key:
                self._cache.pop(key, None)
                self._timestamps.pop(key, None)
            else:
                self._cache.clear()
                self._timestamps.clear()


# Global cache
stats_cache = StatsCache(ttl_seconds=30)


# ══════════════════════════════════════════════════════════════
# PYDANTIC MODELS
# ══════════════════════════════════════════════════════════════

class ThreatModel(BaseModel):
    name: str
    description: str
    severity: str = "medium"  # low, medium, high, critical
    source: str = "manual"
    category: str = "unknown"  # malware, phishing, intrusion, dos, other
    indicators: List[str] = []
    ttps: List[str] = []  # MITRE ATT&CK TTPs


class ThreatAcknowledge(BaseModel):
    analyst: str
    notes: Optional[str] = None


class ThreatResolve(BaseModel):
    analyst: str
    resolution: str
    notes: Optional[str] = None


class IOCModel(BaseModel):
    value: str
    type: str  # ip, domain, hash, url, email
    threat_type: str = "unknown"  # malware, phishing, c2, scanner, spam
    source: str = "manual"
    confidence: int = Field(default=50, ge=0, le=100)
    tags: List[str] = []
    expiry: Optional[str] = None  # ISO datetime


class FeedSubscribe(BaseModel):
    name: str
    url: str
    type: str = "stix"  # stix, csv, json, misp
    enabled: bool = True
    refresh_interval: int = 3600  # seconds


class IncidentModel(BaseModel):
    title: str
    description: str
    severity: str = "medium"
    status: str = "open"  # open, investigating, contained, resolved, closed
    assignee: Optional[str] = None
    threat_ids: List[str] = []
    ioc_ids: List[str] = []


class ReportGenerate(BaseModel):
    type: str = "summary"  # summary, detailed, executive, ioc_export
    period: str = "24h"  # 24h, 7d, 30d, custom
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    include_resolved: bool = False


class ConfigModel(BaseModel):
    auto_acknowledge_low: bool = False
    alert_retention_days: int = 30
    threat_retention_days: int = 90
    feed_refresh_enabled: bool = True
    risk_score_weights: Dict[str, float] = {
        "severity_critical": 10.0,
        "severity_high": 7.0,
        "severity_medium": 4.0,
        "severity_low": 1.0
    }


# ══════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ══════════════════════════════════════════════════════════════

def _load_json(path: Path) -> list:
    if path.exists():
        try:
            with open(path, 'r') as f:
                return json.load(f)
        except Exception:
            pass
    return []


def _save_json(path: Path, data):
    try:
        with open(path, 'w') as f:
            json.dump(data, f, indent=2, default=str)
    except Exception:
        pass


def _load_config() -> dict:
    default = {
        "auto_acknowledge_low": False,
        "alert_retention_days": 30,
        "threat_retention_days": 90,
        "feed_refresh_enabled": True,
        "risk_score_weights": {
            "severity_critical": 10.0,
            "severity_high": 7.0,
            "severity_medium": 4.0,
            "severity_low": 1.0
        }
    }
    if CONFIG_FILE.exists():
        try:
            import tomllib
            with open(CONFIG_FILE, 'rb') as f:
                return {**default, **tomllib.load(f)}
        except Exception:
            pass
    return default


def _generate_id() -> str:
    return hashlib.sha256(f"{time.time()}".encode()).hexdigest()[:12]


# ══════════════════════════════════════════════════════════════
# ALERT AGGREGATION
# ══════════════════════════════════════════════════════════════

def _fetch_crowdsec_alerts() -> List[Dict]:
    """Fetch alerts from CrowdSec."""
    alerts = []
    try:
        result = subprocess.run(
            ["cscli", "alerts", "list", "-o", "json"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0 and result.stdout:
            cs_alerts = json.loads(result.stdout)
            for a in cs_alerts[:50]:
                alerts.append({
                    "id": f"cs-{a.get('id', '')}",
                    "source": "crowdsec",
                    "severity": "high" if a.get("scenario", "").startswith("crowdsecurity/") else "medium",
                    "message": a.get("scenario", "Unknown"),
                    "value": a.get("source", {}).get("ip", ""),
                    "timestamp": a.get("created_at", ""),
                    "raw": a
                })
    except Exception:
        pass
    return alerts


def _fetch_suricata_alerts() -> List[Dict]:
    """Fetch alerts from Suricata eve.json log."""
    alerts = []
    eve_log = Path("/var/log/suricata/eve.json")
    if eve_log.exists():
        try:
            # Read last 100 lines
            result = subprocess.run(
                ["tail", "-n", "100", str(eve_log)],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                for line in result.stdout.strip().split("\n"):
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                        if event.get("event_type") == "alert":
                            alert_data = event.get("alert", {})
                            severity_map = {1: "critical", 2: "high", 3: "medium"}
                            alerts.append({
                                "id": f"sur-{event.get('flow_id', _generate_id())}",
                                "source": "suricata",
                                "severity": severity_map.get(alert_data.get("severity", 3), "low"),
                                "message": alert_data.get("signature", "Unknown"),
                                "value": event.get("src_ip", ""),
                                "timestamp": event.get("timestamp", ""),
                                "category": alert_data.get("category", ""),
                                "raw": event
                            })
                    except Exception:
                        continue
        except Exception:
            pass
    return alerts[-50:]


def _fetch_waf_alerts() -> List[Dict]:
    """Fetch alerts from HAProxy/mitmproxy WAF logs."""
    alerts = []
    waf_log = Path("/var/log/secubox/waf.json")
    if waf_log.exists():
        try:
            result = subprocess.run(
                ["tail", "-n", "50", str(waf_log)],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                for line in result.stdout.strip().split("\n"):
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                        alerts.append({
                            "id": f"waf-{event.get('id', _generate_id())}",
                            "source": "waf",
                            "severity": event.get("severity", "medium"),
                            "message": event.get("rule", event.get("message", "Unknown")),
                            "value": event.get("client_ip", ""),
                            "timestamp": event.get("timestamp", ""),
                            "raw": event
                        })
                    except Exception:
                        continue
        except Exception:
            pass
    return alerts


# ══════════════════════════════════════════════════════════════
# HEALTH & STATUS
# ══════════════════════════════════════════════════════════════

@app.get("/health")
async def health():
    return {"status": "ok", "module": "threats"}


@app.get("/status")
async def status():
    threats = _load_json(THREATS_FILE)
    alerts = _load_json(ALERTS_FILE)
    iocs = _load_json(IOCS_FILE)
    incidents = _load_json(INCIDENTS_FILE)

    active_threats = sum(1 for t in threats if t.get('status') != 'resolved')
    critical_threats = sum(1 for t in threats if t.get('severity') == 'critical' and t.get('status') != 'resolved')
    unacked_alerts = sum(1 for a in alerts if not a.get('acknowledged'))
    open_incidents = sum(1 for i in incidents if i.get('status') not in ['resolved', 'closed'])

    return {
        "module": "threats",
        "status": "ok",
        "version": "1.0.0",
        "active_threats": active_threats,
        "critical_threats": critical_threats,
        "unacknowledged_alerts": unacked_alerts,
        "open_incidents": open_incidents,
        "total_iocs": len(iocs)
    }


# ══════════════════════════════════════════════════════════════
# CONFIGURATION
# ══════════════════════════════════════════════════════════════

@app.get("/config", dependencies=[Depends(require_jwt)])
async def get_config_endpoint():
    return _load_config()


@app.post("/config", dependencies=[Depends(require_jwt)])
async def set_config(config: ConfigModel):
    try:
        import tomli_w
        CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(CONFIG_FILE, 'wb') as f:
            tomli_w.dump(config.dict(), f)
        stats_cache.invalidate()
        return {"success": True, "config": config.dict()}
    except ImportError:
        # Fallback to JSON if tomli_w not available
        config_path = DATA_DIR / "config.json"
        _save_json(config_path, config.dict())
        return {"success": True, "config": config.dict()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ══════════════════════════════════════════════════════════════
# THREATS
# ══════════════════════════════════════════════════════════════

@app.get("/threats", dependencies=[Depends(require_jwt)])
async def list_threats(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    category: Optional[str] = None,
    limit: int = Query(100, ge=1, le=500)
):
    threats = _load_json(THREATS_FILE)

    if status:
        threats = [t for t in threats if t.get('status') == status]
    if severity:
        threats = [t for t in threats if t.get('severity') == severity]
    if category:
        threats = [t for t in threats if t.get('category') == category]

    threats.sort(key=lambda x: x.get('created_at', ''), reverse=True)

    return {
        "threats": threats[:limit],
        "total": len(threats),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@app.get("/threat/{threat_id}", dependencies=[Depends(require_jwt)])
async def get_threat(threat_id: str):
    threats = _load_json(THREATS_FILE)
    for t in threats:
        if t.get('id') == threat_id:
            # Enrich with related IOCs
            iocs = _load_json(IOCS_FILE)
            related_iocs = [i for i in iocs if i.get('id') in t.get('ioc_ids', [])]
            return {**t, "related_iocs": related_iocs}
    raise HTTPException(status_code=404, detail="Threat not found")


@app.post("/threats", dependencies=[Depends(require_jwt)])
async def create_threat(threat: ThreatModel):
    threats = _load_json(THREATS_FILE)
    new_threat = {
        "id": _generate_id(),
        "name": threat.name,
        "description": threat.description,
        "severity": threat.severity,
        "source": threat.source,
        "category": threat.category,
        "indicators": threat.indicators,
        "ttps": threat.ttps,
        "status": "active",
        "acknowledged": False,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "ioc_ids": []
    }
    threats.append(new_threat)
    _save_json(THREATS_FILE, threats)
    stats_cache.invalidate()
    return {"success": True, "threat": new_threat}


@app.post("/threat/{threat_id}/acknowledge", dependencies=[Depends(require_jwt)])
async def acknowledge_threat(threat_id: str, ack: ThreatAcknowledge):
    threats = _load_json(THREATS_FILE)
    for i, t in enumerate(threats):
        if t.get('id') == threat_id:
            threats[i]["acknowledged"] = True
            threats[i]["acknowledged_by"] = ack.analyst
            threats[i]["acknowledged_at"] = datetime.now(timezone.utc).isoformat()
            threats[i]["ack_notes"] = ack.notes
            threats[i]["updated_at"] = datetime.now(timezone.utc).isoformat()
            _save_json(THREATS_FILE, threats)
            stats_cache.invalidate()
            return {"success": True, "threat": threats[i]}
    raise HTTPException(status_code=404, detail="Threat not found")


@app.post("/threat/{threat_id}/resolve", dependencies=[Depends(require_jwt)])
async def resolve_threat(threat_id: str, resolve: ThreatResolve):
    threats = _load_json(THREATS_FILE)
    for i, t in enumerate(threats):
        if t.get('id') == threat_id:
            threats[i]["status"] = "resolved"
            threats[i]["resolved_by"] = resolve.analyst
            threats[i]["resolved_at"] = datetime.now(timezone.utc).isoformat()
            threats[i]["resolution"] = resolve.resolution
            threats[i]["resolve_notes"] = resolve.notes
            threats[i]["updated_at"] = datetime.now(timezone.utc).isoformat()
            _save_json(THREATS_FILE, threats)
            stats_cache.invalidate()
            return {"success": True, "threat": threats[i]}
    raise HTTPException(status_code=404, detail="Threat not found")


# ══════════════════════════════════════════════════════════════
# ALERTS (Aggregated)
# ══════════════════════════════════════════════════════════════

@app.get("/alerts", dependencies=[Depends(require_jwt)])
async def list_alerts(
    source: Optional[str] = None,
    severity: Optional[str] = None,
    acknowledged: Optional[bool] = None,
    limit: int = Query(100, ge=1, le=500)
):
    # Load stored alerts
    stored_alerts = _load_json(ALERTS_FILE)

    # Fetch fresh alerts from sources
    fresh_alerts = []
    fresh_alerts.extend(_fetch_crowdsec_alerts())
    fresh_alerts.extend(_fetch_suricata_alerts())
    fresh_alerts.extend(_fetch_waf_alerts())

    # Merge fresh alerts (avoid duplicates by ID)
    existing_ids = {a.get('id') for a in stored_alerts}
    for fa in fresh_alerts:
        if fa.get('id') not in existing_ids:
            fa["acknowledged"] = False
            fa["stored_at"] = datetime.now(timezone.utc).isoformat()
            stored_alerts.append(fa)
            existing_ids.add(fa.get('id'))

    # Save merged alerts
    _save_json(ALERTS_FILE, stored_alerts[-1000:])  # Keep last 1000

    # Apply filters
    alerts = stored_alerts
    if source:
        alerts = [a for a in alerts if a.get('source') == source]
    if severity:
        alerts = [a for a in alerts if a.get('severity') == severity]
    if acknowledged is not None:
        alerts = [a for a in alerts if a.get('acknowledged') == acknowledged]

    alerts.sort(key=lambda x: x.get('timestamp', ''), reverse=True)

    return {
        "alerts": alerts[:limit],
        "total": len(alerts),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@app.get("/alerts/sources", dependencies=[Depends(require_jwt)])
async def get_alert_sources():
    """Get available alert sources and their status."""
    sources = []

    # CrowdSec
    try:
        result = subprocess.run(["systemctl", "is-active", "crowdsec"], capture_output=True, text=True, timeout=5)
        cs_active = result.stdout.strip() == "active"
    except Exception:
        cs_active = False
    sources.append({
        "id": "crowdsec",
        "name": "CrowdSec",
        "active": cs_active,
        "description": "Collaborative security engine"
    })

    # Suricata
    try:
        result = subprocess.run(["systemctl", "is-active", "suricata"], capture_output=True, text=True, timeout=5)
        sur_active = result.stdout.strip() == "active"
    except Exception:
        sur_active = False
    sources.append({
        "id": "suricata",
        "name": "Suricata IDS",
        "active": sur_active,
        "description": "Network intrusion detection"
    })

    # WAF
    waf_log = Path("/var/log/secubox/waf.json")
    sources.append({
        "id": "waf",
        "name": "WAF (HAProxy/mitmproxy)",
        "active": waf_log.exists(),
        "description": "Web application firewall"
    })

    return {"sources": sources}


# ══════════════════════════════════════════════════════════════
# IOCs (Indicators of Compromise)
# ══════════════════════════════════════════════════════════════

@app.get("/iocs", dependencies=[Depends(require_jwt)])
async def list_iocs(
    type: Optional[str] = None,
    threat_type: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = Query(100, ge=1, le=500)
):
    iocs = _load_json(IOCS_FILE)

    if type:
        iocs = [i for i in iocs if i.get('type') == type]
    if threat_type:
        iocs = [i for i in iocs if i.get('threat_type') == threat_type]
    if search:
        search_lower = search.lower()
        iocs = [i for i in iocs if search_lower in i.get('value', '').lower()]

    iocs.sort(key=lambda x: x.get('added_at', ''), reverse=True)

    return {
        "iocs": iocs[:limit],
        "total": len(iocs),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@app.post("/ioc", dependencies=[Depends(require_jwt)])
async def add_ioc(ioc: IOCModel):
    iocs = _load_json(IOCS_FILE)

    # Check for duplicate
    existing = [i for i in iocs if i.get('value') == ioc.value and i.get('type') == ioc.type]
    if existing:
        raise HTTPException(status_code=409, detail="IOC already exists")

    new_ioc = {
        "id": _generate_id(),
        "value": ioc.value,
        "type": ioc.type,
        "threat_type": ioc.threat_type,
        "source": ioc.source,
        "confidence": ioc.confidence,
        "tags": ioc.tags,
        "expiry": ioc.expiry,
        "added_at": datetime.now(timezone.utc).isoformat(),
        "hits": 0
    }
    iocs.append(new_ioc)
    _save_json(IOCS_FILE, iocs)
    stats_cache.invalidate()
    return {"success": True, "ioc": new_ioc}


@app.delete("/ioc/{ioc_id}", dependencies=[Depends(require_jwt)])
async def delete_ioc(ioc_id: str):
    iocs = _load_json(IOCS_FILE)
    original_len = len(iocs)
    iocs = [i for i in iocs if i.get('id') != ioc_id]
    if len(iocs) == original_len:
        raise HTTPException(status_code=404, detail="IOC not found")
    _save_json(IOCS_FILE, iocs)
    stats_cache.invalidate()
    return {"success": True}


# ══════════════════════════════════════════════════════════════
# THREAT FEEDS
# ══════════════════════════════════════════════════════════════

@app.get("/feeds", dependencies=[Depends(require_jwt)])
async def list_feeds():
    feeds = _load_json(FEEDS_FILE)
    return {"feeds": feeds, "total": len(feeds)}


@app.post("/feed/subscribe", dependencies=[Depends(require_jwt)])
async def subscribe_feed(feed: FeedSubscribe):
    feeds = _load_json(FEEDS_FILE)

    # Check for duplicate URL
    existing = [f for f in feeds if f.get('url') == feed.url]
    if existing:
        raise HTTPException(status_code=409, detail="Feed already subscribed")

    new_feed = {
        "id": _generate_id(),
        "name": feed.name,
        "url": feed.url,
        "type": feed.type,
        "enabled": feed.enabled,
        "refresh_interval": feed.refresh_interval,
        "subscribed_at": datetime.now(timezone.utc).isoformat(),
        "last_refresh": None,
        "ioc_count": 0,
        "status": "pending"
    }
    feeds.append(new_feed)
    _save_json(FEEDS_FILE, feeds)
    return {"success": True, "feed": new_feed}


@app.delete("/feed/{feed_id}", dependencies=[Depends(require_jwt)])
async def unsubscribe_feed(feed_id: str):
    feeds = _load_json(FEEDS_FILE)
    original_len = len(feeds)
    feeds = [f for f in feeds if f.get('id') != feed_id]
    if len(feeds) == original_len:
        raise HTTPException(status_code=404, detail="Feed not found")
    _save_json(FEEDS_FILE, feeds)
    return {"success": True}


# ══════════════════════════════════════════════════════════════
# TIMELINE
# ══════════════════════════════════════════════════════════════

@app.get("/timeline", dependencies=[Depends(require_jwt)])
async def get_timeline(
    hours: int = Query(24, ge=1, le=168),
    limit: int = Query(100, ge=1, le=500)
):
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    cutoff_iso = cutoff.isoformat()

    events = []

    # Add threats
    threats = _load_json(THREATS_FILE)
    for t in threats:
        if t.get('created_at', '') > cutoff_iso:
            events.append({
                "type": "threat",
                "id": t.get('id'),
                "timestamp": t.get('created_at'),
                "severity": t.get('severity'),
                "title": t.get('name'),
                "description": t.get('description', '')[:100]
            })

    # Add alerts
    alerts = _load_json(ALERTS_FILE)
    for a in alerts:
        if a.get('timestamp', '') > cutoff_iso:
            events.append({
                "type": "alert",
                "id": a.get('id'),
                "timestamp": a.get('timestamp'),
                "severity": a.get('severity'),
                "title": f"[{a.get('source', 'unknown')}] {a.get('message', '')}",
                "description": a.get('value', '')
            })

    # Add incidents
    incidents = _load_json(INCIDENTS_FILE)
    for i in incidents:
        if i.get('created_at', '') > cutoff_iso:
            events.append({
                "type": "incident",
                "id": i.get('id'),
                "timestamp": i.get('created_at'),
                "severity": i.get('severity'),
                "title": i.get('title'),
                "description": i.get('description', '')[:100]
            })

    # Sort by timestamp
    events.sort(key=lambda x: x.get('timestamp', ''), reverse=True)

    return {
        "events": events[:limit],
        "total": len(events),
        "period_hours": hours,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


# ══════════════════════════════════════════════════════════════
# RISK SCORES
# ══════════════════════════════════════════════════════════════

@app.get("/scores", dependencies=[Depends(require_jwt)])
async def get_risk_scores():
    cached = stats_cache.get("scores")
    if cached:
        return {**cached, "cached": True}

    config = _load_config()
    weights = config.get("risk_score_weights", {})

    threats = _load_json(THREATS_FILE)
    alerts = _load_json(ALERTS_FILE)
    incidents = _load_json(INCIDENTS_FILE)

    # Calculate overall risk score
    threat_score = 0
    for t in threats:
        if t.get('status') != 'resolved':
            sev = t.get('severity', 'medium')
            threat_score += weights.get(f"severity_{sev}", 4.0)

    alert_score = 0
    for a in alerts[-100:]:  # Last 100 alerts
        if not a.get('acknowledged'):
            sev = a.get('severity', 'medium')
            alert_score += weights.get(f"severity_{sev}", 4.0) * 0.5

    incident_score = 0
    for i in incidents:
        if i.get('status') not in ['resolved', 'closed']:
            sev = i.get('severity', 'medium')
            incident_score += weights.get(f"severity_{sev}", 4.0) * 2

    total_score = threat_score + alert_score + incident_score
    max_score = 100.0
    normalized_score = min(total_score / max_score * 100, 100)

    # Risk level
    if normalized_score >= 80:
        risk_level = "critical"
    elif normalized_score >= 60:
        risk_level = "high"
    elif normalized_score >= 30:
        risk_level = "medium"
    else:
        risk_level = "low"

    result = {
        "overall_score": round(normalized_score, 1),
        "risk_level": risk_level,
        "components": {
            "threats": round(threat_score, 1),
            "alerts": round(alert_score, 1),
            "incidents": round(incident_score, 1)
        },
        "active_threats": sum(1 for t in threats if t.get('status') != 'resolved'),
        "unacked_alerts": sum(1 for a in alerts if not a.get('acknowledged')),
        "open_incidents": sum(1 for i in incidents if i.get('status') not in ['resolved', 'closed']),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

    stats_cache.set("scores", result)
    return result


# ══════════════════════════════════════════════════════════════
# INCIDENTS
# ══════════════════════════════════════════════════════════════

@app.get("/incidents", dependencies=[Depends(require_jwt)])
async def list_incidents(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = Query(50, ge=1, le=200)
):
    incidents = _load_json(INCIDENTS_FILE)

    if status:
        incidents = [i for i in incidents if i.get('status') == status]
    if severity:
        incidents = [i for i in incidents if i.get('severity') == severity]

    incidents.sort(key=lambda x: x.get('created_at', ''), reverse=True)

    return {
        "incidents": incidents[:limit],
        "total": len(incidents),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@app.post("/incident", dependencies=[Depends(require_jwt)])
async def create_incident(incident: IncidentModel):
    incidents = _load_json(INCIDENTS_FILE)
    new_incident = {
        "id": _generate_id(),
        "title": incident.title,
        "description": incident.description,
        "severity": incident.severity,
        "status": incident.status,
        "assignee": incident.assignee,
        "threat_ids": incident.threat_ids,
        "ioc_ids": incident.ioc_ids,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "timeline": [{
            "action": "created",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }]
    }
    incidents.append(new_incident)
    _save_json(INCIDENTS_FILE, incidents)
    stats_cache.invalidate()
    return {"success": True, "incident": new_incident}


@app.put("/incident/{incident_id}", dependencies=[Depends(require_jwt)])
async def update_incident(incident_id: str, incident: IncidentModel):
    incidents = _load_json(INCIDENTS_FILE)
    for i, inc in enumerate(incidents):
        if inc.get('id') == incident_id:
            old_status = inc.get('status')
            incidents[i].update({
                "title": incident.title,
                "description": incident.description,
                "severity": incident.severity,
                "status": incident.status,
                "assignee": incident.assignee,
                "threat_ids": incident.threat_ids,
                "ioc_ids": incident.ioc_ids,
                "updated_at": datetime.now(timezone.utc).isoformat()
            })
            if old_status != incident.status:
                incidents[i].setdefault("timeline", []).append({
                    "action": f"status_changed_to_{incident.status}",
                    "timestamp": datetime.now(timezone.utc).isoformat()
                })
            _save_json(INCIDENTS_FILE, incidents)
            stats_cache.invalidate()
            return {"success": True, "incident": incidents[i]}
    raise HTTPException(status_code=404, detail="Incident not found")


# ══════════════════════════════════════════════════════════════
# REPORTS
# ══════════════════════════════════════════════════════════════

@app.get("/reports", dependencies=[Depends(require_jwt)])
async def list_reports(limit: int = Query(20, ge=1, le=100)):
    reports = _load_json(REPORTS_FILE)
    reports.sort(key=lambda x: x.get('generated_at', ''), reverse=True)
    return {"reports": reports[:limit], "total": len(reports)}


@app.post("/report/generate", dependencies=[Depends(require_jwt)])
async def generate_report(params: ReportGenerate):
    # Determine time range
    now = datetime.now(timezone.utc)
    if params.period == "24h":
        start = now - timedelta(hours=24)
    elif params.period == "7d":
        start = now - timedelta(days=7)
    elif params.period == "30d":
        start = now - timedelta(days=30)
    else:
        if params.start_date:
            start = datetime.fromisoformat(params.start_date.replace('Z', '+00:00'))
        else:
            start = now - timedelta(hours=24)
        if params.end_date:
            now = datetime.fromisoformat(params.end_date.replace('Z', '+00:00'))

    start_iso = start.isoformat()
    end_iso = now.isoformat()

    # Gather data
    threats = _load_json(THREATS_FILE)
    alerts = _load_json(ALERTS_FILE)
    incidents = _load_json(INCIDENTS_FILE)
    iocs = _load_json(IOCS_FILE)

    # Filter by time range
    threats_in_range = [t for t in threats if t.get('created_at', '') >= start_iso]
    alerts_in_range = [a for a in alerts if a.get('timestamp', '') >= start_iso]
    incidents_in_range = [i for i in incidents if i.get('created_at', '') >= start_iso]

    if not params.include_resolved:
        threats_in_range = [t for t in threats_in_range if t.get('status') != 'resolved']
        incidents_in_range = [i for i in incidents_in_range if i.get('status') not in ['resolved', 'closed']]

    # Build report
    report_data = {
        "summary": {
            "period": params.period,
            "start": start_iso,
            "end": end_iso,
            "total_threats": len(threats_in_range),
            "critical_threats": sum(1 for t in threats_in_range if t.get('severity') == 'critical'),
            "total_alerts": len(alerts_in_range),
            "total_incidents": len(incidents_in_range),
            "total_iocs": len(iocs)
        },
        "threats_by_severity": {
            "critical": sum(1 for t in threats_in_range if t.get('severity') == 'critical'),
            "high": sum(1 for t in threats_in_range if t.get('severity') == 'high'),
            "medium": sum(1 for t in threats_in_range if t.get('severity') == 'medium'),
            "low": sum(1 for t in threats_in_range if t.get('severity') == 'low')
        },
        "alerts_by_source": {},
        "top_iocs": iocs[:10] if params.type == "ioc_export" else []
    }

    # Count alerts by source
    for a in alerts_in_range:
        source = a.get('source', 'unknown')
        report_data["alerts_by_source"][source] = report_data["alerts_by_source"].get(source, 0) + 1

    if params.type == "detailed":
        report_data["threats"] = threats_in_range[:50]
        report_data["incidents"] = incidents_in_range[:20]

    # Save report
    reports = _load_json(REPORTS_FILE)
    new_report = {
        "id": _generate_id(),
        "type": params.type,
        "period": params.period,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "data": report_data
    }
    reports.append(new_report)
    _save_json(REPORTS_FILE, reports[-100:])  # Keep last 100 reports

    return {"success": True, "report": new_report}


@app.get("/report/{report_id}", dependencies=[Depends(require_jwt)])
async def get_report(report_id: str):
    reports = _load_json(REPORTS_FILE)
    for r in reports:
        if r.get('id') == report_id:
            return r
    raise HTTPException(status_code=404, detail="Report not found")
