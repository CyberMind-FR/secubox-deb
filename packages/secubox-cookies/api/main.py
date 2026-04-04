"""
SecuBox-Deb :: Cookies
Cookie tracking, analysis, and privacy compliance monitoring
CyberMind — https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate
"""

from fastapi import FastAPI, Depends, HTTPException, Query
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from pathlib import Path
from datetime import datetime, timedelta
import subprocess
import json
import re
import hashlib
import asyncio

# Import shared auth
import sys
sys.path.insert(0, '/usr/lib/secubox/core')
try:
    from secubox_core.auth import require_jwt
except ImportError:
    async def require_jwt():
        return {"sub": "dev"}

app = FastAPI(title="SecuBox Cookies API", version="1.0.0")

# Configuration paths
CONFIG_FILE = Path("/etc/secubox/cookies.json")
DATA_DIR = Path("/var/lib/secubox/cookies")
CACHE_DIR = Path("/var/cache/secubox/cookies")
LOG_FILE = Path("/var/log/secubox/cookies.log")

# Default configuration
DEFAULT_CONFIG = {
    "enabled": True,
    "scan_interval": 300,
    "retention_days": 30,
    "block_trackers": True,
    "alert_on_suspicious": True,
    "gdpr_mode": True,
    "third_party_detection": True,
    "tracker_detection": True,
    "known_trackers": [
        {"pattern": ".*google-analytics\\.com.*", "name": "Google Analytics", "category": "analytics"},
        {"pattern": ".*facebook\\.com.*fbp.*", "name": "Facebook Pixel", "category": "advertising"},
        {"pattern": ".*doubleclick\\.net.*", "name": "DoubleClick", "category": "advertising"},
        {"pattern": ".*hotjar\\.com.*", "name": "Hotjar", "category": "analytics"},
        {"pattern": ".*mixpanel\\.com.*", "name": "Mixpanel", "category": "analytics"},
        {"pattern": ".*segment\\.com.*", "name": "Segment", "category": "analytics"},
        {"pattern": ".*hubspot\\.com.*", "name": "HubSpot", "category": "marketing"},
        {"pattern": ".*intercom\\.io.*", "name": "Intercom", "category": "marketing"},
        {"pattern": ".*criteo\\.com.*", "name": "Criteo", "category": "advertising"},
        {"pattern": ".*adroll\\.com.*", "name": "AdRoll", "category": "advertising"}
    ],
    "policies": [
        {
            "id": "default-gdpr",
            "name": "GDPR Default",
            "enabled": True,
            "block_third_party": False,
            "block_trackers": True,
            "require_consent": True,
            "max_cookie_age_days": 365
        }
    ]
}

# In-memory cache
_cache: Dict[str, Any] = {
    "cookies": {},
    "violations": [],
    "stats": {},
    "last_scan": None
}


# Models
class ConfigUpdate(BaseModel):
    enabled: Optional[bool] = None
    scan_interval: Optional[int] = None
    retention_days: Optional[int] = None
    block_trackers: Optional[bool] = None
    alert_on_suspicious: Optional[bool] = None
    gdpr_mode: Optional[bool] = None
    third_party_detection: Optional[bool] = None
    tracker_detection: Optional[bool] = None


class TrackerPattern(BaseModel):
    pattern: str
    name: str
    category: str = "unknown"


class CookiePolicy(BaseModel):
    name: str
    enabled: bool = True
    block_third_party: bool = False
    block_trackers: bool = True
    require_consent: bool = True
    max_cookie_age_days: int = 365
    domains: Optional[List[str]] = None


class ScanRequest(BaseModel):
    url: str
    depth: int = 1
    include_third_party: bool = True


# Helpers
def load_config() -> dict:
    """Load cookies configuration"""
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text())
        except:
            pass
    return DEFAULT_CONFIG.copy()


def save_config(config: dict):
    """Save cookies configuration"""
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(config, indent=2))


def load_cookies_db() -> dict:
    """Load tracked cookies database"""
    db_file = DATA_DIR / "cookies.json"
    if db_file.exists():
        try:
            return json.loads(db_file.read_text())
        except:
            pass
    return {"cookies": {}, "domains": {}, "trackers_found": []}


def save_cookies_db(db: dict):
    """Save cookies database"""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    db_file = DATA_DIR / "cookies.json"
    db_file.write_text(json.dumps(db, indent=2))


def load_violations() -> list:
    """Load policy violations"""
    violations_file = DATA_DIR / "violations.json"
    if violations_file.exists():
        try:
            return json.loads(violations_file.read_text())
        except:
            pass
    return []


def save_violations(violations: list):
    """Save violations"""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    violations_file = DATA_DIR / "violations.json"
    violations_file.write_text(json.dumps(violations, indent=2))


def log_event(event_type: str, data: dict):
    """Log an event"""
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "timestamp": datetime.now().isoformat(),
        "type": event_type,
        **data
    }
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")


def is_third_party(cookie_domain: str, page_domain: str) -> bool:
    """Check if cookie is third-party"""
    cookie_domain = cookie_domain.lstrip(".")
    page_domain = page_domain.lstrip(".")

    if cookie_domain == page_domain:
        return False

    # Check if cookie domain is a subdomain of page domain
    if cookie_domain.endswith("." + page_domain):
        return False

    # Check if page domain is a subdomain of cookie domain
    if page_domain.endswith("." + cookie_domain):
        return False

    return True


def detect_tracker(cookie: dict, trackers: list) -> Optional[dict]:
    """Detect if a cookie matches known tracker patterns"""
    cookie_str = f"{cookie.get('domain', '')} {cookie.get('name', '')} {cookie.get('value', '')}"

    for tracker in trackers:
        try:
            if re.search(tracker["pattern"], cookie_str, re.IGNORECASE):
                return tracker
        except:
            continue

    return None


def calculate_stats(cookies_db: dict, violations: list) -> dict:
    """Calculate cookie statistics"""
    total_cookies = 0
    domains = set()
    third_party_count = 0
    tracker_count = 0
    categories = {}

    for domain, cookies in cookies_db.get("cookies", {}).items():
        domains.add(domain)
        for cookie in cookies:
            total_cookies += 1
            if cookie.get("is_third_party"):
                third_party_count += 1
            if cookie.get("is_tracker"):
                tracker_count += 1
                cat = cookie.get("tracker_category", "unknown")
                categories[cat] = categories.get(cat, 0) + 1

    return {
        "total_cookies": total_cookies,
        "total_domains": len(domains),
        "third_party_cookies": third_party_count,
        "tracker_cookies": tracker_count,
        "tracker_categories": categories,
        "violations_count": len(violations),
        "violations_today": len([v for v in violations if v.get("timestamp", "").startswith(datetime.now().strftime("%Y-%m-%d"))]),
        "last_updated": datetime.now().isoformat()
    }


def check_policy_violations(cookies_db: dict, config: dict) -> list:
    """Check for policy violations"""
    violations = []
    policies = config.get("policies", [])

    for policy in policies:
        if not policy.get("enabled"):
            continue

        for domain, cookies in cookies_db.get("cookies", {}).items():
            # Check domain filter
            policy_domains = policy.get("domains")
            if policy_domains and domain not in policy_domains:
                continue

            for cookie in cookies:
                # Third-party violation
                if policy.get("block_third_party") and cookie.get("is_third_party"):
                    violations.append({
                        "id": hashlib.md5(f"{domain}-{cookie['name']}-third_party".encode()).hexdigest()[:12],
                        "timestamp": datetime.now().isoformat(),
                        "policy": policy["name"],
                        "domain": domain,
                        "cookie_name": cookie["name"],
                        "violation_type": "third_party",
                        "description": f"Third-party cookie detected from {cookie.get('domain', domain)}"
                    })

                # Tracker violation
                if policy.get("block_trackers") and cookie.get("is_tracker"):
                    violations.append({
                        "id": hashlib.md5(f"{domain}-{cookie['name']}-tracker".encode()).hexdigest()[:12],
                        "timestamp": datetime.now().isoformat(),
                        "policy": policy["name"],
                        "domain": domain,
                        "cookie_name": cookie["name"],
                        "violation_type": "tracker",
                        "description": f"Tracking cookie detected: {cookie.get('tracker_name', 'Unknown')}"
                    })

                # Cookie age violation
                max_age = policy.get("max_cookie_age_days", 365)
                cookie_expires = cookie.get("expires")
                if cookie_expires:
                    try:
                        expires_dt = datetime.fromisoformat(cookie_expires)
                        age_days = (expires_dt - datetime.now()).days
                        if age_days > max_age:
                            violations.append({
                                "id": hashlib.md5(f"{domain}-{cookie['name']}-age".encode()).hexdigest()[:12],
                                "timestamp": datetime.now().isoformat(),
                                "policy": policy["name"],
                                "domain": domain,
                                "cookie_name": cookie["name"],
                                "violation_type": "excessive_age",
                                "description": f"Cookie expires in {age_days} days (max: {max_age})"
                            })
                    except:
                        pass

    return violations


# Background cache refresh
async def refresh_cache():
    """Refresh cache periodically"""
    while True:
        try:
            cookies_db = load_cookies_db()
            violations = load_violations()
            config = load_config()

            _cache["cookies"] = cookies_db
            _cache["violations"] = violations
            _cache["stats"] = calculate_stats(cookies_db, violations)
            _cache["last_scan"] = datetime.now().isoformat()

            # Save cache
            CACHE_DIR.mkdir(parents=True, exist_ok=True)
            (CACHE_DIR / "stats.json").write_text(json.dumps(_cache["stats"]))

        except Exception as e:
            log_event("cache_error", {"error": str(e)})

        await asyncio.sleep(60)


@app.on_event("startup")
async def startup():
    """Initialize on startup"""
    # Ensure directories exist
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

    # Initialize config if needed
    if not CONFIG_FILE.exists():
        save_config(DEFAULT_CONFIG)

    # Start background cache refresh
    asyncio.create_task(refresh_cache())


# Health & Status endpoints
@app.get("/health")
async def health():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "secubox-cookies",
        "timestamp": datetime.now().isoformat()
    }


@app.get("/status")
async def get_status():
    """Get service status"""
    config = load_config()
    stats = _cache.get("stats") or calculate_stats(load_cookies_db(), load_violations())

    return {
        "enabled": config.get("enabled", True),
        "running": True,
        "last_scan": _cache.get("last_scan"),
        "total_cookies": stats.get("total_cookies", 0),
        "total_domains": stats.get("total_domains", 0),
        "third_party_cookies": stats.get("third_party_cookies", 0),
        "tracker_cookies": stats.get("tracker_cookies", 0),
        "violations_today": stats.get("violations_today", 0),
        "gdpr_mode": config.get("gdpr_mode", True),
        "tracker_detection": config.get("tracker_detection", True)
    }


# Configuration endpoints
@app.get("/config")
async def get_config():
    """Get configuration"""
    return load_config()


@app.post("/config")
async def update_config(req: ConfigUpdate, user: dict = Depends(require_jwt)):
    """Update configuration"""
    config = load_config()

    for field, value in req.dict(exclude_unset=True).items():
        if value is not None:
            config[field] = value

    save_config(config)
    log_event("config_updated", {"user": user.get("sub", "unknown")})

    return {"success": True, "message": "Configuration updated", "config": config}


# Cookie tracking endpoints
@app.get("/cookies")
async def get_cookies(
    domain: Optional[str] = None,
    third_party_only: bool = False,
    trackers_only: bool = False,
    limit: int = Query(100, ge=1, le=1000)
):
    """Get all tracked cookies"""
    cookies_db = _cache.get("cookies") or load_cookies_db()
    result = []

    for cookie_domain, cookies in cookies_db.get("cookies", {}).items():
        if domain and domain not in cookie_domain:
            continue

        for cookie in cookies:
            if third_party_only and not cookie.get("is_third_party"):
                continue
            if trackers_only and not cookie.get("is_tracker"):
                continue

            result.append({
                "domain": cookie_domain,
                **cookie
            })

            if len(result) >= limit:
                break

        if len(result) >= limit:
            break

    return {
        "success": True,
        "count": len(result),
        "cookies": result
    }


@app.get("/cookie/{domain}")
async def get_cookies_by_domain(domain: str):
    """Get cookies for a specific domain"""
    cookies_db = _cache.get("cookies") or load_cookies_db()

    # Find exact match or partial match
    domain_cookies = []
    for cookie_domain, cookies in cookies_db.get("cookies", {}).items():
        if domain in cookie_domain or cookie_domain in domain:
            domain_cookies.extend([{"domain": cookie_domain, **c} for c in cookies])

    return {
        "success": True,
        "domain": domain,
        "count": len(domain_cookies),
        "cookies": domain_cookies
    }


# Tracker management endpoints
@app.get("/trackers")
async def get_trackers():
    """Get known tracker patterns"""
    config = load_config()
    cookies_db = _cache.get("cookies") or load_cookies_db()

    # Count detections per tracker
    detections = {}
    for domain, cookies in cookies_db.get("cookies", {}).items():
        for cookie in cookies:
            if cookie.get("is_tracker") and cookie.get("tracker_name"):
                name = cookie["tracker_name"]
                detections[name] = detections.get(name, 0) + 1

    trackers = config.get("known_trackers", [])
    for tracker in trackers:
        tracker["detections"] = detections.get(tracker["name"], 0)

    return {
        "success": True,
        "count": len(trackers),
        "trackers": trackers
    }


@app.post("/tracker/add")
async def add_tracker(tracker: TrackerPattern, user: dict = Depends(require_jwt)):
    """Add a new tracker pattern"""
    config = load_config()

    # Validate regex
    try:
        re.compile(tracker.pattern)
    except re.error as e:
        raise HTTPException(status_code=400, detail=f"Invalid regex pattern: {str(e)}")

    new_tracker = {
        "pattern": tracker.pattern,
        "name": tracker.name,
        "category": tracker.category
    }

    if "known_trackers" not in config:
        config["known_trackers"] = []

    config["known_trackers"].append(new_tracker)
    save_config(config)

    log_event("tracker_added", {"name": tracker.name, "user": user.get("sub", "unknown")})

    return {"success": True, "message": f"Tracker pattern '{tracker.name}' added", "tracker": new_tracker}


@app.delete("/tracker/{tracker_id}")
async def remove_tracker(tracker_id: str, user: dict = Depends(require_jwt)):
    """Remove a tracker pattern by name or index"""
    config = load_config()
    trackers = config.get("known_trackers", [])

    # Try to find by name or index
    found_idx = None
    try:
        idx = int(tracker_id)
        if 0 <= idx < len(trackers):
            found_idx = idx
    except ValueError:
        for i, t in enumerate(trackers):
            if t.get("name", "").lower() == tracker_id.lower():
                found_idx = i
                break

    if found_idx is None:
        raise HTTPException(status_code=404, detail="Tracker pattern not found")

    removed = trackers.pop(found_idx)
    config["known_trackers"] = trackers
    save_config(config)

    log_event("tracker_removed", {"name": removed.get("name"), "user": user.get("sub", "unknown")})

    return {"success": True, "message": f"Tracker pattern removed", "removed": removed}


# Third-party cookies endpoint
@app.get("/thirdparty")
async def get_third_party_cookies(limit: int = Query(100, ge=1, le=1000)):
    """Get all third-party cookies"""
    cookies_db = _cache.get("cookies") or load_cookies_db()
    third_party = []

    for domain, cookies in cookies_db.get("cookies", {}).items():
        for cookie in cookies:
            if cookie.get("is_third_party"):
                third_party.append({"domain": domain, **cookie})
                if len(third_party) >= limit:
                    break
        if len(third_party) >= limit:
            break

    return {
        "success": True,
        "count": len(third_party),
        "cookies": third_party
    }


# Policy management endpoints
@app.get("/policies")
async def get_policies():
    """Get all cookie policies"""
    config = load_config()
    return {
        "success": True,
        "policies": config.get("policies", [])
    }


@app.post("/policy")
async def create_policy(policy: CookiePolicy, user: dict = Depends(require_jwt)):
    """Create a new cookie policy"""
    config = load_config()

    policy_id = hashlib.md5(policy.name.encode()).hexdigest()[:12]
    new_policy = {
        "id": policy_id,
        "name": policy.name,
        "enabled": policy.enabled,
        "block_third_party": policy.block_third_party,
        "block_trackers": policy.block_trackers,
        "require_consent": policy.require_consent,
        "max_cookie_age_days": policy.max_cookie_age_days,
        "domains": policy.domains
    }

    if "policies" not in config:
        config["policies"] = []

    config["policies"].append(new_policy)
    save_config(config)

    log_event("policy_created", {"name": policy.name, "user": user.get("sub", "unknown")})

    return {"success": True, "message": f"Policy '{policy.name}' created", "policy": new_policy}


@app.delete("/policy/{policy_id}")
async def delete_policy(policy_id: str, user: dict = Depends(require_jwt)):
    """Delete a cookie policy"""
    config = load_config()
    policies = config.get("policies", [])

    found_idx = None
    for i, p in enumerate(policies):
        if p.get("id") == policy_id or p.get("name", "").lower() == policy_id.lower():
            found_idx = i
            break

    if found_idx is None:
        raise HTTPException(status_code=404, detail="Policy not found")

    removed = policies.pop(found_idx)
    config["policies"] = policies
    save_config(config)

    log_event("policy_deleted", {"name": removed.get("name"), "user": user.get("sub", "unknown")})

    return {"success": True, "message": "Policy deleted", "removed": removed}


# Violations endpoint
@app.get("/violations")
async def get_violations(
    limit: int = Query(100, ge=1, le=1000),
    policy: Optional[str] = None,
    violation_type: Optional[str] = None
):
    """Get policy violations"""
    violations = _cache.get("violations") or load_violations()

    # Filter
    filtered = violations
    if policy:
        filtered = [v for v in filtered if policy.lower() in v.get("policy", "").lower()]
    if violation_type:
        filtered = [v for v in filtered if v.get("violation_type") == violation_type]

    # Sort by timestamp (newest first) and limit
    filtered = sorted(filtered, key=lambda x: x.get("timestamp", ""), reverse=True)[:limit]

    return {
        "success": True,
        "count": len(filtered),
        "total": len(violations),
        "violations": filtered
    }


# Statistics endpoint
@app.get("/stats")
async def get_stats():
    """Get cookie statistics"""
    stats = _cache.get("stats")
    if not stats:
        cookies_db = load_cookies_db()
        violations = load_violations()
        stats = calculate_stats(cookies_db, violations)

    config = load_config()

    return {
        "success": True,
        "stats": stats,
        "config": {
            "gdpr_mode": config.get("gdpr_mode", True),
            "tracker_detection": config.get("tracker_detection", True),
            "third_party_detection": config.get("third_party_detection", True)
        }
    }


# Scan endpoint
@app.post("/scan")
async def scan_url(req: ScanRequest, user: dict = Depends(require_jwt)):
    """Scan a URL for cookies"""
    config = load_config()
    cookies_db = load_cookies_db()

    # Parse domain from URL
    from urllib.parse import urlparse
    parsed = urlparse(req.url if req.url.startswith("http") else f"https://{req.url}")
    domain = parsed.netloc or req.url

    # Simulate cookie scan (in production, this would use browser automation or traffic inspection)
    # For now, record the scan request
    scan_result = {
        "url": req.url,
        "domain": domain,
        "timestamp": datetime.now().isoformat(),
        "cookies_found": 0,
        "third_party": 0,
        "trackers": 0,
        "cookies": []
    }

    log_event("scan_requested", {
        "url": req.url,
        "domain": domain,
        "user": user.get("sub", "unknown")
    })

    # If we have existing data for this domain, return it
    if domain in cookies_db.get("cookies", {}):
        existing_cookies = cookies_db["cookies"][domain]
        scan_result["cookies_found"] = len(existing_cookies)
        scan_result["third_party"] = len([c for c in existing_cookies if c.get("is_third_party")])
        scan_result["trackers"] = len([c for c in existing_cookies if c.get("is_tracker")])
        scan_result["cookies"] = existing_cookies

    return {
        "success": True,
        "message": "Scan completed",
        "result": scan_result
    }


# Logs endpoint
@app.get("/logs")
async def get_logs(
    limit: int = Query(100, ge=1, le=1000),
    event_type: Optional[str] = None
):
    """Get analysis logs"""
    logs = []

    if LOG_FILE.exists():
        try:
            with open(LOG_FILE) as f:
                for line in f:
                    try:
                        entry = json.loads(line.strip())
                        if event_type and entry.get("type") != event_type:
                            continue
                        logs.append(entry)
                    except:
                        continue
        except:
            pass

    # Return newest first
    logs = sorted(logs, key=lambda x: x.get("timestamp", ""), reverse=True)[:limit]

    return {
        "success": True,
        "count": len(logs),
        "logs": logs
    }


@app.get("/info")
async def get_info():
    """Get module info"""
    return {
        "module": "secubox-cookies",
        "version": "1.0.0",
        "description": "Cookie tracking, analysis, and privacy compliance monitoring"
    }
