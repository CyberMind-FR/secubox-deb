"""SecuBox WAF - Web Application Firewall

Mitmproxy-based threat detection with CrowdSec integration.
300+ rules across 14+ categories (SQLi, XSS, RCE, VoIP, router botnets, etc.)
"""
import json
import re
import subprocess
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from collections import defaultdict
from fastapi import FastAPI, Depends, HTTPException, Request
from pydantic import BaseModel
from secubox_core.auth import require_jwt
from secubox_core.config import get_config

app = FastAPI(title="SecuBox WAF")

# Paths
RULES_PATH = "/usr/share/secubox/waf/waf-rules.json"
THREATS_LOG = "/var/log/secubox/waf-threats.log"
STATS_CACHE = "/tmp/secubox/waf-stats.json"

# Runtime state
_compiled_patterns: Dict[str, List[dict]] = {}
_category_stats: Dict[str, dict] = {}
_request_counts: Dict[str, List[float]] = defaultdict(list)


def _cfg():
    cfg = get_config("waf")
    return {
        "enabled": cfg.get("enabled", True) if cfg else True,
        "autoban_enabled": cfg.get("autoban_enabled", True) if cfg else True,
        "ban_duration": cfg.get("ban_duration", "4h") if cfg else "4h",
        "min_severity": cfg.get("min_severity", "high") if cfg else "high",
        "sensitivity": cfg.get("sensitivity", "moderate") if cfg else "moderate",
        "rate_limit": cfg.get("rate_limit", 100) if cfg else 100,
        "rate_window": cfg.get("rate_window", 60) if cfg else 60,
        "whitelist": cfg.get("whitelist", "127.0.0.1,192.168.255.1") if cfg else "127.0.0.1",
    }


def _load_rules():
    """Load and compile WAF rules from JSON."""
    global _compiled_patterns, _category_stats

    rules_file = Path(RULES_PATH)
    if not rules_file.exists():
        # Try local config path
        rules_file = Path("/home/reepost/CyberMindStudio/secubox-deb/secubox-deb/packages/secubox-waf/config/waf-rules.json")
        if not rules_file.exists():
            return

    try:
        data = json.loads(rules_file.read_text())
        categories = data.get("categories", {})

        _compiled_patterns.clear()
        _category_stats.clear()

        for cat_id, cat_data in categories.items():
            if not cat_data.get("enabled", True):
                continue

            patterns = []
            for rule in cat_data.get("patterns", []):
                try:
                    compiled = re.compile(rule["pattern"], re.IGNORECASE)
                    patterns.append({
                        "id": rule["id"],
                        "regex": compiled,
                        "desc": rule.get("desc", ""),
                        "cve": rule.get("cve"),
                    })
                except re.error:
                    pass  # Skip invalid patterns

            _compiled_patterns[cat_id] = patterns
            _category_stats[cat_id] = {
                "name": cat_data.get("name", cat_id),
                "severity": cat_data.get("severity", "medium"),
                "owasp": cat_data.get("owasp"),
                "rules_count": len(patterns),
                "enabled": True,
            }
    except Exception:
        pass


# Load rules on startup
_load_rules()


def _check_request(path: str, query: str = "", body: str = "", headers: dict = None) -> Optional[dict]:
    """Check request against WAF rules."""
    if not _cfg()["enabled"]:
        return None

    # Combine all inputs for scanning
    scan_text = f"{path} {query} {body}".lower()

    for cat_id, patterns in _compiled_patterns.items():
        for pattern in patterns:
            if pattern["regex"].search(scan_text):
                return {
                    "matched": True,
                    "category": cat_id,
                    "rule_id": pattern["id"],
                    "description": pattern["desc"],
                    "severity": _category_stats.get(cat_id, {}).get("severity", "medium"),
                    "cve": pattern.get("cve"),
                }

    return None


def _check_rate_limit(ip: str) -> dict:
    """Check if IP exceeds rate limit."""
    cfg = _cfg()
    window = cfg["rate_window"]
    max_requests = cfg["rate_limit"]

    now = datetime.now().timestamp()
    cutoff = now - window

    # Clean old entries
    _request_counts[ip] = [t for t in _request_counts[ip] if t > cutoff]
    _request_counts[ip].append(now)

    count = len(_request_counts[ip])
    return {
        "is_limited": count > max_requests,
        "count": count,
        "limit": max_requests,
        "window": window,
    }


def _log_threat(ip: str, threat: dict, request_path: str):
    """Log threat to file."""
    log_dir = Path(THREATS_LOG).parent
    log_dir.mkdir(parents=True, exist_ok=True)

    entry = {
        "timestamp": datetime.now().isoformat(),
        "ip": ip,
        "path": request_path,
        "category": threat.get("category"),
        "rule_id": threat.get("rule_id"),
        "severity": threat.get("severity"),
        "description": threat.get("description"),
    }

    with open(THREATS_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")


def _should_autoban(threat: dict) -> bool:
    """Determine if threat should trigger auto-ban."""
    cfg = _cfg()
    if not cfg["autoban_enabled"]:
        return False

    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    threat_severity = severity_order.get(threat.get("severity", "low"), 1)
    min_severity = severity_order.get(cfg["min_severity"], 3)

    return threat_severity >= min_severity


def _ban_ip(ip: str, duration: str = "4h", reason: str = "WAF auto-ban"):
    """Ban IP via CrowdSec."""
    try:
        subprocess.run([
            "cscli", "decisions", "add",
            "--ip", ip,
            "--type", "ban",
            "--duration", duration,
            "--reason", reason
        ], capture_output=True, timeout=10)
    except Exception:
        pass


def _unban_ip(ip: str):
    """Remove IP ban via CrowdSec."""
    try:
        subprocess.run([
            "cscli", "decisions", "delete",
            "--ip", ip
        ], capture_output=True, timeout=10)
    except Exception:
        pass


def _get_bans() -> List[dict]:
    """Get active bans from CrowdSec."""
    try:
        result = subprocess.run([
            "cscli", "decisions", "list", "-o", "json"
        ], capture_output=True, text=True, timeout=10)

        if result.returncode == 0 and result.stdout:
            return json.loads(result.stdout) or []
    except Exception:
        pass
    return []


def _get_threat_stats() -> dict:
    """Get threat statistics from log."""
    stats = {
        "total_threats": 0,
        "threats_today": 0,
        "by_category": defaultdict(int),
        "by_severity": defaultdict(int),
        "top_ips": defaultdict(int),
    }

    log_path = Path(THREATS_LOG)
    if not log_path.exists():
        return stats

    today = datetime.now().date().isoformat()

    try:
        with open(log_path) as f:
            for line in f:
                try:
                    entry = json.loads(line.strip())
                    stats["total_threats"] += 1

                    if entry.get("timestamp", "").startswith(today):
                        stats["threats_today"] += 1

                    stats["by_category"][entry.get("category", "unknown")] += 1
                    stats["by_severity"][entry.get("severity", "unknown")] += 1
                    stats["top_ips"][entry.get("ip", "unknown")] += 1
                except json.JSONDecodeError:
                    pass
    except Exception:
        pass

    # Convert defaultdicts and get top 10 IPs
    stats["by_category"] = dict(stats["by_category"])
    stats["by_severity"] = dict(stats["by_severity"])
    stats["top_ips"] = dict(sorted(stats["top_ips"].items(), key=lambda x: -x[1])[:10])

    return stats


# === Public Endpoints ===

@app.get("/status")
async def status():
    """WAF status (public)."""
    cfg = _cfg()
    total_rules = sum(len(p) for p in _compiled_patterns.values())
    active_categories = len(_compiled_patterns)

    return {
        "module": "waf",
        "enabled": cfg["enabled"],
        "autoban_enabled": cfg["autoban_enabled"],
        "total_rules": total_rules,
        "active_categories": active_categories,
        "sensitivity": cfg["sensitivity"],
    }


# === Protected Endpoints ===

@app.get("/info", dependencies=[Depends(require_jwt)])
async def info():
    """Detailed WAF info."""
    cfg = _cfg()
    return {
        "config": cfg,
        "rules_path": RULES_PATH,
        "threats_log": THREATS_LOG,
    }


@app.get("/categories")
async def get_categories():
    """List all WAF categories with stats (public)."""
    return {
        "categories": _category_stats,
        "total_rules": sum(c["rules_count"] for c in _category_stats.values()),
    }


@app.get("/rules", dependencies=[Depends(require_jwt)])
async def get_rules():
    """Get all WAF rules by category."""
    rules = {}
    for cat_id, patterns in _compiled_patterns.items():
        rules[cat_id] = [
            {"id": p["id"], "pattern": p["regex"].pattern, "desc": p["desc"], "cve": p.get("cve")}
            for p in patterns
        ]
    return {"rules": rules}


@app.get("/rules/{category}", dependencies=[Depends(require_jwt)])
async def get_category_rules(category: str):
    """Get rules for a specific category."""
    if category not in _compiled_patterns:
        raise HTTPException(404, f"Category not found: {category}")

    patterns = _compiled_patterns[category]
    return {
        "category": category,
        "info": _category_stats.get(category, {}),
        "rules": [
            {"id": p["id"], "pattern": p["regex"].pattern, "desc": p["desc"], "cve": p.get("cve")}
            for p in patterns
        ]
    }


class ToggleCategoryRequest(BaseModel):
    enabled: bool


@app.post("/category/{category}/toggle", dependencies=[Depends(require_jwt)])
async def toggle_category(category: str, req: ToggleCategoryRequest):
    """Enable or disable a WAF category."""
    if category not in _category_stats:
        raise HTTPException(404, f"Category not found: {category}")

    # Update in-memory state
    if req.enabled:
        _load_rules()  # Reload to re-enable
    else:
        _compiled_patterns.pop(category, None)
        if category in _category_stats:
            _category_stats[category]["enabled"] = False

    return {"success": True, "category": category, "enabled": req.enabled}


@app.get("/stats")
async def get_stats():
    """Get threat statistics (public)."""
    return _get_threat_stats()


@app.get("/alerts")
async def get_alerts(limit: int = 50):
    """Get recent threat alerts (public)."""
    log_path = Path(THREATS_LOG)
    if not log_path.exists():
        return {"alerts": []}

    alerts = []
    try:
        with open(log_path) as f:
            lines = f.readlines()[-limit:]
            for line in reversed(lines):
                try:
                    alerts.append(json.loads(line.strip()))
                except json.JSONDecodeError:
                    pass
    except Exception:
        pass

    return {"alerts": alerts}


@app.get("/bans")
async def get_bans():
    """Get active IP bans from CrowdSec (public)."""
    bans = _get_bans()
    return {"bans": bans, "total": len(bans)}


class BanRequest(BaseModel):
    ip: str
    duration: str = "4h"
    reason: str = "Manual WAF ban"


@app.post("/ban", dependencies=[Depends(require_jwt)])
async def ban_ip(req: BanRequest):
    """Manually ban an IP."""
    _ban_ip(req.ip, req.duration, req.reason)
    return {"success": True, "ip": req.ip, "duration": req.duration}


@app.post("/unban/{ip}", dependencies=[Depends(require_jwt)])
async def unban_ip(ip: str):
    """Remove IP ban."""
    _unban_ip(ip)
    return {"success": True, "ip": ip}


class CheckRequest(BaseModel):
    path: str
    query: str = ""
    body: str = ""
    headers: dict = None
    ip: str = None


@app.post("/check", dependencies=[Depends(require_jwt)])
async def check_threat(req: CheckRequest):
    """Check a request for threats (for HAProxy integration)."""
    # Rate limit check
    if req.ip:
        rate_result = _check_rate_limit(req.ip)
        if rate_result["is_limited"]:
            return {
                "blocked": True,
                "reason": "rate_limit",
                "details": rate_result,
            }

    # WAF pattern check
    threat = _check_request(req.path, req.query, req.body, req.headers)

    if threat:
        if req.ip:
            _log_threat(req.ip, threat, req.path)

            cfg = _cfg()
            whitelist = cfg["whitelist"].split(",")
            if req.ip not in whitelist and _should_autoban(threat):
                _ban_ip(req.ip, cfg["ban_duration"], f"WAF: {threat['rule_id']}")
                threat["auto_banned"] = True

        return {"blocked": True, "reason": "waf_match", "threat": threat}

    return {"blocked": False}


@app.post("/reload", dependencies=[Depends(require_jwt)])
async def reload_rules():
    """Reload WAF rules from file."""
    _load_rules()
    total_rules = sum(len(p) for p in _compiled_patterns.values())
    return {
        "success": True,
        "categories": len(_compiled_patterns),
        "rules": total_rules,
    }


class AutobanConfig(BaseModel):
    enabled: bool = None
    ban_duration: str = None
    min_severity: str = None
    sensitivity: str = None


@app.post("/autoban/config", dependencies=[Depends(require_jwt)])
async def update_autoban_config(req: AutobanConfig):
    """Update auto-ban configuration."""
    # In production, this would update the TOML config file
    return {"success": True, "config": req.dict(exclude_none=True)}


@app.get("/whitelist", dependencies=[Depends(require_jwt)])
async def get_whitelist():
    """Get whitelisted IPs."""
    cfg = _cfg()
    return {"whitelist": cfg["whitelist"].split(",")}


class WhitelistRequest(BaseModel):
    ip: str
    action: str  # "add" or "remove"


@app.post("/whitelist", dependencies=[Depends(require_jwt)])
async def update_whitelist(req: WhitelistRequest):
    """Add or remove IP from whitelist."""
    # In production, this would update the TOML config file
    return {"success": True, "ip": req.ip, "action": req.action}
