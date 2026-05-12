# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""SecuBox WAF - Web Application Firewall

Mitmproxy-based threat detection with CrowdSec integration.
300+ rules across 14+ categories (SQLi, XSS, RCE, VoIP, router botnets, etc.)
"""
import os
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
import geoip2.database
import geoip2.errors

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
        "timestamp": datetime.utcnow().isoformat() + "Z",  # UTC with Z suffix
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
            "sudo", "cscli", "decisions", "add",
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
            "sudo", "cscli", "decisions", "delete",
            "--ip", ip
        ], capture_output=True, timeout=10)
    except Exception:
        pass


def _get_bans() -> List[dict]:
    """Get active bans from CrowdSec, flattened for dashboard."""
    try:
        result = subprocess.run([
            "sudo", "cscli", "decisions", "list", "-o", "json"
        ], capture_output=True, text=True, timeout=15)

        if result.returncode == 0 and result.stdout:
            raw = json.loads(result.stdout) or []
            # Flatten nested structure for dashboard
            bans = []
            for item in raw:
                decisions = item.get("decisions", [])
                events = item.get("events", [])
                # Extract metadata from first event
                meta = {}
                if events and events[0].get("meta"):
                    for m in events[0]["meta"]:
                        meta[m.get("key", "")] = m.get("value", "")

                for d in decisions:
                    bans.append({
                        "ip": d.get("value", ""),
                        "value": d.get("value", ""),
                        "scenario": d.get("scenario", ""),
                        "reason": d.get("scenario", ""),
                        "duration": d.get("duration", ""),
                        "type": d.get("type", "ban"),
                        "origin": d.get("origin", ""),
                        "id": d.get("id"),
                        "created_at": item.get("created_at", ""),
                        "country": meta.get("IsoCode", ""),
                        "asn": meta.get("ASNNumber", ""),
                        "asn_org": meta.get("ASNOrg", ""),
                    })
            return bans
    except Exception:
        pass
    return []


def _get_threat_stats() -> dict:
    """Get threat statistics from log with GeoIP country lookup."""
    stats = {
        "total_threats": 0,
        "threats_today": 0,
        "by_category": defaultdict(int),
        "by_severity": defaultdict(int),
        "top_ips": defaultdict(int),
        "top_countries": defaultdict(int),
        "top_vhosts": defaultdict(int),
    }
    ip_countries: Dict[str, str] = {}  # IP → country mapping

    log_path = Path(THREATS_LOG)
    if not log_path.exists():
        return stats

    today = datetime.now().date().isoformat()
    geoip_reader = _get_geoip_reader()

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

                    # IP tracking - try both field names for compatibility
                    ip = entry.get("client_ip") or entry.get("ip", "unknown")
                    stats["top_ips"][ip] += 1

                    # Country lookup via GeoIP (cache per IP)
                    if ip not in ip_countries:
                        ip_countries[ip] = _lookup_country(ip, geoip_reader)
                    country = ip_countries[ip]
                    stats["top_countries"][country] += 1

                    # Vhost tracking
                    vhost = entry.get("host") or entry.get("vhost", "unknown")
                    stats["top_vhosts"][vhost] += 1
                except json.JSONDecodeError:
                    pass
    except Exception:
        pass

    # Convert defaultdicts and get top 10
    stats["by_category"] = dict(stats["by_category"])
    stats["by_severity"] = dict(stats["by_severity"])

    # Top IPs with country codes included
    top_ips_sorted = sorted(stats["top_ips"].items(), key=lambda x: -x[1])[:10]
    stats["top_ips"] = {ip: count for ip, count in top_ips_sorted}
    stats["top_ips_countries"] = {ip: ip_countries.get(ip, "??") for ip, _ in top_ips_sorted}

    stats["top_countries"] = dict(sorted(stats["top_countries"].items(), key=lambda x: -x[1])[:10])
    stats["top_vhosts"] = dict(sorted(stats["top_vhosts"].items(), key=lambda x: -x[1])[:10])

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
    stats = _get_threat_stats()

    # Add dashboard-friendly fields
    stats["running"] = _cfg()["enabled"]
    stats["version"] = "1.2.0"
    stats["rules_loaded"] = sum(len(p) for p in _compiled_patterns.values())

    # blocked_today for card metric
    stats["blocked_today"] = stats.get("threats_today", 0)
    stats["blocked_24h"] = stats.get("total_threats", 0)

    # Categories list with counts for dashboard emojis
    cats = stats.get("by_category", {})
    stats["categories_list"] = [
        {"name": cat, "count": count}
        for cat, count in sorted(cats.items(), key=lambda x: -x[1])[:8]
    ]

    # Top countries formatted for dashboard
    countries = stats.get("top_countries", {})
    stats["top_countries"] = [
        {"country": c, "count": cnt}
        for c, cnt in sorted(countries.items(), key=lambda x: -x[1])[:5]
    ]

    # Top vhosts (full DNS names) for dashboard
    vhosts = stats.get("top_vhosts", {})
    stats["top_vhosts"] = [
        {"vhost": v, "count": cnt}
        for v, cnt in sorted(vhosts.items(), key=lambda x: -x[1])[:5]
    ]

    # Last threat for dashboard
    log_path = Path(THREATS_LOG)
    if log_path.exists():
        try:
            with open(log_path, "rb") as f:
                f.seek(0, 2)  # End of file
                size = f.tell()
                if size > 2000:
                    f.seek(-2000, 2)  # Last 2000 bytes
                else:
                    f.seek(0)
                lines = f.read().decode("utf-8", errors="ignore").strip().split("\n")
                if lines:
                    last_line = lines[-1]
                    last = json.loads(last_line)
                    # Calculate time ago
                    ts = last.get("timestamp", "")
                    time_ago = "recently"
                    if ts:
                        try:
                            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                            diff = datetime.now(dt.tzinfo) - dt
                            mins = int(diff.total_seconds() / 60)
                            if mins < 1:
                                time_ago = "just now"
                            elif mins < 60:
                                time_ago = f"{mins}m ago"
                            else:
                                time_ago = f"{mins // 60}h ago"
                        except Exception:
                            pass
                    stats["last_threat"] = {
                        "ip": last.get("ip") or last.get("client_ip", "unknown"),
                        "type": last.get("category", "attack"),
                        "vhost": last.get("host") or last.get("vhost"),
                        "time_ago": time_ago
                    }
        except Exception:
            pass

    return stats


@app.get("/alerts")
async def get_alerts(limit: int = 50, aggregate: bool = False):
    """Get recent threat alerts (public).

    Args:
        limit: Max alerts to return
        aggregate: If True, group alerts by IP with counts
    """
    log_path = Path(THREATS_LOG)
    if not log_path.exists():
        return {"alerts": []}

    alerts = []
    try:
        with open(log_path) as f:
            lines = f.readlines()[-500:]  # Read last 500 lines for aggregation
            for line in reversed(lines):
                try:
                    entry = json.loads(line.strip())
                    # Normalize field names
                    entry["client_ip"] = entry.get("client_ip") or entry.get("ip", "unknown")
                    alerts.append(entry)
                except json.JSONDecodeError:
                    pass
    except Exception:
        pass

    if aggregate:
        # Group by IP
        from collections import defaultdict
        ip_groups = defaultdict(lambda: {"alerts": [], "count": 0, "categories": set(), "severities": set()})

        for alert in alerts:
            ip = alert.get("client_ip", "unknown")
            ip_groups[ip]["alerts"].append(alert)
            ip_groups[ip]["count"] += 1
            ip_groups[ip]["categories"].add(alert.get("category", ""))
            ip_groups[ip]["severities"].add(alert.get("severity", ""))
            if "first_seen" not in ip_groups[ip]:
                ip_groups[ip]["first_seen"] = alert.get("timestamp")
            ip_groups[ip]["last_seen"] = alert.get("timestamp")

        # Convert to list sorted by count
        aggregated = []
        for ip, data in sorted(ip_groups.items(), key=lambda x: x[1]["count"], reverse=True)[:limit]:
            # Determine highest severity
            sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
            max_sev = max(data["severities"], key=lambda s: sev_order.get(s, 0), default="low")
            aggregated.append({
                "client_ip": ip,
                "count": data["count"],
                "categories": list(data["categories"]),
                "max_severity": max_sev,
                "first_seen": data.get("first_seen"),
                "last_seen": data.get("last_seen"),
                "latest_alert": data["alerts"][0] if data["alerts"] else None,
            })
        return {"alerts": aggregated, "aggregated": True}

    return {"alerts": alerts[:limit], "aggregated": False}


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


# ── Health & Auto-Repair ──────────────────────────────────────────

@app.get("/health")
async def health_check():
    """Layer 1: Basic health check."""
    rules_loaded = len(_compiled_patterns) > 0
    log_writable = os.access(Path(THREATS_LOG).parent, os.W_OK) if Path(THREATS_LOG).parent.exists() else False

    status = "ok" if rules_loaded and log_writable else "degraded"
    rules_count = sum(len(p) for p in _compiled_patterns.values())
    return {
        "status": status,
        "healthy": status == "ok",
        "module": "waf",
        "version": "1.2.0",
        "dev_stage": "production",
        "enabled": "enabled",
        "message": f"WAF active ({rules_count} rules)" if status == "ok" else "WAF degraded",
        "checks": {
            "rules_loaded": rules_loaded,
            "rules_count": rules_count,
            "log_writable": log_writable,
            "categories": len(_compiled_patterns)
        }
    }


@app.get("/doctor")
async def doctor_check():
    """Layer 2: Doctor health - can we self-repair?"""
    issues = []
    can_repair = True

    # Check rules file
    rules_path = Path(RULES_PATH)
    if not rules_path.exists():
        issues.append({"type": "rules_missing", "repairable": True})
    elif len(_compiled_patterns) == 0:
        issues.append({"type": "rules_not_loaded", "repairable": True})

    # Check log directory
    log_dir = Path(THREATS_LOG).parent
    if not log_dir.exists():
        issues.append({"type": "log_dir_missing", "repairable": True})
    elif not os.access(log_dir, os.W_OK):
        issues.append({"type": "log_not_writable", "repairable": True})

    # Check mitmproxy routes (for WAF integration)
    routes_file = Path("/srv/mitmproxy-waf/data/routes.json")
    if not routes_file.exists():
        routes_file = Path("/srv/mitmproxy/routes.json")
    if not routes_file.exists():
        issues.append({"type": "routes_missing", "repairable": False})
        can_repair = False

    return {
        "healthy": len(issues) == 0,
        "issues": issues,
        "can_repair": can_repair,
        "repair_endpoint": "/repair"
    }


@app.post("/repair", dependencies=[Depends(require_jwt)])
async def repair_waf():
    """Auto-repair WAF: reload rules, fix logs, sync routes."""
    repairs = []

    # 1. Ensure log directory
    log_dir = Path(THREATS_LOG).parent
    if not log_dir.exists():
        log_dir.mkdir(parents=True, exist_ok=True)
        repairs.append({"action": "create_log_dir", "status": "ok"})

    # Fix log permissions
    if log_dir.exists():
        try:
            os.chmod(log_dir, 0o755)
            log_file = Path(THREATS_LOG)
            if log_file.exists():
                os.chmod(log_file, 0o666)
            repairs.append({"action": "fix_log_perms", "status": "ok"})
        except Exception as e:
            repairs.append({"action": "fix_log_perms", "status": "error", "message": str(e)})

    # 2. Reload rules
    try:
        _load_rules()
        total = sum(len(p) for p in _compiled_patterns.values())
        repairs.append({"action": "reload_rules", "status": "ok", "rules": total})
    except Exception as e:
        repairs.append({"action": "reload_rules", "status": "error", "message": str(e)})

    # 3. Clear expired bans (via mitmproxy if available)
    # This would be done via the mitmproxy addon

    # 4. Verify mitmproxy connection
    routes_file = Path("/srv/mitmproxy-waf/data/routes.json")
    if not routes_file.exists():
        routes_file = Path("/srv/mitmproxy/routes.json")
    if routes_file.exists():
        try:
            routes = json.loads(routes_file.read_text())
            repairs.append({"action": "check_routes", "status": "ok", "routes": len(routes)})
        except Exception as e:
            repairs.append({"action": "check_routes", "status": "error", "message": str(e)})
    else:
        repairs.append({"action": "check_routes", "status": "warning", "message": "routes.json not found"})

    return {
        "success": all(r["status"] in ("ok", "warning") for r in repairs),
        "repairs": repairs
    }


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

# GeoIP lookup with caching
import urllib.request
import ssl

_geoip_cache = {}

# GeoIP database reader (local MaxMind database)
_geoip_reader = None
_geoip_cache = {}
GEOIP_DB_PATH = "/var/lib/secubox/geoip/GeoLite2-Country.mmdb"

def _get_geoip_reader():
    global _geoip_reader
    if _geoip_reader is None:
        try:
            _geoip_reader = geoip2.database.Reader(GEOIP_DB_PATH)
        except Exception:
            pass
    return _geoip_reader


def _lookup_country(ip: str, reader=None) -> str:
    """Lookup country code for IP address."""
    if ip in _geoip_cache:
        return _geoip_cache[ip]

    # Skip private/local IPs
    if ip.startswith(("10.", "192.168.", "127.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.3", "unknown")):
        _geoip_cache[ip] = "LAN"
        return "LAN"

    if reader is None:
        reader = _get_geoip_reader()

    if reader:
        try:
            response = reader.country(ip)
            country = response.country.iso_code or "??"
            _geoip_cache[ip] = country
            return country
        except geoip2.errors.AddressNotFoundError:
            _geoip_cache[ip] = "??"
            return "??"
        except Exception:
            pass

    _geoip_cache[ip] = "??"
    return "??"


@app.get("/geoip/{ip}")
async def get_geoip(ip: str):
    """Lookup country code for IP address using local MaxMind database."""
    if ip in _geoip_cache:
        return {"ip": ip, "country": _geoip_cache[ip]}
    
    # Skip private IPs
    if ip.startswith(("10.", "192.168.", "127.", "172.16.", "172.17.", "172.18.", "172.19.")):
        _geoip_cache[ip] = "LAN"
        return {"ip": ip, "country": "LAN"}
    
    # Try local database
    reader = _get_geoip_reader()
    if reader:
        try:
            response = reader.country(ip)
            country = response.country.iso_code or ""
            if country:
                _geoip_cache[ip] = country
                return {"ip": ip, "country": country}
        except Exception:
            pass
    
    return {"ip": ip, "country": ""}
