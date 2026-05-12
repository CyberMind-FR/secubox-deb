#!/usr/bin/env python3
"""SecuBox Metrics Dashboard API - FastAPI Backend

Provides real-time system metrics with caching for instant response.
Ported from luci-app-metrics-dashboard RPCD backend.
"""

import asyncio
import json
import os
import subprocess
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Try to import auth, fallback to no-auth for development
try:
    from secubox_core.auth import require_jwt
    AUTH_ENABLED = True
except ImportError:
    AUTH_ENABLED = False
    async def require_jwt():
        pass

from visitor_origin import VisitorOriginAggregator
from live_hosts import LiveHostsAggregator
from cert_status import CertStatusAggregator

try:
    from secubox_core.config import (
        get_visitor_origin_config,
        get_live_hosts_config,
        get_cert_status_config,
    )
except ImportError:  # dev fallback
    def get_visitor_origin_config(): return {"enabled": False, "window_minutes": 60, "min_count": 5, "top_n": 5, "asn_db_path": "/var/lib/GeoIP/GeoLite2-ASN.mmdb", "nft_table": "secubox_metrics", "nft_set": "seen_src", "nft_family": "inet"}
    def get_live_hosts_config():     return {"enabled": False, "window_minutes": 60, "top_n": 5, "haproxy_socket": "/run/haproxy/admin.sock", "frontend_filter": "*"}
    def get_cert_status_config():    return {"enabled": False, "letsencrypt_live_dir": "/etc/letsencrypt/live", "warn_days": 30, "critical_days": 7}

visitor_origin_agg = VisitorOriginAggregator(get_visitor_origin_config())
live_hosts_agg     = LiveHostsAggregator(get_live_hosts_config())
cert_status_agg    = CertStatusAggregator(get_cert_status_config())


@asynccontextmanager
async def lifespan(_app):
    tasks = [
        asyncio.create_task(visitor_origin_agg.run_forever()),
        asyncio.create_task(live_hosts_agg.run_forever()),
        asyncio.create_task(cert_status_agg.run_forever()),
    ]
    try:
        yield
    finally:
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


app = FastAPI(
    title="SecuBox Metrics Dashboard",
    description="Real-time system metrics with caching",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS middleware for cross-origin health banner requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Health banner injected on any domain
    allow_credentials=False,
    allow_methods=["GET"],
    allow_headers=["*"],
)

# Cache configuration
CACHE_DIR = Path("/tmp/secubox")
CACHE_FILE = CACHE_DIR / "metrics-cache.json"
CACHE_TTL = 30  # seconds

# Ensure cache directory exists
CACHE_DIR.mkdir(parents=True, exist_ok=True)

def run_cmd(cmd: list, default: str = "") -> str:
    """Run a command and return output."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        return result.stdout.strip() if result.returncode == 0 else default
    except Exception:
        return default

def get_cache_age() -> int:
    """Get cache age in seconds."""
    if not CACHE_FILE.exists():
        return 999
    try:
        mtime = CACHE_FILE.stat().st_mtime
        return int(time.time() - mtime)
    except Exception:
        return 999

def cache_is_fresh() -> bool:
    """Check if cache is fresh."""
    return get_cache_age() < CACHE_TTL

def read_cache() -> Optional[dict]:
    """Read cached data."""
    if not CACHE_FILE.exists():
        return None
    try:
        with open(CACHE_FILE) as f:
            return json.load(f)
    except Exception:
        return None

def write_cache(data: dict):
    """Write data to cache."""
    try:
        with open(CACHE_FILE, 'w') as f:
            json.dump(data, f)
    except Exception:
        pass

def build_overview() -> dict:
    """Build system overview metrics."""
    # Uptime
    try:
        with open('/proc/uptime') as f:
            uptime = int(float(f.read().split()[0]))
    except Exception:
        uptime = 0

    # Load average
    try:
        with open('/proc/loadavg') as f:
            load = ' '.join(f.read().split()[:3])
    except Exception:
        load = "0 0 0"

    # Memory
    try:
        with open('/proc/meminfo') as f:
            meminfo = {}
            for line in f:
                parts = line.split()
                if len(parts) >= 2:
                    meminfo[parts[0].rstrip(':')] = int(parts[1])
        mem_total = meminfo.get('MemTotal', 0)
        mem_free = meminfo.get('MemAvailable', meminfo.get('MemFree', 0))
        mem_used = mem_total - mem_free
        mem_pct = (mem_used * 100 // mem_total) if mem_total > 0 else 0
    except Exception:
        mem_total = mem_used = mem_pct = 0

    # Service status checks
    def check_lxc_running(name: str) -> bool:
        result = run_cmd(['lxc-info', '-n', name, '-s'])
        return 'RUNNING' in result

    def check_process(name: str) -> bool:
        result = run_cmd(['pgrep', '-x', name])
        return bool(result)

    def check_systemd_service(name: str) -> bool:
        result = run_cmd(['systemctl', 'is-active', name])
        return result == 'active'

    haproxy_up = check_lxc_running('haproxy') or check_systemd_service('haproxy')
    mitmproxy_up = check_lxc_running('mitmproxy-in') or check_process('mitmdump')
    crowdsec_up = check_process('crowdsec') or check_systemd_service('crowdsec')

    # Counts - adapted for Debian (using config files instead of UCI)
    vhost_count = 0
    try:
        vhost_dir = Path('/etc/nginx/sites-enabled')
        if vhost_dir.exists():
            vhost_count = len(list(vhost_dir.glob('*')))
    except Exception:
        pass

    metablog_count = 0
    try:
        # Count actual site directories in /srv/metablogizer/sites/
        metablog_dir = Path('/srv/metablogizer/sites')
        if metablog_dir.exists():
            metablog_count = len([d for d in metablog_dir.iterdir() if d.is_dir() and not d.name.startswith('.')])
    except Exception:
        pass

    streamlit_count = 0
    try:
        # Count running streamlit instances via systemd
        result = run_cmd(['systemctl', 'list-units', '--type=service', '--state=running', '--plain', '--no-legend'])
        if result:
            streamlit_count = sum(1 for line in result.split('\n') if 'streamlit' in line.lower())
        # Fallback: count config entries
        if streamlit_count == 0:
            streamlit_conf = Path('/etc/secubox/streamlit.toml')
            if streamlit_conf.exists():
                content = streamlit_conf.read_text()
                streamlit_count = content.count('[instance.')
    except Exception:
        pass

    cert_count = 0
    try:
        # Count certificates in HAProxy certs directory and Let's Encrypt
        cert_dirs = [Path('/data/haproxy/certs'), Path('/srv/haproxy/certs'), Path('/etc/letsencrypt/live')]
        for cert_dir in cert_dirs:
            if cert_dir.exists():
                # Count .pem files and subdirectories (for Let's Encrypt)
                cert_count += len([f for f in cert_dir.glob('*.pem') if f.is_file()])
                cert_count += len([d for d in cert_dir.iterdir() if d.is_dir() and not d.name.startswith('.')])
    except Exception:
        pass

    lxc_running = 0
    try:
        result = run_cmd(['lxc-ls', '--running'])
        if result:
            lxc_running = len(result.split())
    except Exception:
        pass

    return {
        "uptime": uptime,
        "load": load,
        "mem_total_kb": mem_total,
        "mem_used_kb": mem_used,
        "mem_pct": mem_pct,
        "haproxy": haproxy_up,
        "mitmproxy": mitmproxy_up,
        "crowdsec": crowdsec_up,
        "vhosts": vhost_count,
        "metablogs": metablog_count,
        "streamlits": streamlit_count,
        "certificates": cert_count,
        "lxc_containers": lxc_running
    }

def build_waf_stats() -> dict:
    """Build WAF/CrowdSec statistics."""
    cs_running = bool(run_cmd(['pgrep', '-x', 'crowdsec'])) or \
                 run_cmd(['systemctl', 'is-active', 'crowdsec']) == 'active'
    mitmproxy_running = bool(run_cmd(['pgrep', '-f', 'mitmdump']))

    bans = alerts_today = waf_blocked = 0

    if cs_running:
        try:
            # Get decisions count
            result = run_cmd(['cscli', 'decisions', 'list', '-o', 'json'])
            if result:
                decisions = json.loads(result) or []
                bans = len(decisions)
                waf_blocked = sum(1 for d in decisions if 'mitmproxy' in str(d))
        except Exception:
            pass

        try:
            # Get alerts count
            result = run_cmd(['cscli', 'alerts', 'list', '--since', '24h', '-o', 'json'])
            if result:
                alerts = json.loads(result) or []
                alerts_today = len(alerts)
        except Exception:
            pass

    return {
        "crowdsec_running": cs_running,
        "mitmproxy_running": mitmproxy_running,
        "active_bans": bans,
        "alerts_today": alerts_today,
        "waf_blocked": waf_blocked
    }

def build_connections() -> dict:
    """Build connection statistics."""
    def count_connections(port: int) -> int:
        try:
            result = run_cmd(['ss', '-tn', 'state', 'established', f'sport', f'= :{port}'])
            return max(0, len(result.strip().split('\n')) - 1)  # -1 for header
        except Exception:
            return 0

    http_conns = count_connections(80)
    https_conns = count_connections(443)
    ssh_conns = count_connections(22)

    # Total TCP established
    try:
        result = run_cmd(['ss', '-tn', 'state', 'established'])
        total_tcp = max(0, len(result.strip().split('\n')) - 1)
    except Exception:
        total_tcp = 0

    return {
        "http": http_conns,
        "https": https_conns,
        "ssh": ssh_conns,
        "total_tcp": total_tcp
    }

def build_cache() -> dict:
    """Build full metrics cache."""
    data = {
        "overview": build_overview(),
        "waf": build_waf_stats(),
        "connections": build_connections(),
        "timestamp": datetime.now().isoformat(),
        "timestamp_epoch": int(time.time())
    }
    write_cache(data)
    return data

def get_freshness() -> dict:
    """Get cache freshness metadata."""
    age = get_cache_age()
    cached = read_cache()

    return {
        "age": age,
        "timestamp": cached.get("timestamp", "") if cached else "",
        "timestamp_epoch": cached.get("timestamp_epoch", 0) if cached else 0,
        "fresh": age < CACHE_TTL
    }

def get_cached_or_build() -> dict:
    """Get cached data or build new."""
    if cache_is_fresh():
        cached = read_cache()
        if cached:
            return cached
    return build_cache()

# API Endpoints

@app.get("/api/v1/metrics/status")
async def get_status():
    """Module status endpoint."""
    return {"status": "ok", "module": "metrics", "version": "1.0.0"}

@app.get("/health")
@app.get("/api/v1/metrics/health")
async def get_health():
    """Standard health check endpoint (navbar compliant)."""
    cache_ok = CACHE_FILE.exists() and cache_is_fresh()
    return {
        "status": "ok" if cache_ok else "degraded",
        "healthy": cache_ok,
        "module": "metrics",
        "version": "1.0.0",
        "dev_stage": "beta",
        "enabled": "enabled",
        "message": "Metrics cache active" if cache_ok else "Cache stale or missing",
        "checks": {
            "cache_exists": CACHE_FILE.exists(),
            "cache_fresh": cache_is_fresh(),
            "cache_age": get_cache_age()
        }
    }

@app.get("/api/v1/metrics/overview")
async def get_overview(auth: None = Depends(require_jwt)):
    """Get system overview metrics."""
    cached = read_cache()
    if cached and cache_is_fresh():
        data = cached.get("overview", build_overview())
    else:
        # Trigger async rebuild
        data = build_overview()

    data["_freshness"] = get_freshness()
    return data

@app.get("/api/v1/metrics/waf_stats")
async def get_waf_stats(auth: None = Depends(require_jwt)):
    """Get WAF/CrowdSec statistics."""
    cached = read_cache()
    if cached and cache_is_fresh():
        data = cached.get("waf", build_waf_stats())
    else:
        data = build_waf_stats()

    data["_freshness"] = get_freshness()
    return data

@app.get("/api/v1/metrics/connections")
async def get_connections(auth: None = Depends(require_jwt)):
    """Get connection statistics."""
    cached = read_cache()
    if cached and cache_is_fresh():
        data = cached.get("connections", build_connections())
    else:
        data = build_connections()

    data["_freshness"] = get_freshness()
    return data

@app.get("/api/v1/metrics/all")
async def get_all(auth: None = Depends(require_jwt)):
    """Get all metrics data."""
    return get_cached_or_build()

@app.post("/api/v1/metrics/refresh")
async def refresh_cache(auth: None = Depends(require_jwt)):
    """Force cache refresh."""
    data = build_cache()
    return {"status": "ok", "message": "Cache refreshed", "timestamp": data["timestamp"]}

@app.get("/api/v1/metrics/certs")
async def get_certs(auth: None = Depends(require_jwt)):
    """Get SSL certificate information."""
    certs = []
    cert_dirs = [Path('/etc/letsencrypt/live'), Path('/srv/haproxy/certs')]

    for cert_dir in cert_dirs:
        if not cert_dir.exists():
            continue

        for item in cert_dir.iterdir():
            if item.is_dir() or item.suffix == '.pem':
                name = item.stem if item.is_file() else item.name
                certs.append({
                    "name": name,
                    "expiry": "valid",
                    "days_left": 365,
                    "status": "valid"
                })
                if len(certs) >= 20:
                    break

    return {"certs": certs}

@app.get("/api/v1/metrics/vhosts")
async def get_vhosts(auth: None = Depends(require_jwt)):
    """Get virtual hosts list."""
    vhosts = []
    vhost_dir = Path('/etc/nginx/sites-enabled')

    if vhost_dir.exists():
        for item in vhost_dir.iterdir():
            if item.is_file() or item.is_symlink():
                vhosts.append({
                    "domain": item.name,
                    "enabled": True
                })
                if len(vhosts) >= 20:
                    break

    return {"vhosts": vhosts}

@app.get("/api/v1/metrics/firewall_stats")
async def get_firewall_stats(auth: None = Depends(require_jwt)):
    """Get firewall statistics."""
    # Get nftables drop count
    nft_drops = 0
    try:
        result = run_cmd(['nft', 'list', 'counters'])
        # Parse drop counters if available
    except Exception:
        pass

    return {
        "iptables_drops": 0,
        "nft_drops": nft_drops,
        "bouncer_blocks": 0
    }


# ═══════════════════════════════════════════════════════════════════════════════
# HEALTH BANNER SUMMARY API
# For the global health banner with smart doctor advisor
# ═══════════════════════════════════════════════════════════════════════════════

def build_health_summary() -> dict:
    """Build aggregated health summary for the health banner."""

    # Get cached metrics or build fresh
    cached = read_cache()
    if not cached or not cache_is_fresh():
        cached = build_cache()

    overview = cached.get("overview", {})
    waf_stats = cached.get("waf", {})

    # Calculate module statuses
    modules = {}

    # WAF status (mitmproxy)
    mitmproxy_up = overview.get("mitmproxy", False)
    modules["waf"] = {
        "status": "ok" if mitmproxy_up else "error",
        "running": mitmproxy_up
    }

    # CrowdSec status
    crowdsec_up = overview.get("crowdsec", False) or waf_stats.get("crowdsec_running", False)
    modules["crowdsec"] = {
        "status": "ok" if crowdsec_up else "error",
        "running": crowdsec_up
    }

    # HAProxy status
    haproxy_up = overview.get("haproxy", False)
    modules["haproxy"] = {
        "status": "ok" if haproxy_up else "error",
        "running": haproxy_up
    }

    # Nginx status
    nginx_up = run_cmd(['systemctl', 'is-active', 'nginx']) == 'active'
    modules["nginx"] = {
        "status": "ok" if nginx_up else "warn",
        "running": nginx_up
    }

    # System status (based on resources)
    mem_pct = overview.get("mem_pct", 0)
    system_status = "ok"
    if mem_pct > 90:
        system_status = "error"
    elif mem_pct > 75:
        system_status = "warn"
    modules["system"] = {
        "status": system_status,
        "mem_pct": mem_pct
    }

    # Get CPU usage
    cpu_pct = 0
    try:
        with open('/proc/stat') as f:
            cpu_line = f.readline()
            parts = cpu_line.split()
            if len(parts) >= 5:
                idle = int(parts[4])
                total = sum(int(p) for p in parts[1:])
                # Rough estimate - proper would need delta
                cpu_pct = min(99, max(0, 100 - (idle * 100 // max(1, total))))
    except Exception:
        pass

    # Fallback: use load average as percentage
    if cpu_pct == 0:
        try:
            load_str = overview.get("load", "0 0 0")
            load_1m = float(load_str.split()[0])
            # Estimate based on 4 cores
            cpu_pct = min(100, int(load_1m * 25))
        except Exception:
            pass

    # Get disk usage
    disk_pct = 0
    try:
        result = run_cmd(['df', '-h', '/'])
        lines = result.split('\n')
        if len(lines) >= 2:
            parts = lines[1].split()
            if len(parts) >= 5:
                disk_pct = int(parts[4].rstrip('%'))
    except Exception:
        pass

    # Get WAF blocked percentage (estimate from recent logs)
    blocked_pct = 0
    try:
        waf_log = Path('/var/log/mitmproxy/threats.jsonl')
        if waf_log.exists():
            # Count threats in last hour
            result = run_cmd(['wc', '-l', str(waf_log)])
            threat_count = int(result.split()[0]) if result else 0
            # Rough estimate: 1000 requests/hour baseline
            blocked_pct = min(100, threat_count // 10)
    except Exception:
        pass

    # Count services down
    services_down = 0
    critical_services = ['haproxy', 'nginx', 'crowdsec']
    for svc in critical_services:
        if run_cmd(['systemctl', 'is-active', svc]) != 'active':
            services_down += 1

    # Calculate overall score (0-100)
    score = 100

    # Deduct for down modules
    for mod_name, mod_info in modules.items():
        if mod_info.get("status") == "error":
            score -= 15
        elif mod_info.get("status") == "warn":
            score -= 5

    # Deduct for high resource usage
    if cpu_pct > 85:
        score -= 10
    elif cpu_pct > 70:
        score -= 5

    if mem_pct > 90:
        score -= 10
    elif mem_pct > 80:
        score -= 5

    if disk_pct > 85:
        score -= 10
    elif disk_pct > 75:
        score -= 5

    # Deduct for high WAF blocking
    if blocked_pct > 25:
        score -= 5

    score = max(0, min(100, score))

    return {
        "score": score,
        "modules": modules,
        "waf": {
            "blocked_pct": blocked_pct,
            "active": waf_stats.get("mitmproxy_running", False)
        },
        "crowdsec": {
            "active_decisions": waf_stats.get("active_bans", 0),
            "alerts_today": waf_stats.get("alerts_today", 0)
        },
        "system": {
            "cpu": cpu_pct,
            "memory": mem_pct,
            "disk": disk_pct,
            "load": overview.get("load", "0 0 0"),
            "uptime": overview.get("uptime", 0)
        },
        "services": {
            "down": services_down,
            "total": len(critical_services),
            "lxc_running": overview.get("lxc_containers", 0)
        },
        "counts": {
            "vhosts": overview.get("vhosts", 0),
            "certificates": overview.get("certificates", 0),
            "metablogs": overview.get("metablogs", 0)
        },
        "_cache": {
            "age": get_cache_age(),
            "fresh": cache_is_fresh()
        },
        "timestamp": datetime.now().isoformat()
    }


# ═══════════════════════════════════════════════════════════════════════════════
# SSL CERTIFICATE STATUS
# ═══════════════════════════════════════════════════════════════════════════════

def get_ssl_status(domain: str) -> dict:
    """
    Get SSL certificate status for a domain.

    Thresholds (aggressive for Let's Encrypt 90-day certs):
    - ok: > 7 days remaining
    - warn: 3-7 days remaining
    - error: < 3 days remaining
    - expired: <= 0 days remaining
    """
    if not domain:
        return {"domain": None, "days_remaining": None, "status": "unknown", "expiry": None}

    parent_domain = '.'.join(domain.split('.')[1:]) if '.' in domain else domain
    cert_paths = [
        Path(f"/data/haproxy/certs/{domain}.pem"),  # HAProxy certs (primary)
        Path(f"/data/haproxy/certs/_wildcard_.{parent_domain}.pem"),  # Wildcard certs
        Path(f"/etc/letsencrypt/live/{domain}/cert.pem"),
        Path(f"/etc/letsencrypt/live/{parent_domain}/cert.pem"),
        Path(f"/etc/haproxy/certs/{domain}.pem"),
        Path(f"/etc/nginx/ssl/{domain}.crt"),
    ]

    cert_path = None
    for p in cert_paths:
        try:
            if p.exists():
                cert_path = p
                break
        except PermissionError:
            # Can't access this path, try next
            continue

    if not cert_path:
        return {"domain": domain, "days_remaining": None, "status": "unknown", "expiry": None}

    try:
        cert_data = cert_path.read_bytes()
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())
        now = datetime.now(timezone.utc)
        expiry = cert.not_valid_after_utc
        days_remaining = (expiry - now).days

        if days_remaining <= 0:
            status = "expired"
        elif days_remaining < 3:
            status = "error"
        elif days_remaining <= 7:
            status = "warn"
        else:
            status = "ok"

        return {"domain": domain, "days_remaining": days_remaining, "status": status, "expiry": expiry.isoformat()}
    except Exception as e:
        return {"domain": domain, "days_remaining": None, "status": "unknown", "expiry": None, "error": str(e)}


@app.get("/api/v1/metrics/health/summary")
async def get_health_summary(request: Request, domain: Optional[str] = None):
    """
    Health summary for the global health banner.
    Returns aggregated health score and module statuses.
    No auth required for banner display.

    Args:
        domain: Optional domain to check SSL certificate for. If not provided,
                falls back to the Host header.
    """
    summary = build_health_summary()

    # Add SSL certificate status for the specified domain or Host header
    ssl_domain = domain or request.headers.get("host", "").split(":")[0]
    if ssl_domain:
        summary["ssl"] = get_ssl_status(ssl_domain)
    else:
        summary["ssl"] = None

    return summary

@app.get("/api/v1/metrics/visitor-origin")
async def visitor_origin_endpoint():
    return JSONResponse(
        content=visitor_origin_agg.current(),
        headers={"Cache-Control": "public, max-age=300"},
    )


@app.get("/api/v1/metrics/live-hosts")
async def live_hosts_endpoint():
    return JSONResponse(
        content=live_hosts_agg.current(),
        headers={"Cache-Control": "public, max-age=300"},
    )


@app.get("/api/v1/metrics/cert-status")
async def cert_status_endpoint():
    return JSONResponse(
        content=cert_status_agg.current(),
        headers={"Cache-Control": "public, max-age=300"},
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
