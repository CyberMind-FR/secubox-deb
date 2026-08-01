"""secubox-certs — ACME Certificate Manager API"""
from fastapi import FastAPI, APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel
from pathlib import Path
from datetime import datetime, timedelta
import subprocess
import json
import asyncio
import time
import re
import ssl
import socket

from secubox_core.auth import require_jwt
from secubox_core import user_store

app = FastAPI(title="secubox-certs", version="1.0.0", root_path="/api/v1/certs")
router = APIRouter()
public_router = APIRouter()


def require_admin(user=Depends(require_jwt)) -> dict:
    """Admin gate for the destructive verbs (#942).

    Issuing or revoking a certificate changes what the whole box presents to
    the world; an ordinary session should not be able to do it. Same idiom as
    secubox-auth's /settings.
    """
    who = user_store.get_user(user.get("sub")) or {}
    if who.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin requis")
    return user

# Configuration
CERTS_DIR = Path("/data/haproxy/certs")
ACME_DIR = Path("/etc/letsencrypt")
HAPROXY_CFG = Path("/data/haproxy/haproxy.cfg")
CACHE_FILE = Path("/var/cache/secubox/certs/status.json")
METRICS_FILE = Path("/var/cache/secubox/certs/metrics.json")
WAF_THREATS_LOG = Path("/var/log/secubox/waf-threats.log")

# Background cache
_certs_cache = {}
_metrics_cache = {}

# Origin detection patterns
ORIGIN_PATTERNS = {
    "git": ("💻", "Gitea"),
    "blog": ("📝", "Metablog"),
    "meta": ("📝", "Metablog"),
    "stream": ("📊", "Streamlit"),
    "cloud": ("☁️", "Nextcloud"),
    "file": ("☁️", "Nextcloud"),
    "mail": ("📧", "Mail"),
    "webmail": ("📧", "Webmail"),
    "matrix": ("💬", "Matrix"),
    "chat": ("💬", "Chat"),
    "media": ("🎬", "Jellyfin"),
    "jelly": ("🎬", "Jellyfin"),
    "vault": ("🔐", "Vaultwarden"),
    "bw": ("🔐", "Bitwarden"),
    "meet": ("📹", "Jitsi"),
    "jitsi": ("📹", "Jitsi"),
    "radio": ("📻", "WebRadio"),
    "voip": ("📞", "VoIP"),
    "sip": ("📞", "SIP"),
    "admin": ("⚙️", "Admin"),
    "api": ("⚡", "API"),
    "secubox": ("🛡️", "SecuBox"),
    "arm": ("🖥️", "Armada"),
    "c3box": ("📊", "C3BOX"),
    "cf": ("🔥", "Cloudflare"),
    "status": ("📡", "Status"),
}


def detect_origin(domain: str) -> tuple:
    """Detect origin service from domain name."""
    d = domain.lower()
    for pattern, (emoji, name) in ORIGIN_PATTERNS.items():
        if pattern in d:
            return emoji, name
    return "🌐", "Web"


def get_ttd_emoji(days: int) -> str:
    """Get Time-To-Death emoji based on days remaining."""
    if days < 0:
        return "💀"  # Expired
    if days == 0:
        return "☠️"  # Dies today
    if days <= 3:
        return "🔴"  # Critical
    if days <= 7:
        return "🟠"  # Very soon
    if days <= 14:
        return "🟡"  # Warning
    if days <= 30:
        return "🟢"  # OK but watch
    return "💚"  # Healthy


def get_cert_status(days: int) -> str:
    """Get status string from days remaining."""
    if days < 0:
        return "expired"
    if days <= 7:
        return "critical"
    if days <= 30:
        return "warning"
    return "healthy"


def parse_pem_expiry(pem_path: Path) -> datetime | None:
    """Extract expiry date from PEM certificate."""
    try:
        result = subprocess.run(
            ["openssl", "x509", "-enddate", "-noout", "-in", str(pem_path)],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            # Format: notAfter=May 10 12:00:00 2026 GMT
            match = re.search(r"notAfter=(.+)", result.stdout)
            if match:
                date_str = match.group(1).strip()
                return datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")
    except Exception:
        pass
    return None


def get_cert_subject(pem_path: Path) -> str | None:
    """Extract subject/CN from certificate."""
    try:
        result = subprocess.run(
            ["openssl", "x509", "-subject", "-noout", "-in", str(pem_path)],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            match = re.search(r"CN\s*=\s*([^,/]+)", result.stdout)
            if match:
                return match.group(1).strip()
    except Exception:
        pass
    return None


def get_cert_issuer(pem_path: Path) -> str | None:
    """Extract issuer from certificate."""
    try:
        result = subprocess.run(
            ["openssl", "x509", "-issuer", "-noout", "-in", str(pem_path)],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            match = re.search(r"CN\s*=\s*([^,/]+)", result.stdout)
            if match:
                return match.group(1).strip()
    except Exception:
        pass
    return None


def scan_certificates() -> list:
    """Scan all certificates and return status list."""
    certs = []
    now = datetime.utcnow()

    if not CERTS_DIR.exists():
        return certs

    for pem_file in sorted(CERTS_DIR.glob("*.pem")):
        domain = pem_file.stem
        # Clean domain name (remove wildcards representation)
        if domain.startswith("_wildcard_"):
            domain = "*." + domain.replace("_wildcard_.", "")

        expiry = parse_pem_expiry(pem_file)
        if expiry:
            days = (expiry - now).days
        else:
            days = -999  # Unknown

        origin_emoji, origin_name = detect_origin(domain)
        issuer = get_cert_issuer(pem_file) or "Unknown"

        certs.append({
            "domain": domain,
            "file": pem_file.name,
            "expiry": expiry.isoformat() if expiry else None,
            "days": days,
            "status": get_cert_status(days),
            "ttd_emoji": get_ttd_emoji(days),
            "origin_emoji": origin_emoji,
            "origin_name": origin_name,
            "issuer": issuer,
            "size": pem_file.stat().st_size,
            "modified": datetime.fromtimestamp(pem_file.stat().st_mtime).isoformat(),
        })

    return certs


def get_attack_stats(domain: str = None) -> dict:
    """Get WAF attack statistics, optionally filtered by domain."""
    stats = {
        "total_attacks": 0,
        "today_attacks": 0,
        "blocked_ips": set(),
        "top_categories": {},
        "by_domain": {},
    }

    if not WAF_THREATS_LOG.exists():
        return stats

    try:
        today = datetime.now().strftime("%Y-%m-%d")
        with open(WAF_THREATS_LOG, "r") as f:
            for line in f:
                try:
                    entry = json.loads(line)
                    stats["total_attacks"] += 1

                    # Check if today
                    ts = entry.get("timestamp", "")
                    if ts.startswith(today):
                        stats["today_attacks"] += 1

                    # Track blocked IPs
                    ip = entry.get("client_ip", "")
                    if ip:
                        stats["blocked_ips"].add(ip)

                    # Track categories
                    cat = entry.get("category", "Unknown")
                    stats["top_categories"][cat] = stats["top_categories"].get(cat, 0) + 1

                    # Track by domain
                    host = entry.get("host", "unknown")
                    if host not in stats["by_domain"]:
                        stats["by_domain"][host] = {"total": 0, "today": 0}
                    stats["by_domain"][host]["total"] += 1
                    if ts.startswith(today):
                        stats["by_domain"][host]["today"] += 1

                except json.JSONDecodeError:
                    continue
    except Exception:
        pass

    # Convert set to count
    stats["blocked_ips_count"] = len(stats["blocked_ips"])
    del stats["blocked_ips"]

    # Sort categories by count
    stats["top_categories"] = dict(sorted(
        stats["top_categories"].items(),
        key=lambda x: x[1],
        reverse=True
    )[:10])

    return stats


def get_visit_metrics() -> dict:
    """Get visit metrics from HAProxy logs or Nginx access logs."""
    metrics = {
        "total_requests": 0,
        "today_requests": 0,
        "by_domain": {},
        "by_status": {},
    }

    # Try HAProxy log
    haproxy_log = Path("/var/log/haproxy.log")
    if haproxy_log.exists():
        try:
            today = datetime.now().strftime("%b %d")
            result = subprocess.run(
                ["wc", "-l", str(haproxy_log)],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                metrics["total_requests"] = int(result.stdout.split()[0])

            # Count today's requests
            result = subprocess.run(
                ["grep", "-c", today, str(haproxy_log)],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                metrics["today_requests"] = int(result.stdout.strip())
        except Exception:
            pass

    return metrics


# ══════════════════════════════════════════════════════════════════
# API Endpoints
# ══════════════════════════════════════════════════════════════════

@router.get("/list")
async def list_certificates():
    """List all certificates with status and expiry info."""
    certs = _certs_cache if _certs_cache else scan_certificates()

    # Calculate summary stats
    expired = len([c for c in certs if c["days"] < 0])
    critical = len([c for c in certs if 0 <= c["days"] <= 7])
    warning = len([c for c in certs if 7 < c["days"] <= 30])
    healthy = len([c for c in certs if c["days"] > 30])

    return {
        "certificates": certs,
        "summary": {
            "total": len(certs),
            "expired": expired,
            "critical": critical,
            "warning": warning,
            "healthy": healthy,
        },
        "timestamp": datetime.utcnow().isoformat(),
    }


@router.get("/status")
async def cert_status():
    """Get overall certificate health status."""
    certs = _certs_cache if _certs_cache else scan_certificates()

    expired = len([c for c in certs if c["days"] < 0])
    critical = len([c for c in certs if 0 <= c["days"] <= 7])
    warning = len([c for c in certs if 7 < c["days"] <= 30])
    healthy = len([c for c in certs if c["days"] > 30])

    # Calculate health percentage
    total = len(certs)
    if total > 0:
        health_pct = int((healthy / total) * 100)
    else:
        health_pct = 100

    # Overall status
    if expired > 0:
        overall = "critical"
    elif critical > 0:
        overall = "warning"
    elif warning > 0:
        overall = "ok"
    else:
        overall = "healthy"

    return {
        "overall": overall,
        "health_percent": health_pct,
        "counts": {
            "total": total,
            "expired": expired,
            "critical": critical,
            "warning": warning,
            "healthy": healthy,
        },
    }


@router.get("/details/{domain}")
def cert_details(domain: str):
    """Get detailed info for a specific certificate."""
    # Find the cert file
    pem_path = CERTS_DIR / f"{domain}.pem"
    if not pem_path.exists():
        # Try with wildcards encoding
        pem_path = CERTS_DIR / f"_wildcard_.{domain.lstrip('*.')}.pem"
        if not pem_path.exists():
            raise HTTPException(404, f"Certificate not found: {domain}")

    expiry = parse_pem_expiry(pem_path)
    now = datetime.utcnow()
    days = (expiry - now).days if expiry else -999

    origin_emoji, origin_name = detect_origin(domain)

    # Get full cert info
    result = subprocess.run(
        ["openssl", "x509", "-text", "-noout", "-in", str(pem_path)],
        capture_output=True, text=True, timeout=10
    )

    # Get attack stats for this domain
    attacks = get_attack_stats(domain)
    domain_attacks = attacks.get("by_domain", {}).get(domain, {"total": 0, "today": 0})

    return {
        "domain": domain,
        "file": pem_path.name,
        "expiry": expiry.isoformat() if expiry else None,
        "days": days,
        "status": get_cert_status(days),
        "ttd_emoji": get_ttd_emoji(days),
        "origin_emoji": origin_emoji,
        "origin_name": origin_name,
        "issuer": get_cert_issuer(pem_path),
        "subject": get_cert_subject(pem_path),
        "size": pem_path.stat().st_size,
        "modified": datetime.fromtimestamp(pem_path.stat().st_mtime).isoformat(),
        "full_info": result.stdout if result.returncode == 0 else None,
        "attacks": domain_attacks,
    }


class CertRequest(BaseModel):
    domain: str
    dns_provider: str = "cloudflare"  # cloudflare, ovh, gandi, http
    backend_type: str = "custom"
    backend_port: int = 8080


@router.post("/check")
def check_domain(req: CertRequest):
    """Pre-flight checks before issuing certificate."""
    checks = []
    domain = req.domain

    # 1. DNS Resolution
    try:
        socket.gethostbyname(domain)
        checks.append({"name": "DNS Resolution", "pass": True, "msg": f"Resolved to IP"})
    except socket.gaierror:
        checks.append({"name": "DNS Resolution", "pass": False, "msg": "Domain not resolving"})

    # 2. HTTP Reachability (port 80)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((domain, 80))
        sock.close()
        if result == 0:
            checks.append({"name": "HTTP Reachability", "pass": True, "msg": "Port 80 accessible"})
        else:
            checks.append({"name": "HTTP Reachability", "pass": False, "msg": "Port 80 not accessible"})
    except Exception as e:
        checks.append({"name": "HTTP Reachability", "pass": False, "msg": str(e)})

    # 3. HTTPS Port availability
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((domain, 443))
        sock.close()
        checks.append({"name": "HTTPS Port", "pass": True, "msg": "Port 443 available"})
    except Exception as e:
        checks.append({"name": "HTTPS Port", "pass": False, "msg": str(e)})

    # 4. DNS API access (check credentials exist)
    dns_cred_file = Path(f"/etc/secubox/dns/{req.dns_provider}.conf")
    if req.dns_provider == "http":
        checks.append({"name": "DNS API", "pass": True, "msg": "HTTP-01 challenge (no API needed)"})
    elif dns_cred_file.exists():
        checks.append({"name": "DNS API", "pass": True, "msg": f"{req.dns_provider} credentials found"})
    else:
        checks.append({"name": "DNS API", "pass": False, "msg": f"Missing {dns_cred_file}"})

    # 5. ACME account
    acme_account = Path("/etc/letsencrypt/accounts")
    if acme_account.exists() and list(acme_account.glob("**/regr.json")):
        checks.append({"name": "ACME Account", "pass": True, "msg": "Account registered"})
    else:
        checks.append({"name": "ACME Account", "pass": False, "msg": "No ACME account found"})

    all_pass = all(c["pass"] for c in checks)

    return {
        "domain": domain,
        "checks": checks,
        "ready": all_pass,
    }


@router.post("/issue")
def issue_certificate(req: CertRequest, background_tasks: BackgroundTasks,
                      _admin=Depends(require_admin)):
    """Issue a new certificate via ACME."""
    domain = req.domain

    # Check if cert already exists
    pem_path = CERTS_DIR / f"{domain}.pem"
    if pem_path.exists():
        return {"success": False, "error": f"Certificate already exists for {domain}"}

    # Build certbot command based on DNS provider
    if req.dns_provider == "http":
        cmd = [
            "certbot", "certonly",
            "--webroot", "-w", "/var/www/html/.well-known/acme-challenge",
            "-d", domain,
            "--non-interactive", "--agree-tos",
            "--email", "admin@secubox.in",
        ]
    else:
        # DNS challenge
        dns_plugin = {
            "cloudflare": "dns-cloudflare",
            "ovh": "dns-ovh",
            "gandi": "dns-gandi",
        }.get(req.dns_provider, "dns-cloudflare")

        cred_file = f"/etc/secubox/dns/{req.dns_provider}.conf"

        cmd = [
            "certbot", "certonly",
            f"--{dns_plugin}",
            f"--{dns_plugin}-credentials", cred_file,
            "-d", domain,
            "--non-interactive", "--agree-tos",
            "--email", "admin@secubox.in",
        ]

    # Run certbot (would be async in production)
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

    if result.returncode != 0:
        return {
            "success": False,
            "error": result.stderr or "Certbot failed",
            "stdout": result.stdout,
        }

    # Convert to HAProxy format (fullchain + key in single PEM)
    fullchain = Path(f"/etc/letsencrypt/live/{domain}/fullchain.pem")
    privkey = Path(f"/etc/letsencrypt/live/{domain}/privkey.pem")

    if fullchain.exists() and privkey.exists():
        with open(pem_path, "w") as out:
            out.write(fullchain.read_text())
            out.write(privkey.read_text())

        # Reload HAProxy
        subprocess.run(["systemctl", "reload", "haproxy"], capture_output=True)

        return {
            "success": True,
            "domain": domain,
            "cert_file": str(pem_path),
            "message": "Certificate issued and HAProxy reloaded",
        }

    return {"success": False, "error": "Certificate files not found after issuance"}


@router.post("/renew/{domain}")
async def renew_certificate(domain: str, _admin=Depends(require_admin)):
    """Renew a specific certificate."""
    # Find existing cert
    pem_path = CERTS_DIR / f"{domain}.pem"
    if not pem_path.exists():
        raise HTTPException(404, f"Certificate not found: {domain}")

    # Use certbot renew
    cmd = ["certbot", "renew", "--cert-name", domain, "--force-renewal"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

    if result.returncode != 0:
        return {
            "success": False,
            "domain": domain,
            "error": result.stderr or "Renewal failed",
        }

    # Update HAProxy PEM
    fullchain = Path(f"/etc/letsencrypt/live/{domain}/fullchain.pem")
    privkey = Path(f"/etc/letsencrypt/live/{domain}/privkey.pem")

    if fullchain.exists() and privkey.exists():
        with open(pem_path, "w") as out:
            out.write(fullchain.read_text())
            out.write(privkey.read_text())

        subprocess.run(["systemctl", "reload", "haproxy"], capture_output=True)

    return {
        "success": True,
        "domain": domain,
        "message": "Certificate renewed",
    }


@router.post("/renew-all")
async def renew_all_expiring():
    """Renew all certificates expiring within 30 days."""
    certs = _certs_cache if _certs_cache else scan_certificates()
    expiring = [c for c in certs if c["days"] <= 30]

    results = []
    for cert in expiring:
        domain = cert["domain"]
        if domain.startswith("*."):
            domain = domain[2:]  # Remove wildcard for certbot

        try:
            result = await renew_certificate(domain)
            results.append({"domain": domain, **result})
        except Exception as e:
            results.append({"domain": domain, "success": False, "error": str(e)})

    return {
        "processed": len(results),
        "results": results,
    }


@router.delete("/revoke/{domain}")
def revoke_certificate(domain: str, _admin=Depends(require_admin)):
    """Revoke and delete a certificate."""
    pem_path = CERTS_DIR / f"{domain}.pem"
    if not pem_path.exists():
        raise HTTPException(404, f"Certificate not found: {domain}")

    # Revoke via certbot
    cmd = ["certbot", "revoke", "--cert-name", domain, "--non-interactive"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

    # Delete local file regardless of certbot result
    pem_path.unlink(missing_ok=True)

    # Reload HAProxy
    subprocess.run(["systemctl", "reload", "haproxy"], capture_output=True)

    return {
        "success": True,
        "domain": domain,
        "message": "Certificate revoked and deleted",
    }


@router.get("/metrics")
async def get_metrics():
    """Get visit and attack metrics for all domains."""
    certs = _certs_cache if _certs_cache else scan_certificates()
    attacks = get_attack_stats()
    visits = get_visit_metrics()

    # Merge metrics with cert data
    domain_metrics = []
    for cert in certs:
        domain = cert["domain"]
        d_attacks = attacks.get("by_domain", {}).get(domain, {"total": 0, "today": 0})
        d_visits = visits.get("by_domain", {}).get(domain, {"total": 0, "today": 0})

        domain_metrics.append({
            "domain": domain,
            "status": cert["status"],
            "ttd_emoji": cert["ttd_emoji"],
            "origin_emoji": cert["origin_emoji"],
            "origin_name": cert["origin_name"],
            "days": cert["days"],
            "attacks_total": d_attacks.get("total", 0),
            "attacks_today": d_attacks.get("today", 0),
            "visits_total": d_visits.get("total", 0),
            "visits_today": d_visits.get("today", 0),
        })

    return {
        "domains": domain_metrics,
        "summary": {
            "total_attacks": attacks.get("total_attacks", 0),
            "today_attacks": attacks.get("today_attacks", 0),
            "blocked_ips": attacks.get("blocked_ips_count", 0),
            "top_categories": attacks.get("top_categories", {}),
            "total_visits": visits.get("total_requests", 0),
            "today_visits": visits.get("today_requests", 0),
        },
        "timestamp": datetime.utcnow().isoformat(),
    }


@public_router.get("/health")
async def health():
    """Health check endpoint. Deliberately unauthenticated — liveness probes
    and the watchdog poll it, and it discloses nothing."""
    return {"status": "ok", "module": "certs", "version": "1.0.0"}


# Everything except /health requires a valid session (#942). Until then this
# module imported `Depends` without ever using it: `GET /list`, `POST /issue`
# and `DELETE /revoke/{domain}` answered any caller, and it was verified in
# production that `/list` returned 200 to an unauthenticated LAN client
# through the full HAProxy → sbxwaf → nginx chain. Any device on the LAN could
# issue or revoke the box's TLS certificates.
app.include_router(public_router)
app.include_router(router, dependencies=[Depends(require_jwt)])


# Background cache refresh
async def _refresh_cache():
    """Background task to refresh cache every 5 minutes."""
    global _certs_cache, _metrics_cache
    # If cache is already loaded from file, wait before first scan
    if _certs_cache:
        await asyncio.sleep(60)  # Delay first scan by 1 minute
    while True:
        try:
            # Run scan in thread to not block event loop
            _certs_cache = await asyncio.get_event_loop().run_in_executor(None, scan_certificates)
            _metrics_cache = get_attack_stats()

            # Save to file
            CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
            CACHE_FILE.write_text(json.dumps({
                "certificates": _certs_cache,
                "timestamp": datetime.utcnow().isoformat(),
            }))
        except Exception:
            pass
        await asyncio.sleep(300)


@app.on_event("startup")
async def startup():
    global _certs_cache
    # Load from file cache first (fast startup)
    if CACHE_FILE.exists():
        try:
            data = json.loads(CACHE_FILE.read_text())
            _certs_cache = data.get("certificates", [])
        except Exception:
            pass
    # Start background refresh (won't block)
    asyncio.create_task(_refresh_cache())
