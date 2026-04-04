"""SecuBox OpenClaw API - OSINT Intelligence Gathering

Open Source Intelligence (OSINT) tool for reconnaissance and information gathering:
- Domain reconnaissance
- IP intelligence
- Email harvesting detection
- Social media footprint
- DNS enumeration
- Whois lookup
- Subdomain discovery
- Certificate transparency
- Shodan/Censys integration
"""
import asyncio
import subprocess
import re
import os
import json
import socket
import time
import uuid
import hashlib
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from enum import Enum
from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks, Query
from fastapi.responses import Response
from pydantic import BaseModel, Field
import httpx
from secubox_core.auth import require_jwt
from secubox_core.config import get_config

app = FastAPI(title="SecuBox OpenClaw", version="1.0.0")
config = get_config("openclaw")

# Data directories
DATA_DIR = Path("/var/lib/secubox/openclaw")
SCANS_DIR = DATA_DIR / "scans"
CONFIG_FILE = DATA_DIR / "config.json"
CACHE_DIR = Path("/var/cache/secubox/openclaw")

# Ensure directories exist
DATA_DIR.mkdir(parents=True, exist_ok=True)
SCANS_DIR.mkdir(parents=True, exist_ok=True)
CACHE_DIR.mkdir(parents=True, exist_ok=True)

# Default configuration
DEFAULT_CONFIG = {
    "shodan_api_key": "",
    "censys_api_id": "",
    "censys_api_secret": "",
    "virustotal_api_key": "",
    "securitytrails_api_key": "",
    "max_concurrent_scans": 3,
    "scan_timeout": 300,
    "cache_ttl": 3600,
    "dns_servers": ["8.8.8.8", "1.1.1.1"],
    "user_agent": "SecuBox-OpenClaw/1.0 OSINT Scanner"
}


class ScanType(str, Enum):
    DOMAIN = "domain"
    IP = "ip"
    EMAIL = "email"


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ScanRequest(BaseModel):
    target: str
    scan_type: ScanType = ScanType.DOMAIN
    options: Optional[Dict[str, Any]] = None


class ConfigUpdate(BaseModel):
    shodan_api_key: Optional[str] = None
    censys_api_id: Optional[str] = None
    censys_api_secret: Optional[str] = None
    virustotal_api_key: Optional[str] = None
    securitytrails_api_key: Optional[str] = None
    max_concurrent_scans: Optional[int] = None
    scan_timeout: Optional[int] = None
    cache_ttl: Optional[int] = None
    dns_servers: Optional[List[str]] = None


class ExportRequest(BaseModel):
    scan_id: str
    format: str = "json"  # json, csv, xml


# Configuration management
def _load_config() -> Dict:
    """Load configuration."""
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE) as f:
                cfg = json.load(f)
                return {**DEFAULT_CONFIG, **cfg}
        except Exception:
            pass
    return DEFAULT_CONFIG.copy()


def _save_config(cfg: Dict):
    """Save configuration."""
    with open(CONFIG_FILE, 'w') as f:
        json.dump(cfg, f, indent=2)


# Scan management
def _load_scan(scan_id: str) -> Optional[Dict]:
    """Load a scan by ID."""
    scan_file = SCANS_DIR / f"{scan_id}.json"
    if scan_file.exists():
        try:
            with open(scan_file) as f:
                return json.load(f)
        except Exception:
            pass
    return None


def _save_scan(scan: Dict):
    """Save a scan."""
    scan_file = SCANS_DIR / f"{scan['id']}.json"
    with open(scan_file, 'w') as f:
        json.dump(scan, f, indent=2)


def _list_scans(limit: int = 50) -> List[Dict]:
    """List all scans, most recent first."""
    scans = []
    for f in SCANS_DIR.glob("*.json"):
        try:
            with open(f) as fp:
                scan = json.load(fp)
                scans.append({
                    "id": scan.get("id"),
                    "target": scan.get("target"),
                    "type": scan.get("type"),
                    "status": scan.get("status"),
                    "created_at": scan.get("created_at"),
                    "completed_at": scan.get("completed_at"),
                    "findings_count": len(scan.get("results", {}).get("findings", []))
                })
        except Exception:
            pass
    scans.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    return scans[:limit]


# DNS enumeration
async def _dns_lookup(domain: str, record_type: str = "A") -> List[str]:
    """Perform DNS lookup."""
    results = []
    try:
        proc = await asyncio.create_subprocess_exec(
            "dig", "+short", domain, record_type,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
        for line in stdout.decode().strip().split('\n'):
            if line:
                results.append(line.strip())
    except Exception:
        pass
    return results


async def _dns_enumeration(domain: str) -> Dict:
    """Full DNS enumeration."""
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "PTR", "SRV"]
    results = {}

    tasks = []
    for rtype in record_types:
        tasks.append(_dns_lookup(domain, rtype))

    records = await asyncio.gather(*tasks)

    for rtype, values in zip(record_types, records):
        if values:
            results[rtype] = values

    return results


# Whois lookup
async def _whois_lookup(target: str) -> Dict:
    """Perform WHOIS lookup."""
    result = {
        "raw": "",
        "parsed": {},
        "error": None
    }

    try:
        proc = await asyncio.create_subprocess_exec(
            "whois", target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
        result["raw"] = stdout.decode()

        # Parse common fields
        raw = result["raw"]
        patterns = {
            "registrar": r"Registrar:\s*(.+)",
            "creation_date": r"Creation Date:\s*(.+)",
            "expiry_date": r"(?:Expir(?:y|ation) Date|Registry Expiry Date):\s*(.+)",
            "updated_date": r"Updated Date:\s*(.+)",
            "name_servers": r"Name Server:\s*(.+)",
            "status": r"Status:\s*(.+)",
            "registrant_org": r"Registrant Organization:\s*(.+)",
            "registrant_country": r"Registrant Country:\s*(.+)",
            "admin_email": r"Admin Email:\s*(.+)",
            "tech_email": r"Tech Email:\s*(.+)",
        }

        for key, pattern in patterns.items():
            matches = re.findall(pattern, raw, re.IGNORECASE)
            if matches:
                result["parsed"][key] = matches if len(matches) > 1 else matches[0]

    except asyncio.TimeoutError:
        result["error"] = "Timeout"
    except Exception as e:
        result["error"] = str(e)

    return result


# Subdomain discovery
async def _discover_subdomains(domain: str) -> List[str]:
    """Discover subdomains using various techniques."""
    subdomains = set()

    # Common subdomains to check
    common_prefixes = [
        "www", "mail", "ftp", "webmail", "smtp", "pop", "imap", "blog",
        "admin", "administrator", "api", "app", "apps", "beta", "cdn",
        "cloud", "cpanel", "dashboard", "db", "dev", "download", "files",
        "forum", "git", "gitlab", "help", "images", "img", "info", "intranet",
        "jenkins", "jira", "login", "m", "mobile", "mysql", "news", "ns",
        "ns1", "ns2", "ns3", "old", "panel", "portal", "proxy", "remote",
        "search", "secure", "server", "shop", "ssl", "staging", "static",
        "status", "store", "support", "test", "vpn", "web", "wiki", "www2"
    ]

    async def check_subdomain(sub: str) -> Optional[str]:
        full = f"{sub}.{domain}"
        try:
            socket.gethostbyname(full)
            return full
        except socket.gaierror:
            return None

    # Check common subdomains in parallel
    tasks = [check_subdomain(sub) for sub in common_prefixes]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for result in results:
        if result and not isinstance(result, Exception):
            subdomains.add(result)

    # Try zone transfer (usually fails but worth trying)
    try:
        ns_records = await _dns_lookup(domain, "NS")
        for ns in ns_records[:2]:  # Try first 2 NS servers
            try:
                proc = await asyncio.create_subprocess_exec(
                    "dig", f"@{ns}", domain, "AXFR",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
                for line in stdout.decode().split('\n'):
                    match = re.match(rf"(\S+\.{re.escape(domain)})\.", line)
                    if match:
                        subdomains.add(match.group(1))
            except Exception:
                pass
    except Exception:
        pass

    return sorted(list(subdomains))


# Certificate transparency
async def _cert_transparency(domain: str) -> List[Dict]:
    """Query certificate transparency logs."""
    certs = []
    cfg = _load_config()

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            # Query crt.sh
            response = await client.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                headers={"User-Agent": cfg.get("user_agent", DEFAULT_CONFIG["user_agent"])}
            )
            if response.status_code == 200:
                data = response.json()
                seen = set()
                for entry in data[:100]:  # Limit to 100 entries
                    name = entry.get("name_value", "")
                    if name not in seen:
                        seen.add(name)
                        certs.append({
                            "name": name,
                            "issuer": entry.get("issuer_name", ""),
                            "not_before": entry.get("not_before", ""),
                            "not_after": entry.get("not_after", ""),
                            "serial": entry.get("serial_number", "")
                        })
    except Exception:
        pass

    return certs


# IP intelligence
async def _ip_intelligence(ip: str) -> Dict:
    """Gather intelligence about an IP address."""
    info = {
        "ip": ip,
        "reverse_dns": [],
        "geolocation": {},
        "asn": {},
        "ports": [],
        "reputation": {}
    }

    # Reverse DNS
    try:
        proc = await asyncio.create_subprocess_exec(
            "dig", "+short", "-x", ip,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
        for line in stdout.decode().strip().split('\n'):
            if line:
                info["reverse_dns"].append(line.strip().rstrip('.'))
    except Exception:
        pass

    # ASN lookup using Team Cymru
    try:
        reversed_ip = '.'.join(reversed(ip.split('.')))
        proc = await asyncio.create_subprocess_exec(
            "dig", "+short", f"{reversed_ip}.origin.asn.cymru.com", "TXT",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
        output = stdout.decode().strip().replace('"', '')
        if output:
            parts = output.split('|')
            if len(parts) >= 3:
                info["asn"] = {
                    "number": parts[0].strip(),
                    "prefix": parts[1].strip(),
                    "country": parts[2].strip()
                }
    except Exception:
        pass

    return info


# Email reconnaissance
async def _email_recon(email: str) -> Dict:
    """Reconnaissance on email address."""
    info = {
        "email": email,
        "valid_format": False,
        "domain": "",
        "mx_records": [],
        "spf": "",
        "dmarc": "",
        "breaches": []
    }

    # Validate format
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    info["valid_format"] = bool(re.match(email_pattern, email))

    if not info["valid_format"]:
        return info

    # Extract domain
    domain = email.split('@')[1]
    info["domain"] = domain

    # MX records
    info["mx_records"] = await _dns_lookup(domain, "MX")

    # SPF record
    txt_records = await _dns_lookup(domain, "TXT")
    for txt in txt_records:
        if "v=spf1" in txt:
            info["spf"] = txt
            break

    # DMARC record
    dmarc_records = await _dns_lookup(f"_dmarc.{domain}", "TXT")
    for txt in dmarc_records:
        if "v=DMARC1" in txt:
            info["dmarc"] = txt
            break

    return info


# Shodan integration
async def _shodan_lookup(target: str, api_key: str) -> Dict:
    """Query Shodan for target."""
    if not api_key:
        return {"error": "Shodan API key not configured"}

    results = {}
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            # Determine if IP or domain
            try:
                socket.inet_aton(target)
                endpoint = f"https://api.shodan.io/shodan/host/{target}"
            except socket.error:
                endpoint = f"https://api.shodan.io/dns/resolve"
                params = {"hostnames": target, "key": api_key}
                response = await client.get(endpoint, params=params)
                if response.status_code == 200:
                    data = response.json()
                    if target in data:
                        target = data[target]
                        endpoint = f"https://api.shodan.io/shodan/host/{target}"
                    else:
                        return {"error": "Could not resolve domain"}

            response = await client.get(endpoint, params={"key": api_key})
            if response.status_code == 200:
                results = response.json()
            elif response.status_code == 404:
                results = {"error": "No information available"}
            else:
                results = {"error": f"Shodan API error: {response.status_code}"}
    except Exception as e:
        results = {"error": str(e)}

    return results


# Port scanning (basic, non-intrusive)
async def _port_check(ip: str, port: int, timeout: float = 2.0) -> bool:
    """Check if a port is open."""
    try:
        conn = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False


async def _scan_common_ports(ip: str) -> List[Dict]:
    """Scan common ports."""
    common_ports = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        993: "IMAPS",
        995: "POP3S",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        6379: "Redis",
        8080: "HTTP-Proxy",
        8443: "HTTPS-Alt",
        27017: "MongoDB"
    }

    open_ports = []

    async def check_port(port: int, service: str):
        if await _port_check(ip, port):
            return {"port": port, "service": service, "state": "open"}
        return None

    tasks = [check_port(port, service) for port, service in common_ports.items()]
    results = await asyncio.gather(*tasks)

    for result in results:
        if result:
            open_ports.append(result)

    return sorted(open_ports, key=lambda x: x["port"])


# Reputation check
async def _check_reputation(target: str) -> Dict:
    """Check target reputation against various sources."""
    reputation = {
        "target": target,
        "blacklists": [],
        "score": "unknown"
    }

    # Check common RBLs for IP
    try:
        socket.inet_aton(target)
        is_ip = True
    except socket.error:
        is_ip = False

    if is_ip:
        rbls = [
            "zen.spamhaus.org",
            "bl.spamcop.net",
            "dnsbl.sorbs.net",
            "b.barracudacentral.org"
        ]

        reversed_ip = '.'.join(reversed(target.split('.')))

        for rbl in rbls:
            try:
                socket.gethostbyname(f"{reversed_ip}.{rbl}")
                reputation["blacklists"].append(rbl)
            except socket.gaierror:
                pass

        if reputation["blacklists"]:
            reputation["score"] = "bad"
        else:
            reputation["score"] = "clean"

    return reputation


# Main scan function
async def _run_scan(scan_id: str, target: str, scan_type: ScanType, options: Dict = None):
    """Run the actual scan."""
    scan = _load_scan(scan_id)
    if not scan:
        return

    scan["status"] = ScanStatus.RUNNING.value
    scan["started_at"] = datetime.utcnow().isoformat() + "Z"
    _save_scan(scan)

    cfg = _load_config()
    results = {
        "target": target,
        "type": scan_type.value,
        "findings": [],
        "data": {}
    }

    try:
        if scan_type == ScanType.DOMAIN:
            # DNS enumeration
            dns_results = await _dns_enumeration(target)
            if dns_results:
                results["data"]["dns"] = dns_results
                results["findings"].append({
                    "type": "dns",
                    "title": "DNS Records Found",
                    "severity": "info",
                    "count": sum(len(v) for v in dns_results.values())
                })

            # Whois lookup
            whois_results = await _whois_lookup(target)
            if whois_results.get("parsed"):
                results["data"]["whois"] = whois_results
                results["findings"].append({
                    "type": "whois",
                    "title": "WHOIS Information",
                    "severity": "info",
                    "registrar": whois_results["parsed"].get("registrar", "Unknown")
                })

            # Subdomain discovery
            subdomains = await _discover_subdomains(target)
            if subdomains:
                results["data"]["subdomains"] = subdomains
                results["findings"].append({
                    "type": "subdomains",
                    "title": "Subdomains Discovered",
                    "severity": "low",
                    "count": len(subdomains)
                })

            # Certificate transparency
            certs = await _cert_transparency(target)
            if certs:
                results["data"]["certificates"] = certs
                results["findings"].append({
                    "type": "certificates",
                    "title": "SSL Certificates Found",
                    "severity": "info",
                    "count": len(certs)
                })

            # Shodan (if API key configured)
            if cfg.get("shodan_api_key"):
                shodan_data = await _shodan_lookup(target, cfg["shodan_api_key"])
                if "error" not in shodan_data:
                    results["data"]["shodan"] = shodan_data
                    ports = shodan_data.get("ports", [])
                    if ports:
                        results["findings"].append({
                            "type": "shodan",
                            "title": "Shodan Intelligence",
                            "severity": "medium" if len(ports) > 5 else "low",
                            "ports": ports
                        })

        elif scan_type == ScanType.IP:
            # IP intelligence
            ip_info = await _ip_intelligence(target)
            results["data"]["ip_info"] = ip_info

            # Port scan
            ports = await _scan_common_ports(target)
            if ports:
                results["data"]["ports"] = ports
                results["findings"].append({
                    "type": "ports",
                    "title": "Open Ports Detected",
                    "severity": "medium" if len(ports) > 3 else "low",
                    "count": len(ports)
                })

            # Reputation check
            reputation = await _check_reputation(target)
            results["data"]["reputation"] = reputation
            if reputation.get("blacklists"):
                results["findings"].append({
                    "type": "reputation",
                    "title": "Blacklist Hits",
                    "severity": "high",
                    "blacklists": reputation["blacklists"]
                })

            # Shodan (if API key configured)
            if cfg.get("shodan_api_key"):
                shodan_data = await _shodan_lookup(target, cfg["shodan_api_key"])
                if "error" not in shodan_data:
                    results["data"]["shodan"] = shodan_data

        elif scan_type == ScanType.EMAIL:
            # Email reconnaissance
            email_info = await _email_recon(target)
            results["data"]["email_info"] = email_info

            if not email_info.get("valid_format"):
                results["findings"].append({
                    "type": "email",
                    "title": "Invalid Email Format",
                    "severity": "high"
                })
            else:
                if email_info.get("mx_records"):
                    results["findings"].append({
                        "type": "email",
                        "title": "Email Domain Valid",
                        "severity": "info",
                        "mx_count": len(email_info["mx_records"])
                    })
                if not email_info.get("spf"):
                    results["findings"].append({
                        "type": "email_security",
                        "title": "No SPF Record",
                        "severity": "medium"
                    })
                if not email_info.get("dmarc"):
                    results["findings"].append({
                        "type": "email_security",
                        "title": "No DMARC Record",
                        "severity": "medium"
                    })

        scan["status"] = ScanStatus.COMPLETED.value
        scan["results"] = results

    except Exception as e:
        scan["status"] = ScanStatus.FAILED.value
        scan["error"] = str(e)

    scan["completed_at"] = datetime.utcnow().isoformat() + "Z"
    _save_scan(scan)


# ============================================================================
# API Endpoints
# ============================================================================

@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy", "service": "secubox-openclaw", "version": "1.0.0"}


@app.get("/status")
async def status():
    """Status endpoint with statistics."""
    scans = _list_scans(1000)
    cfg = _load_config()

    return {
        "module": "openclaw",
        "status": "ok",
        "version": "1.0.0",
        "total_scans": len(scans),
        "completed_scans": sum(1 for s in scans if s.get("status") == "completed"),
        "integrations": {
            "shodan": bool(cfg.get("shodan_api_key")),
            "censys": bool(cfg.get("censys_api_id")),
            "virustotal": bool(cfg.get("virustotal_api_key")),
            "securitytrails": bool(cfg.get("securitytrails_api_key"))
        }
    }


@app.get("/config", dependencies=[Depends(require_jwt)])
async def get_config_endpoint():
    """Get current configuration (sensitive values masked)."""
    cfg = _load_config()

    # Mask sensitive values
    masked = cfg.copy()
    for key in ["shodan_api_key", "censys_api_id", "censys_api_secret",
                "virustotal_api_key", "securitytrails_api_key"]:
        if masked.get(key):
            masked[key] = "***configured***"
        else:
            masked[key] = ""

    return masked


@app.post("/config", dependencies=[Depends(require_jwt)])
async def update_config(update: ConfigUpdate):
    """Update configuration."""
    cfg = _load_config()

    updates = update.dict(exclude_none=True)
    cfg.update(updates)
    _save_config(cfg)

    return {"status": "updated", "updated_fields": list(updates.keys())}


@app.post("/scan/domain", dependencies=[Depends(require_jwt)])
async def scan_domain(target: str, background_tasks: BackgroundTasks):
    """Start a domain scan."""
    # Validate domain
    if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$', target):
        raise HTTPException(status_code=400, detail="Invalid domain format")

    scan_id = str(uuid.uuid4())[:8]
    scan = {
        "id": scan_id,
        "target": target,
        "type": ScanType.DOMAIN.value,
        "status": ScanStatus.PENDING.value,
        "created_at": datetime.utcnow().isoformat() + "Z",
        "results": None,
        "error": None
    }
    _save_scan(scan)

    background_tasks.add_task(_run_scan, scan_id, target, ScanType.DOMAIN)

    return {"status": "started", "scan_id": scan_id, "target": target}


@app.post("/scan/ip", dependencies=[Depends(require_jwt)])
async def scan_ip(target: str, background_tasks: BackgroundTasks):
    """Start an IP scan."""
    # Validate IP
    try:
        socket.inet_aton(target)
    except socket.error:
        raise HTTPException(status_code=400, detail="Invalid IP address")

    scan_id = str(uuid.uuid4())[:8]
    scan = {
        "id": scan_id,
        "target": target,
        "type": ScanType.IP.value,
        "status": ScanStatus.PENDING.value,
        "created_at": datetime.utcnow().isoformat() + "Z",
        "results": None,
        "error": None
    }
    _save_scan(scan)

    background_tasks.add_task(_run_scan, scan_id, target, ScanType.IP)

    return {"status": "started", "scan_id": scan_id, "target": target}


@app.post("/scan/email", dependencies=[Depends(require_jwt)])
async def scan_email(target: str, background_tasks: BackgroundTasks):
    """Start an email scan."""
    scan_id = str(uuid.uuid4())[:8]
    scan = {
        "id": scan_id,
        "target": target,
        "type": ScanType.EMAIL.value,
        "status": ScanStatus.PENDING.value,
        "created_at": datetime.utcnow().isoformat() + "Z",
        "results": None,
        "error": None
    }
    _save_scan(scan)

    background_tasks.add_task(_run_scan, scan_id, target, ScanType.EMAIL)

    return {"status": "started", "scan_id": scan_id, "target": target}


@app.get("/scans", dependencies=[Depends(require_jwt)])
async def get_scans(limit: int = Query(default=50, ge=1, le=200)):
    """Get scan history."""
    scans = _list_scans(limit)
    return {"scans": scans, "total": len(scans)}


@app.get("/scan/{scan_id}", dependencies=[Depends(require_jwt)])
async def get_scan(scan_id: str):
    """Get scan results."""
    scan = _load_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@app.delete("/scan/{scan_id}", dependencies=[Depends(require_jwt)])
async def delete_scan(scan_id: str):
    """Delete a scan."""
    scan_file = SCANS_DIR / f"{scan_id}.json"
    if not scan_file.exists():
        raise HTTPException(status_code=404, detail="Scan not found")

    scan_file.unlink()
    return {"status": "deleted", "scan_id": scan_id}


@app.get("/subdomains/{domain}", dependencies=[Depends(require_jwt)])
async def get_subdomains(domain: str):
    """Enumerate subdomains for a domain."""
    if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$', domain):
        raise HTTPException(status_code=400, detail="Invalid domain format")

    subdomains = await _discover_subdomains(domain)
    return {"domain": domain, "subdomains": subdomains, "count": len(subdomains)}


@app.get("/dns/{domain}", dependencies=[Depends(require_jwt)])
async def get_dns(domain: str):
    """Get DNS records for a domain."""
    if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$', domain):
        raise HTTPException(status_code=400, detail="Invalid domain format")

    records = await _dns_enumeration(domain)
    return {"domain": domain, "records": records}


@app.get("/whois/{target}", dependencies=[Depends(require_jwt)])
async def get_whois(target: str):
    """Get WHOIS information."""
    result = await _whois_lookup(target)
    return {"target": target, "whois": result}


@app.get("/certs/{domain}", dependencies=[Depends(require_jwt)])
async def get_certs(domain: str):
    """Get certificate transparency logs."""
    if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$', domain):
        raise HTTPException(status_code=400, detail="Invalid domain format")

    certs = await _cert_transparency(domain)
    return {"domain": domain, "certificates": certs, "count": len(certs)}


@app.get("/ports/{ip}", dependencies=[Depends(require_jwt)])
async def get_ports(ip: str):
    """Scan common ports on an IP."""
    try:
        socket.inet_aton(ip)
    except socket.error:
        raise HTTPException(status_code=400, detail="Invalid IP address")

    cfg = _load_config()

    # First try Shodan if configured
    if cfg.get("shodan_api_key"):
        shodan_data = await _shodan_lookup(ip, cfg["shodan_api_key"])
        if "error" not in shodan_data:
            return {
                "ip": ip,
                "source": "shodan",
                "ports": shodan_data.get("ports", []),
                "data": shodan_data.get("data", [])
            }

    # Fall back to direct scan
    ports = await _scan_common_ports(ip)
    return {"ip": ip, "source": "direct", "ports": ports}


@app.get("/reputation/{target}", dependencies=[Depends(require_jwt)])
async def get_reputation(target: str):
    """Check reputation of IP or domain."""
    result = await _check_reputation(target)
    return result


@app.get("/exports", dependencies=[Depends(require_jwt)])
async def get_export_formats():
    """Get available export formats."""
    return {
        "formats": [
            {"id": "json", "name": "JSON", "description": "Full JSON export"},
            {"id": "csv", "name": "CSV", "description": "CSV spreadsheet"},
            {"id": "xml", "name": "XML", "description": "XML format"}
        ]
    }


@app.post("/export", dependencies=[Depends(require_jwt)])
async def export_scan(request: ExportRequest):
    """Export scan results."""
    scan = _load_scan(request.scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if request.format == "json":
        return Response(
            content=json.dumps(scan, indent=2),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename=openclaw-{request.scan_id}.json"}
        )
    elif request.format == "csv":
        # Simple CSV export of findings
        lines = ["Type,Title,Severity,Details"]
        for finding in scan.get("results", {}).get("findings", []):
            details = json.dumps({k: v for k, v in finding.items() if k not in ["type", "title", "severity"]})
            lines.append(f"{finding.get('type','')},{finding.get('title','')},{finding.get('severity','')},{details}")

        return Response(
            content='\n'.join(lines),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=openclaw-{request.scan_id}.csv"}
        )
    elif request.format == "xml":
        # Basic XML export
        xml = ['<?xml version="1.0" encoding="UTF-8"?>']
        xml.append(f'<scan id="{scan.get("id")}" target="{scan.get("target")}" type="{scan.get("type")}">')
        xml.append(f'  <status>{scan.get("status")}</status>')
        xml.append('  <findings>')
        for finding in scan.get("results", {}).get("findings", []):
            xml.append(f'    <finding type="{finding.get("type")}" severity="{finding.get("severity")}">')
            xml.append(f'      <title>{finding.get("title", "")}</title>')
            xml.append('    </finding>')
        xml.append('  </findings>')
        xml.append('</scan>')

        return Response(
            content='\n'.join(xml),
            media_type="application/xml",
            headers={"Content-Disposition": f"attachment; filename=openclaw-{request.scan_id}.xml"}
        )
    else:
        raise HTTPException(status_code=400, detail="Invalid export format")


@app.get("/integrations", dependencies=[Depends(require_jwt)])
async def get_integrations():
    """Get integration status."""
    cfg = _load_config()

    integrations = [
        {
            "id": "shodan",
            "name": "Shodan",
            "description": "Internet-wide port scanning and device search",
            "configured": bool(cfg.get("shodan_api_key")),
            "url": "https://shodan.io"
        },
        {
            "id": "censys",
            "name": "Censys",
            "description": "Internet asset discovery and monitoring",
            "configured": bool(cfg.get("censys_api_id") and cfg.get("censys_api_secret")),
            "url": "https://censys.io"
        },
        {
            "id": "virustotal",
            "name": "VirusTotal",
            "description": "File and URL scanning and analysis",
            "configured": bool(cfg.get("virustotal_api_key")),
            "url": "https://virustotal.com"
        },
        {
            "id": "securitytrails",
            "name": "SecurityTrails",
            "description": "DNS and domain intelligence",
            "configured": bool(cfg.get("securitytrails_api_key")),
            "url": "https://securitytrails.com"
        },
        {
            "id": "crtsh",
            "name": "crt.sh",
            "description": "Certificate transparency logs",
            "configured": True,
            "url": "https://crt.sh"
        }
    ]

    return {"integrations": integrations}
