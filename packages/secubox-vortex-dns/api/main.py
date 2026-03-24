"""SecuBox Vortex-DNS API - DNS Firewall with RPZ and Threat Feeds"""
import asyncio
import subprocess
import os
import json
import re
from pathlib import Path
from datetime import datetime
from typing import Optional
from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel
from secubox_core.auth import require_jwt
from secubox_core.config import get_config

app = FastAPI(title="SecuBox Vortex-DNS")
config = get_config("vortex-dns")

# Configuration paths
CONFIG_DIR = "/etc/secubox/vortex-dns"
RPZ_DIR = "/var/lib/secubox/vortex-dns/rpz"
BLOCKLIST_DIR = "/var/lib/secubox/vortex-dns/blocklists"
STATE_FILE = "/var/lib/secubox/vortex-dns/state.json"

# Supported DNS servers
DNS_SERVERS = ["unbound", "bind9", "dnsmasq"]

# Ensure directories exist
Path(CONFIG_DIR).mkdir(parents=True, exist_ok=True)
Path(RPZ_DIR).mkdir(parents=True, exist_ok=True)
Path(BLOCKLIST_DIR).mkdir(parents=True, exist_ok=True)
Path("/var/lib/secubox/vortex-dns").mkdir(parents=True, exist_ok=True)


class BlocklistSource(BaseModel):
    name: str
    url: str
    enabled: bool = True
    format: str = "hosts"  # hosts, domains, rpz


class DomainRule(BaseModel):
    domain: str
    action: str = "block"  # block, allow, redirect
    redirect_to: Optional[str] = None


class DNSConfig(BaseModel):
    enabled: bool = True
    dns_server: str = "unbound"
    block_action: str = "nxdomain"  # nxdomain, redirect, null
    redirect_ip: str = "0.0.0.0"
    log_queries: bool = False
    safesearch: bool = False


def _load_state() -> dict:
    """Load module state."""
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, 'r') as f:
                return json.load(f)
        except Exception:
            pass
    return {
        "enabled": False,
        "dns_server": "unbound",
        "blocklists": [],
        "custom_rules": [],
        "stats": {"blocked": 0, "allowed": 0}
    }


def _save_state(state: dict):
    """Save module state."""
    try:
        with open(STATE_FILE, 'w') as f:
            json.dump(state, f, indent=2)
    except Exception:
        pass


def _detect_dns_server() -> str:
    """Detect which DNS server is installed and running."""
    for server in DNS_SERVERS:
        try:
            result = subprocess.run(
                ["systemctl", "is-active", server],
                capture_output=True, text=True, timeout=5
            )
            if result.stdout.strip() == "active":
                return server
        except Exception:
            pass
    return "unbound"


def _get_dns_service_status() -> dict:
    """Get DNS server status."""
    server = _detect_dns_server()
    try:
        result = subprocess.run(
            ["systemctl", "show", server, "--property=ActiveState,SubState,MainPID"],
            capture_output=True, text=True, timeout=10
        )
        props = {}
        for line in result.stdout.strip().split('\n'):
            if '=' in line:
                k, v = line.split('=', 1)
                props[k] = v
        return {
            "server": server,
            "active": props.get("ActiveState") == "active",
            "state": props.get("SubState", "unknown"),
            "pid": int(props.get("MainPID", 0))
        }
    except Exception:
        return {"server": server, "active": False, "state": "unknown", "pid": 0}


def _generate_unbound_rpz(domains: list[str], action: str = "refuse") -> str:
    """Generate Unbound RPZ configuration."""
    lines = ["# Vortex-DNS RPZ Zone - Auto-generated", "server:"]

    for domain in domains:
        if action == "refuse":
            lines.append(f'    local-zone: "{domain}" refuse')
        elif action == "redirect":
            lines.append(f'    local-zone: "{domain}" redirect')
            lines.append(f'    local-data: "{domain} A 0.0.0.0"')
        else:  # nxdomain
            lines.append(f'    local-zone: "{domain}" static')

    return '\n'.join(lines)


def _generate_dnsmasq_blocklist(domains: list[str]) -> str:
    """Generate dnsmasq blocklist configuration."""
    lines = ["# Vortex-DNS Blocklist - Auto-generated"]
    for domain in domains:
        lines.append(f"address=/{domain}/")
    return '\n'.join(lines)


def _reload_dns_server(server: str):
    """Reload DNS server configuration."""
    try:
        if server == "unbound":
            subprocess.run(["unbound-control", "reload"], timeout=10)
        elif server == "bind9":
            subprocess.run(["rndc", "reload"], timeout=10)
        elif server == "dnsmasq":
            subprocess.run(["systemctl", "reload", "dnsmasq"], timeout=10)
    except Exception:
        pass


def _parse_blocklist_file(filepath: str, format: str = "hosts") -> list[str]:
    """Parse blocklist file and extract domains."""
    domains = []
    try:
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                if format == "hosts":
                    # Format: 0.0.0.0 domain.com or 127.0.0.1 domain.com
                    parts = line.split()
                    if len(parts) >= 2 and parts[0] in ["0.0.0.0", "127.0.0.1"]:
                        domain = parts[1].lower()
                        if domain not in ["localhost", "localhost.localdomain"]:
                            domains.append(domain)
                elif format == "domains":
                    # Just domain names, one per line
                    domain = line.split('#')[0].strip().lower()
                    if domain:
                        domains.append(domain)
    except Exception:
        pass
    return domains


async def _download_blocklist(url: str, name: str) -> int:
    """Download blocklist from URL."""
    filepath = os.path.join(BLOCKLIST_DIR, f"{name}.txt")
    try:
        result = subprocess.run(
            ["curl", "-sL", "-o", filepath, url],
            capture_output=True, timeout=60
        )
        if result.returncode == 0 and os.path.exists(filepath):
            return os.path.getsize(filepath)
    except Exception:
        pass
    return 0


@app.get("/status")
async def status():
    """Public status endpoint."""
    return {
        "module": "vortex-dns",
        "status": "ok",
        "version": "1.0.0"
    }


@app.get("/service", dependencies=[Depends(require_jwt)])
async def get_service_status():
    """Get DNS service status."""
    state = _load_state()
    dns_status = _get_dns_service_status()

    return {
        "enabled": state.get("enabled", False),
        "dns_server": dns_status,
        "blocklists_count": len(state.get("blocklists", [])),
        "custom_rules_count": len(state.get("custom_rules", []))
    }


@app.post("/enable", dependencies=[Depends(require_jwt)])
async def enable_dns_firewall(enabled: bool = True):
    """Enable or disable DNS firewall."""
    state = _load_state()
    state["enabled"] = enabled
    _save_state(state)

    if enabled:
        # Apply current blocklist configuration
        await apply_blocklists()

    return {"success": True, "enabled": enabled}


@app.get("/blocklists", dependencies=[Depends(require_jwt)])
async def get_blocklists():
    """Get configured blocklists."""
    state = _load_state()

    blocklists = state.get("blocklists", [])

    # Add domain counts
    for bl in blocklists:
        filepath = os.path.join(BLOCKLIST_DIR, f"{bl['name']}.txt")
        if os.path.exists(filepath):
            bl["domains_count"] = len(_parse_blocklist_file(filepath, bl.get("format", "hosts")))
            bl["last_updated"] = datetime.fromtimestamp(os.path.getmtime(filepath)).isoformat()
        else:
            bl["domains_count"] = 0
            bl["last_updated"] = None

    return {"blocklists": blocklists}


@app.post("/blocklists", dependencies=[Depends(require_jwt)])
async def add_blocklist(source: BlocklistSource):
    """Add a blocklist source."""
    state = _load_state()

    # Check if already exists
    existing = [b for b in state.get("blocklists", []) if b["name"] == source.name]
    if existing:
        raise HTTPException(status_code=400, detail="Blocklist already exists")

    # Download blocklist
    size = await _download_blocklist(source.url, source.name)
    if size == 0:
        raise HTTPException(status_code=400, detail="Failed to download blocklist")

    state.setdefault("blocklists", []).append({
        "name": source.name,
        "url": source.url,
        "enabled": source.enabled,
        "format": source.format
    })
    _save_state(state)

    return {"success": True, "name": source.name, "size": size}


@app.delete("/blocklists/{name}", dependencies=[Depends(require_jwt)])
async def remove_blocklist(name: str):
    """Remove a blocklist."""
    state = _load_state()
    state["blocklists"] = [b for b in state.get("blocklists", []) if b["name"] != name]
    _save_state(state)

    # Remove downloaded file
    filepath = os.path.join(BLOCKLIST_DIR, f"{name}.txt")
    if os.path.exists(filepath):
        os.remove(filepath)

    return {"success": True}


@app.post("/blocklists/update", dependencies=[Depends(require_jwt)])
async def update_blocklists():
    """Update all enabled blocklists."""
    state = _load_state()
    results = []

    for bl in state.get("blocklists", []):
        if bl.get("enabled", True):
            size = await _download_blocklist(bl["url"], bl["name"])
            results.append({"name": bl["name"], "size": size, "success": size > 0})

    return {"results": results}


@app.post("/blocklists/apply", dependencies=[Depends(require_jwt)])
async def apply_blocklists():
    """Apply blocklists to DNS server."""
    state = _load_state()

    if not state.get("enabled", False):
        return {"success": False, "error": "DNS firewall is disabled"}

    # Collect all domains from enabled blocklists
    all_domains = set()
    for bl in state.get("blocklists", []):
        if bl.get("enabled", True):
            filepath = os.path.join(BLOCKLIST_DIR, f"{bl['name']}.txt")
            domains = _parse_blocklist_file(filepath, bl.get("format", "hosts"))
            all_domains.update(domains)

    # Add custom blocked domains
    for rule in state.get("custom_rules", []):
        if rule.get("action") == "block":
            all_domains.add(rule["domain"])

    # Remove allowed domains
    for rule in state.get("custom_rules", []):
        if rule.get("action") == "allow":
            all_domains.discard(rule["domain"])

    # Generate configuration for detected DNS server
    server = _detect_dns_server()

    if server == "unbound":
        config_content = _generate_unbound_rpz(list(all_domains))
        config_path = "/etc/unbound/unbound.conf.d/vortex-dns.conf"
    elif server == "dnsmasq":
        config_content = _generate_dnsmasq_blocklist(list(all_domains))
        config_path = "/etc/dnsmasq.d/vortex-dns.conf"
    else:
        return {"success": False, "error": f"Unsupported DNS server: {server}"}

    # Write configuration
    try:
        with open(config_path, 'w') as f:
            f.write(config_content)
    except Exception as e:
        return {"success": False, "error": str(e)}

    # Reload DNS server
    _reload_dns_server(server)

    return {
        "success": True,
        "server": server,
        "domains_blocked": len(all_domains)
    }


@app.get("/rules", dependencies=[Depends(require_jwt)])
async def get_custom_rules():
    """Get custom domain rules."""
    state = _load_state()
    return {"rules": state.get("custom_rules", [])}


@app.post("/rules", dependencies=[Depends(require_jwt)])
async def add_rule(rule: DomainRule):
    """Add a custom domain rule."""
    state = _load_state()

    # Remove existing rule for same domain
    state["custom_rules"] = [r for r in state.get("custom_rules", []) if r["domain"] != rule.domain]

    state.setdefault("custom_rules", []).append({
        "domain": rule.domain.lower(),
        "action": rule.action,
        "redirect_to": rule.redirect_to,
        "created": datetime.now().isoformat()
    })
    _save_state(state)

    return {"success": True, "domain": rule.domain}


@app.delete("/rules/{domain}", dependencies=[Depends(require_jwt)])
async def remove_rule(domain: str):
    """Remove a custom domain rule."""
    state = _load_state()
    state["custom_rules"] = [r for r in state.get("custom_rules", []) if r["domain"] != domain.lower()]
    _save_state(state)

    return {"success": True}


@app.get("/stats", dependencies=[Depends(require_jwt)])
async def get_stats():
    """Get DNS firewall statistics."""
    state = _load_state()

    # Count total blocked domains
    total_domains = 0
    for bl in state.get("blocklists", []):
        if bl.get("enabled", True):
            filepath = os.path.join(BLOCKLIST_DIR, f"{bl['name']}.txt")
            if os.path.exists(filepath):
                total_domains += len(_parse_blocklist_file(filepath, bl.get("format", "hosts")))

    return {
        "enabled": state.get("enabled", False),
        "total_blocked_domains": total_domains,
        "blocklists_count": len([b for b in state.get("blocklists", []) if b.get("enabled", True)]),
        "custom_rules_count": len(state.get("custom_rules", [])),
        "queries_blocked": state.get("stats", {}).get("blocked", 0),
        "queries_allowed": state.get("stats", {}).get("allowed", 0)
    }


@app.get("/feeds", dependencies=[Depends(require_jwt)])
async def get_threat_feeds():
    """Get available threat intelligence feeds."""
    return {
        "feeds": [
            {"name": "Steven Black Hosts", "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", "format": "hosts", "category": "ads-malware"},
            {"name": "OISD Basic", "url": "https://small.oisd.nl/domainswild", "format": "domains", "category": "comprehensive"},
            {"name": "URLhaus Malware", "url": "https://urlhaus.abuse.ch/downloads/hostfile/", "format": "hosts", "category": "malware"},
            {"name": "Phishing Army", "url": "https://phishing.army/download/phishing_army_blocklist.txt", "format": "domains", "category": "phishing"},
            {"name": "NoTracking", "url": "https://raw.githubusercontent.com/notracking/hosts-blocklists/master/hostnames.txt", "format": "domains", "category": "tracking"},
        ]
    }


@app.get("/info", dependencies=[Depends(require_jwt)])
async def info():
    """Protected info endpoint."""
    return {"config": dict(config)}
