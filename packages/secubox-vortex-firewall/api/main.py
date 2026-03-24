"""SecuBox Vortex-Firewall API - nftables Threat Enforcement"""
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

app = FastAPI(title="SecuBox Vortex-Firewall")
config = get_config("vortex-firewall")

# Configuration paths
CONFIG_DIR = "/etc/secubox/vortex-firewall"
IPSETS_DIR = "/var/lib/secubox/vortex-firewall/ipsets"
STATE_FILE = "/var/lib/secubox/vortex-firewall/state.json"
NFT_CONF = "/etc/nftables.d/vortex-firewall.nft"

# Ensure directories exist (only create writable ones at startup)
try:
    Path(CONFIG_DIR).mkdir(parents=True, exist_ok=True)
    Path(IPSETS_DIR).mkdir(parents=True, exist_ok=True)
    Path("/var/lib/secubox/vortex-firewall").mkdir(parents=True, exist_ok=True)
except PermissionError:
    pass  # Will be created by postinst or admin


class IPBlocklist(BaseModel):
    name: str
    url: str
    enabled: bool = True
    format: str = "plain"  # plain, cidr, csv


class IPRule(BaseModel):
    ip: str
    action: str = "drop"  # drop, reject, log
    direction: str = "both"  # in, out, both
    comment: Optional[str] = None


class GeoIPConfig(BaseModel):
    enabled: bool = False
    mode: str = "block"  # block, allow
    countries: list[str] = []


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
        "blocklists": [],
        "custom_rules": [],
        "geoip": {"enabled": False, "mode": "block", "countries": []},
        "stats": {"blocked_in": 0, "blocked_out": 0}
    }


def _save_state(state: dict):
    """Save module state."""
    try:
        with open(STATE_FILE, 'w') as f:
            json.dump(state, f, indent=2)
    except Exception:
        pass


def _parse_ip_blocklist(filepath: str, format: str = "plain") -> list[str]:
    """Parse IP blocklist file."""
    ips = []
    try:
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#') or line.startswith(';'):
                    continue

                if format == "csv":
                    # CSV format: ip,category,date
                    parts = line.split(',')
                    if parts:
                        ip = parts[0].strip()
                else:
                    # Plain or CIDR format
                    ip = line.split('#')[0].strip()

                # Validate IP/CIDR format
                if re.match(r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$', ip):
                    ips.append(ip)
    except Exception:
        pass
    return ips


async def _download_blocklist(url: str, name: str) -> int:
    """Download IP blocklist from URL."""
    filepath = os.path.join(IPSETS_DIR, f"{name}.txt")
    try:
        result = subprocess.run(
            ["curl", "-sL", "-o", filepath, url],
            capture_output=True, timeout=120
        )
        if result.returncode == 0 and os.path.exists(filepath):
            return os.path.getsize(filepath)
    except Exception:
        pass
    return 0


def _generate_nft_sets(state: dict) -> str:
    """Generate nftables configuration with IP sets."""
    lines = [
        "#!/usr/sbin/nft -f",
        "# Vortex-Firewall - Auto-generated",
        "",
        "table inet vortex_firewall {",
        "    set blocked_ips_v4 {",
        "        type ipv4_addr",
        "        flags interval",
        "    }",
        "",
        "    set blocked_ips_v6 {",
        "        type ipv6_addr",
        "        flags interval",
        "    }",
        "",
        "    chain input {",
        "        type filter hook input priority -10; policy accept;",
        "        ip saddr @blocked_ips_v4 counter drop comment \"vortex-blocked\"",
        "        ip6 saddr @blocked_ips_v6 counter drop comment \"vortex-blocked\"",
        "    }",
        "",
        "    chain output {",
        "        type filter hook output priority -10; policy accept;",
        "        ip daddr @blocked_ips_v4 counter drop comment \"vortex-blocked\"",
        "        ip6 daddr @blocked_ips_v6 counter drop comment \"vortex-blocked\"",
        "    }",
        "}",
    ]

    return '\n'.join(lines)


def _apply_nft_rules():
    """Apply nftables configuration."""
    try:
        # First flush existing vortex table if exists
        subprocess.run(
            ["nft", "delete", "table", "inet", "vortex_firewall"],
            capture_output=True, timeout=10
        )
    except Exception:
        pass

    # Apply new configuration
    try:
        subprocess.run(
            ["nft", "-f", NFT_CONF],
            capture_output=True, timeout=30, check=True
        )
        return True
    except Exception:
        return False


def _add_ips_to_set(ips: list[str], set_name: str = "blocked_ips_v4"):
    """Add IPs to nftables set."""
    if not ips:
        return

    # Add in batches to avoid command line too long
    batch_size = 100
    for i in range(0, len(ips), batch_size):
        batch = ips[i:i+batch_size]
        elements = ', '.join(batch)
        try:
            subprocess.run(
                ["nft", "add", "element", "inet", "vortex_firewall", set_name, f"{{ {elements} }}"],
                capture_output=True, timeout=30
            )
        except Exception:
            pass


def _get_nft_counters() -> dict:
    """Get nftables counters for blocked traffic."""
    counters = {"input": 0, "output": 0}
    try:
        result = subprocess.run(
            ["nft", "list", "table", "inet", "vortex_firewall"],
            capture_output=True, text=True, timeout=10
        )
        # Parse counter values from output
        for line in result.stdout.split('\n'):
            if 'counter packets' in line:
                match = re.search(r'counter packets (\d+)', line)
                if match:
                    if 'input' in line or 'saddr' in line:
                        counters["input"] += int(match.group(1))
                    elif 'output' in line or 'daddr' in line:
                        counters["output"] += int(match.group(1))
    except Exception:
        pass
    return counters


def _check_nftables_available() -> bool:
    """Check if nftables is available."""
    try:
        result = subprocess.run(["nft", "--version"], capture_output=True, timeout=5)
        return result.returncode == 0
    except Exception:
        return False


@app.get("/status")
async def status():
    """Public status endpoint."""
    return {
        "module": "vortex-firewall",
        "status": "ok",
        "version": "1.0.0",
        "nftables_available": _check_nftables_available()
    }


@app.get("/service", dependencies=[Depends(require_jwt)])
async def get_service_status():
    """Get firewall service status."""
    state = _load_state()
    counters = _get_nft_counters()

    # Count total IPs in blocklists
    total_ips = 0
    for bl in state.get("blocklists", []):
        if bl.get("enabled", True):
            filepath = os.path.join(IPSETS_DIR, f"{bl['name']}.txt")
            if os.path.exists(filepath):
                total_ips += len(_parse_ip_blocklist(filepath, bl.get("format", "plain")))

    return {
        "enabled": state.get("enabled", False),
        "nftables_available": _check_nftables_available(),
        "blocklists_count": len([b for b in state.get("blocklists", []) if b.get("enabled", True)]),
        "total_blocked_ips": total_ips,
        "packets_blocked_in": counters["input"],
        "packets_blocked_out": counters["output"]
    }


@app.post("/enable", dependencies=[Depends(require_jwt)])
async def enable_firewall(enabled: bool = True):
    """Enable or disable threat firewall."""
    if not _check_nftables_available():
        raise HTTPException(status_code=500, detail="nftables not available")

    state = _load_state()
    state["enabled"] = enabled
    _save_state(state)

    if enabled:
        # Generate and apply nft configuration
        nft_config = _generate_nft_sets(state)
        try:
            with open(NFT_CONF, 'w') as f:
                f.write(nft_config)
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

        if not _apply_nft_rules():
            raise HTTPException(status_code=500, detail="Failed to apply nftables rules")

        # Load IP sets
        await apply_blocklists()
    else:
        # Remove vortex table
        try:
            subprocess.run(
                ["nft", "delete", "table", "inet", "vortex_firewall"],
                capture_output=True, timeout=10
            )
        except Exception:
            pass

    return {"success": True, "enabled": enabled}


@app.get("/blocklists", dependencies=[Depends(require_jwt)])
async def get_blocklists():
    """Get configured IP blocklists."""
    state = _load_state()

    blocklists = state.get("blocklists", [])

    for bl in blocklists:
        filepath = os.path.join(IPSETS_DIR, f"{bl['name']}.txt")
        if os.path.exists(filepath):
            bl["ips_count"] = len(_parse_ip_blocklist(filepath, bl.get("format", "plain")))
            bl["last_updated"] = datetime.fromtimestamp(os.path.getmtime(filepath)).isoformat()
        else:
            bl["ips_count"] = 0
            bl["last_updated"] = None

    return {"blocklists": blocklists}


@app.post("/blocklists", dependencies=[Depends(require_jwt)])
async def add_blocklist(source: IPBlocklist):
    """Add an IP blocklist source."""
    state = _load_state()

    existing = [b for b in state.get("blocklists", []) if b["name"] == source.name]
    if existing:
        raise HTTPException(status_code=400, detail="Blocklist already exists")

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
    """Remove an IP blocklist."""
    state = _load_state()
    state["blocklists"] = [b for b in state.get("blocklists", []) if b["name"] != name]
    _save_state(state)

    filepath = os.path.join(IPSETS_DIR, f"{name}.txt")
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
    """Apply all blocklists to nftables."""
    state = _load_state()

    if not state.get("enabled", False):
        return {"success": False, "error": "Firewall is disabled"}

    # Collect all IPs
    all_ips_v4 = set()
    all_ips_v6 = set()

    for bl in state.get("blocklists", []):
        if bl.get("enabled", True):
            filepath = os.path.join(IPSETS_DIR, f"{bl['name']}.txt")
            ips = _parse_ip_blocklist(filepath, bl.get("format", "plain"))
            for ip in ips:
                if ':' in ip:
                    all_ips_v6.add(ip)
                else:
                    all_ips_v4.add(ip)

    # Add custom blocked IPs
    for rule in state.get("custom_rules", []):
        if rule.get("action") == "drop":
            ip = rule["ip"]
            if ':' in ip:
                all_ips_v6.add(ip)
            else:
                all_ips_v4.add(ip)

    # Flush and reload sets
    try:
        subprocess.run(
            ["nft", "flush", "set", "inet", "vortex_firewall", "blocked_ips_v4"],
            capture_output=True, timeout=10
        )
        subprocess.run(
            ["nft", "flush", "set", "inet", "vortex_firewall", "blocked_ips_v6"],
            capture_output=True, timeout=10
        )
    except Exception:
        pass

    # Add IPs to sets
    _add_ips_to_set(list(all_ips_v4), "blocked_ips_v4")
    _add_ips_to_set(list(all_ips_v6), "blocked_ips_v6")

    return {
        "success": True,
        "ipv4_blocked": len(all_ips_v4),
        "ipv6_blocked": len(all_ips_v6)
    }


@app.get("/rules", dependencies=[Depends(require_jwt)])
async def get_custom_rules():
    """Get custom IP rules."""
    state = _load_state()
    return {"rules": state.get("custom_rules", [])}


@app.post("/rules", dependencies=[Depends(require_jwt)])
async def add_rule(rule: IPRule):
    """Add a custom IP rule."""
    state = _load_state()

    # Validate IP format
    if not re.match(r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$', rule.ip) and ':' not in rule.ip:
        raise HTTPException(status_code=400, detail="Invalid IP format")

    state["custom_rules"] = [r for r in state.get("custom_rules", []) if r["ip"] != rule.ip]

    state.setdefault("custom_rules", []).append({
        "ip": rule.ip,
        "action": rule.action,
        "direction": rule.direction,
        "comment": rule.comment,
        "created": datetime.now().isoformat()
    })
    _save_state(state)

    return {"success": True, "ip": rule.ip}


@app.delete("/rules/{ip:path}", dependencies=[Depends(require_jwt)])
async def remove_rule(ip: str):
    """Remove a custom IP rule."""
    state = _load_state()
    state["custom_rules"] = [r for r in state.get("custom_rules", []) if r["ip"] != ip]
    _save_state(state)

    return {"success": True}


@app.get("/geoip", dependencies=[Depends(require_jwt)])
async def get_geoip_config():
    """Get GeoIP blocking configuration."""
    state = _load_state()
    return state.get("geoip", {"enabled": False, "mode": "block", "countries": []})


@app.post("/geoip", dependencies=[Depends(require_jwt)])
async def set_geoip_config(geoip: GeoIPConfig):
    """Configure GeoIP blocking."""
    state = _load_state()
    state["geoip"] = {
        "enabled": geoip.enabled,
        "mode": geoip.mode,
        "countries": geoip.countries
    }
    _save_state(state)

    return {"success": True}


@app.get("/stats", dependencies=[Depends(require_jwt)])
async def get_stats():
    """Get firewall statistics."""
    state = _load_state()
    counters = _get_nft_counters()

    total_ips = 0
    for bl in state.get("blocklists", []):
        if bl.get("enabled", True):
            filepath = os.path.join(IPSETS_DIR, f"{bl['name']}.txt")
            if os.path.exists(filepath):
                total_ips += len(_parse_ip_blocklist(filepath, bl.get("format", "plain")))

    return {
        "enabled": state.get("enabled", False),
        "total_blocked_ips": total_ips,
        "blocklists_count": len([b for b in state.get("blocklists", []) if b.get("enabled", True)]),
        "custom_rules_count": len(state.get("custom_rules", [])),
        "packets_blocked_inbound": counters["input"],
        "packets_blocked_outbound": counters["output"]
    }


@app.get("/feeds", dependencies=[Depends(require_jwt)])
async def get_threat_feeds():
    """Get available threat intelligence IP feeds."""
    return {
        "feeds": [
            {"name": "Spamhaus DROP", "url": "https://www.spamhaus.org/drop/drop.txt", "format": "cidr", "category": "spam"},
            {"name": "Spamhaus EDROP", "url": "https://www.spamhaus.org/drop/edrop.txt", "format": "cidr", "category": "spam"},
            {"name": "Emerging Threats", "url": "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt", "format": "plain", "category": "threats"},
            {"name": "Feodo Tracker", "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", "format": "plain", "category": "botnet"},
            {"name": "SSL Blacklist", "url": "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt", "format": "plain", "category": "malware"},
            {"name": "TOR Exit Nodes", "url": "https://check.torproject.org/torbulkexitlist", "format": "plain", "category": "anonymizer"},
        ]
    }


@app.get("/info", dependencies=[Depends(require_jwt)])
async def info():
    """Protected info endpoint."""
    return {"config": dict(config)}
