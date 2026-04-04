"""SecuBox IPBlock API - IP Blocklist Management"""
import asyncio
import subprocess
import os
import json
import re
import uuid
from pathlib import Path
from datetime import datetime
from typing import Optional
from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel
from secubox_core.auth import require_jwt
from secubox_core.config import get_config

app = FastAPI(title="SecuBox IPBlock")
config = get_config("ipblock")

# Configuration paths
CONFIG_DIR = "/etc/secubox/ipblock"
DATA_DIR = "/var/lib/secubox/ipblock"
LISTS_DIR = f"{DATA_DIR}/lists"
STATE_FILE = f"{DATA_DIR}/state.json"
HISTORY_FILE = f"{DATA_DIR}/history.json"
NFT_CONF = "/etc/nftables.d/ipblock.nft"

# Ensure directories exist
try:
    Path(CONFIG_DIR).mkdir(parents=True, exist_ok=True)
    Path(DATA_DIR).mkdir(parents=True, exist_ok=True)
    Path(LISTS_DIR).mkdir(parents=True, exist_ok=True)
except PermissionError:
    pass


class BlocklistSource(BaseModel):
    name: str
    url: str
    enabled: bool = True
    format: str = "plain"  # plain, cidr, csv
    category: str = "general"
    auto_update: bool = True


class BlockIPRequest(BaseModel):
    ip: str
    reason: Optional[str] = None
    duration: Optional[int] = None  # seconds, None = permanent


class WhitelistIPRequest(BaseModel):
    ip: str
    reason: Optional[str] = None


class ConfigUpdate(BaseModel):
    auto_update_enabled: bool = True
    update_interval: int = 86400  # seconds (default: 24h)
    log_blocked: bool = True
    block_action: str = "drop"  # drop, reject


class ImportRequest(BaseModel):
    content: str
    format: str = "plain"
    name: str = "imported"


def _load_state() -> dict:
    """Load module state."""
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, 'r') as f:
                return json.load(f)
        except Exception:
            pass
    return {
        "enabled": True,
        "sources": [],
        "blocked": {},  # ip -> {reason, added, expires}
        "whitelist": {},  # ip -> {reason, added}
        "config": {
            "auto_update_enabled": True,
            "update_interval": 86400,
            "log_blocked": True,
            "block_action": "drop"
        },
        "stats": {
            "total_blocked": 0,
            "manual_blocks": 0,
            "list_blocks": 0,
            "packets_dropped": 0
        },
        "last_update": None
    }


def _save_state(state: dict):
    """Save module state."""
    try:
        with open(STATE_FILE, 'w') as f:
            json.dump(state, f, indent=2)
    except Exception:
        pass


def _load_history() -> list:
    """Load block history."""
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, 'r') as f:
                return json.load(f)
        except Exception:
            pass
    return []


def _save_history(history: list):
    """Save block history."""
    try:
        # Keep only last 1000 entries
        history = history[-1000:]
        with open(HISTORY_FILE, 'w') as f:
            json.dump(history, f, indent=2)
    except Exception:
        pass


def _add_history_entry(action: str, ip: str, source: str, reason: Optional[str] = None):
    """Add entry to block history."""
    history = _load_history()
    history.append({
        "id": str(uuid.uuid4())[:8],
        "timestamp": datetime.now().isoformat(),
        "action": action,
        "ip": ip,
        "source": source,
        "reason": reason
    })
    _save_history(history)


def _validate_ip(ip: str) -> bool:
    """Validate IP address or CIDR format."""
    # IPv4
    if re.match(r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$', ip):
        return True
    # IPv6 (simplified check)
    if ':' in ip and not ' ' in ip:
        return True
    return False


def _parse_blocklist(filepath: str, format: str = "plain") -> list[str]:
    """Parse IP blocklist file."""
    ips = []
    try:
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#') or line.startswith(';'):
                    continue

                if format == "csv":
                    parts = line.split(',')
                    if parts:
                        ip = parts[0].strip()
                else:
                    ip = line.split('#')[0].strip()

                if _validate_ip(ip):
                    ips.append(ip)
    except Exception:
        pass
    return ips


async def _download_list(url: str, name: str) -> tuple[int, int]:
    """Download blocklist from URL. Returns (success, ip_count)."""
    filepath = os.path.join(LISTS_DIR, f"{name}.txt")
    try:
        result = subprocess.run(
            ["curl", "-sL", "-o", filepath, "--connect-timeout", "30", url],
            capture_output=True, timeout=120
        )
        if result.returncode == 0 and os.path.exists(filepath):
            with open(filepath, 'r') as f:
                lines = [l for l in f.readlines() if l.strip() and not l.startswith('#')]
            return (1, len(lines))
    except Exception:
        pass
    return (0, 0)


def _generate_nft_config(state: dict) -> str:
    """Generate nftables configuration."""
    action = state.get("config", {}).get("block_action", "drop")
    log_blocked = state.get("config", {}).get("log_blocked", True)

    lines = [
        "#!/usr/sbin/nft -f",
        "# SecuBox IPBlock - Auto-generated",
        "",
        "table inet ipblock {",
        "    set blocked_v4 {",
        "        type ipv4_addr",
        "        flags interval",
        "    }",
        "",
        "    set blocked_v6 {",
        "        type ipv6_addr",
        "        flags interval",
        "    }",
        "",
        "    set whitelist_v4 {",
        "        type ipv4_addr",
        "        flags interval",
        "    }",
        "",
        "    set whitelist_v6 {",
        "        type ipv6_addr",
        "        flags interval",
        "    }",
        "",
        "    chain input {",
        "        type filter hook input priority -5; policy accept;",
        "        ip saddr @whitelist_v4 accept",
        "        ip6 saddr @whitelist_v6 accept",
    ]

    if log_blocked:
        lines.append('        ip saddr @blocked_v4 counter log prefix "[IPBLOCK-DROP] " ' + action)
        lines.append('        ip6 saddr @blocked_v6 counter log prefix "[IPBLOCK-DROP] " ' + action)
    else:
        lines.append(f'        ip saddr @blocked_v4 counter {action}')
        lines.append(f'        ip6 saddr @blocked_v6 counter {action}')

    lines.extend([
        "    }",
        "",
        "    chain output {",
        "        type filter hook output priority -5; policy accept;",
        "        ip daddr @whitelist_v4 accept",
        "        ip6 daddr @whitelist_v6 accept",
    ])

    if log_blocked:
        lines.append('        ip daddr @blocked_v4 counter log prefix "[IPBLOCK-DROP] " ' + action)
        lines.append('        ip6 daddr @blocked_v6 counter log prefix "[IPBLOCK-DROP] " ' + action)
    else:
        lines.append(f'        ip daddr @blocked_v4 counter {action}')
        lines.append(f'        ip6 daddr @blocked_v6 counter {action}')

    lines.extend([
        "    }",
        "}",
    ])

    return '\n'.join(lines)


def _apply_nft_rules():
    """Apply nftables configuration."""
    # Remove existing table
    try:
        subprocess.run(
            ["nft", "delete", "table", "inet", "ipblock"],
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


def _add_to_nft_set(ips: list[str], set_name: str):
    """Add IPs to nftables set."""
    if not ips:
        return

    batch_size = 100
    for i in range(0, len(ips), batch_size):
        batch = ips[i:i+batch_size]
        elements = ', '.join(batch)
        try:
            subprocess.run(
                ["nft", "add", "element", "inet", "ipblock", set_name, f"{{ {elements} }}"],
                capture_output=True, timeout=30
            )
        except Exception:
            pass


def _flush_nft_set(set_name: str):
    """Flush nftables set."""
    try:
        subprocess.run(
            ["nft", "flush", "set", "inet", "ipblock", set_name],
            capture_output=True, timeout=10
        )
    except Exception:
        pass


def _reload_all_sets(state: dict):
    """Reload all nftables sets from state."""
    # Flush all sets
    for set_name in ["blocked_v4", "blocked_v6", "whitelist_v4", "whitelist_v6"]:
        _flush_nft_set(set_name)

    # Collect all blocked IPs
    blocked_v4 = set()
    blocked_v6 = set()

    # From sources
    for source in state.get("sources", []):
        if source.get("enabled", True):
            filepath = os.path.join(LISTS_DIR, f"{source['name']}.txt")
            ips = _parse_blocklist(filepath, source.get("format", "plain"))
            for ip in ips:
                if ':' in ip:
                    blocked_v6.add(ip)
                else:
                    blocked_v4.add(ip)

    # From manual blocks
    for ip in state.get("blocked", {}).keys():
        if ':' in ip:
            blocked_v6.add(ip)
        else:
            blocked_v4.add(ip)

    # Remove whitelisted IPs from blocked
    whitelist = set(state.get("whitelist", {}).keys())
    blocked_v4 -= whitelist
    blocked_v6 -= whitelist

    # Apply sets
    _add_to_nft_set(list(blocked_v4), "blocked_v4")
    _add_to_nft_set(list(blocked_v6), "blocked_v6")

    # Whitelist
    whitelist_v4 = [ip for ip in whitelist if ':' not in ip]
    whitelist_v6 = [ip for ip in whitelist if ':' in ip]
    _add_to_nft_set(whitelist_v4, "whitelist_v4")
    _add_to_nft_set(whitelist_v6, "whitelist_v6")

    return len(blocked_v4), len(blocked_v6)


def _get_nft_counters() -> dict:
    """Get nftables packet counters."""
    counters = {"dropped": 0}
    try:
        result = subprocess.run(
            ["nft", "list", "table", "inet", "ipblock"],
            capture_output=True, text=True, timeout=10
        )
        for line in result.stdout.split('\n'):
            if 'counter packets' in line:
                match = re.search(r'counter packets (\d+)', line)
                if match:
                    counters["dropped"] += int(match.group(1))
    except Exception:
        pass
    return counters


def _check_nftables() -> bool:
    """Check if nftables is available."""
    try:
        result = subprocess.run(["nft", "--version"], capture_output=True, timeout=5)
        return result.returncode == 0
    except Exception:
        return False


# Default blocklist sources
DEFAULT_SOURCES = [
    {"id": "spamhaus-drop", "name": "Spamhaus DROP", "url": "https://www.spamhaus.org/drop/drop.txt", "format": "cidr", "category": "spam"},
    {"id": "spamhaus-edrop", "name": "Spamhaus EDROP", "url": "https://www.spamhaus.org/drop/edrop.txt", "format": "cidr", "category": "spam"},
    {"id": "emerging-threats", "name": "Emerging Threats", "url": "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt", "format": "plain", "category": "threats"},
    {"id": "feodo-tracker", "name": "Feodo Tracker", "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", "format": "plain", "category": "botnet"},
    {"id": "sslbl", "name": "SSL Blacklist", "url": "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt", "format": "plain", "category": "malware"},
    {"id": "tor-exit", "name": "TOR Exit Nodes", "url": "https://check.torproject.org/torbulkexitlist", "format": "plain", "category": "anonymizer"},
    {"id": "firehol-level1", "name": "FireHOL Level 1", "url": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset", "format": "cidr", "category": "aggregated"},
    {"id": "blocklist-de", "name": "Blocklist.de", "url": "https://lists.blocklist.de/lists/all.txt", "format": "plain", "category": "attacks"},
]


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy", "module": "ipblock"}


@app.get("/status")
async def status():
    """Public status endpoint."""
    return {
        "module": "ipblock",
        "status": "ok",
        "version": "1.0.0",
        "nftables_available": _check_nftables()
    }


@app.get("/config", dependencies=[Depends(require_jwt)])
async def get_config_endpoint():
    """Get current configuration."""
    state = _load_state()
    return state.get("config", {})


@app.post("/config", dependencies=[Depends(require_jwt)])
async def update_config(cfg: ConfigUpdate):
    """Update configuration."""
    state = _load_state()
    state["config"] = {
        "auto_update_enabled": cfg.auto_update_enabled,
        "update_interval": cfg.update_interval,
        "log_blocked": cfg.log_blocked,
        "block_action": cfg.block_action
    }
    _save_state(state)

    # Regenerate and apply nft rules
    nft_config = _generate_nft_config(state)
    try:
        with open(NFT_CONF, 'w') as f:
            f.write(nft_config)
        _apply_nft_rules()
        _reload_all_sets(state)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    return {"success": True}


@app.get("/lists", dependencies=[Depends(require_jwt)])
async def get_lists():
    """Get active blocklist sources."""
    state = _load_state()
    sources = state.get("sources", [])

    # Add IP counts and last update times
    for src in sources:
        filepath = os.path.join(LISTS_DIR, f"{src['name']}.txt")
        if os.path.exists(filepath):
            ips = _parse_blocklist(filepath, src.get("format", "plain"))
            src["ip_count"] = len(ips)
            src["last_updated"] = datetime.fromtimestamp(os.path.getmtime(filepath)).isoformat()
        else:
            src["ip_count"] = 0
            src["last_updated"] = None

    return {"sources": sources}


@app.get("/lists/available", dependencies=[Depends(require_jwt)])
async def get_available_lists():
    """Get available blocklist sources."""
    return {"sources": DEFAULT_SOURCES}


@app.post("/list/add", dependencies=[Depends(require_jwt)])
async def add_list(source: BlocklistSource):
    """Add a blocklist source."""
    state = _load_state()

    # Check if already exists
    existing = [s for s in state.get("sources", []) if s["name"] == source.name]
    if existing:
        raise HTTPException(status_code=400, detail="Source already exists")

    # Download the list
    success, count = await _download_list(source.url, source.name)
    if not success:
        raise HTTPException(status_code=400, detail="Failed to download blocklist")

    # Add to state
    source_dict = {
        "id": str(uuid.uuid4())[:8],
        "name": source.name,
        "url": source.url,
        "enabled": source.enabled,
        "format": source.format,
        "category": source.category,
        "auto_update": source.auto_update,
        "added": datetime.now().isoformat()
    }
    state.setdefault("sources", []).append(source_dict)
    _save_state(state)

    # Reload sets
    _reload_all_sets(state)

    _add_history_entry("list_added", "-", source.name, f"Added blocklist with {count} IPs")

    return {"success": True, "id": source_dict["id"], "ip_count": count}


@app.delete("/list/{list_id}", dependencies=[Depends(require_jwt)])
async def remove_list(list_id: str):
    """Remove a blocklist source."""
    state = _load_state()

    removed = None
    for src in state.get("sources", []):
        if src.get("id") == list_id or src.get("name") == list_id:
            removed = src
            break

    if not removed:
        raise HTTPException(status_code=404, detail="Source not found")

    state["sources"] = [s for s in state["sources"] if s.get("id") != list_id and s.get("name") != list_id]
    _save_state(state)

    # Remove file
    filepath = os.path.join(LISTS_DIR, f"{removed['name']}.txt")
    if os.path.exists(filepath):
        os.remove(filepath)

    # Reload sets
    _reload_all_sets(state)

    _add_history_entry("list_removed", "-", removed["name"], "Removed blocklist")

    return {"success": True}


@app.post("/list/{list_id}/update", dependencies=[Depends(require_jwt)])
async def update_list(list_id: str):
    """Update a specific blocklist."""
    state = _load_state()

    source = None
    for src in state.get("sources", []):
        if src.get("id") == list_id or src.get("name") == list_id:
            source = src
            break

    if not source:
        raise HTTPException(status_code=404, detail="Source not found")

    success, count = await _download_list(source["url"], source["name"])
    if not success:
        raise HTTPException(status_code=500, detail="Failed to update blocklist")

    # Reload sets
    _reload_all_sets(state)

    return {"success": True, "ip_count": count}


@app.post("/lists/update-all", dependencies=[Depends(require_jwt)])
async def update_all_lists():
    """Update all enabled blocklists."""
    state = _load_state()
    results = []

    for src in state.get("sources", []):
        if src.get("enabled", True) and src.get("auto_update", True):
            success, count = await _download_list(src["url"], src["name"])
            results.append({
                "name": src["name"],
                "success": bool(success),
                "ip_count": count
            })

    state["last_update"] = datetime.now().isoformat()
    _save_state(state)

    # Reload sets
    _reload_all_sets(state)

    return {"results": results}


@app.get("/blocked", dependencies=[Depends(require_jwt)])
async def get_blocked():
    """Get currently blocked IPs (manual blocks)."""
    state = _load_state()
    blocked = []

    for ip, info in state.get("blocked", {}).items():
        blocked.append({
            "ip": ip,
            "reason": info.get("reason"),
            "added": info.get("added"),
            "expires": info.get("expires"),
            "source": "manual"
        })

    return {"blocked": blocked, "count": len(blocked)}


@app.post("/block", dependencies=[Depends(require_jwt)])
async def block_ip(req: BlockIPRequest):
    """Block an IP address manually."""
    if not _validate_ip(req.ip):
        raise HTTPException(status_code=400, detail="Invalid IP format")

    state = _load_state()

    # Check whitelist
    if req.ip in state.get("whitelist", {}):
        raise HTTPException(status_code=400, detail="IP is whitelisted")

    # Add to blocked
    expires = None
    if req.duration:
        from datetime import timedelta
        expires = (datetime.now() + timedelta(seconds=req.duration)).isoformat()

    state.setdefault("blocked", {})[req.ip] = {
        "reason": req.reason,
        "added": datetime.now().isoformat(),
        "expires": expires
    }
    state["stats"]["manual_blocks"] = len(state["blocked"])
    _save_state(state)

    # Add to nftables set
    set_name = "blocked_v6" if ':' in req.ip else "blocked_v4"
    _add_to_nft_set([req.ip], set_name)

    _add_history_entry("blocked", req.ip, "manual", req.reason)

    return {"success": True, "ip": req.ip}


@app.delete("/block/{ip:path}", dependencies=[Depends(require_jwt)])
async def unblock_ip(ip: str):
    """Unblock an IP address."""
    state = _load_state()

    if ip not in state.get("blocked", {}):
        raise HTTPException(status_code=404, detail="IP not in block list")

    del state["blocked"][ip]
    state["stats"]["manual_blocks"] = len(state["blocked"])
    _save_state(state)

    # Reload sets (to remove IP)
    _reload_all_sets(state)

    _add_history_entry("unblocked", ip, "manual", "Manual unblock")

    return {"success": True}


@app.get("/whitelist", dependencies=[Depends(require_jwt)])
async def get_whitelist():
    """Get whitelisted IPs."""
    state = _load_state()
    whitelist = []

    for ip, info in state.get("whitelist", {}).items():
        whitelist.append({
            "ip": ip,
            "reason": info.get("reason"),
            "added": info.get("added")
        })

    return {"whitelist": whitelist, "count": len(whitelist)}


@app.post("/whitelist", dependencies=[Depends(require_jwt)])
async def add_whitelist(req: WhitelistIPRequest):
    """Add IP to whitelist."""
    if not _validate_ip(req.ip):
        raise HTTPException(status_code=400, detail="Invalid IP format")

    state = _load_state()

    # Add to whitelist
    state.setdefault("whitelist", {})[req.ip] = {
        "reason": req.reason,
        "added": datetime.now().isoformat()
    }

    # Remove from blocked if present
    if req.ip in state.get("blocked", {}):
        del state["blocked"][req.ip]

    _save_state(state)

    # Reload sets
    _reload_all_sets(state)

    _add_history_entry("whitelisted", req.ip, "manual", req.reason)

    return {"success": True, "ip": req.ip}


@app.delete("/whitelist/{ip:path}", dependencies=[Depends(require_jwt)])
async def remove_whitelist(ip: str):
    """Remove IP from whitelist."""
    state = _load_state()

    if ip not in state.get("whitelist", {}):
        raise HTTPException(status_code=404, detail="IP not in whitelist")

    del state["whitelist"][ip]
    _save_state(state)

    # Reload sets
    _reload_all_sets(state)

    _add_history_entry("whitelist_removed", ip, "manual", "Removed from whitelist")

    return {"success": True}


@app.get("/stats", dependencies=[Depends(require_jwt)])
async def get_stats():
    """Get block statistics."""
    state = _load_state()
    counters = _get_nft_counters()

    # Count IPs from all sources
    total_list_ips = 0
    for src in state.get("sources", []):
        if src.get("enabled", True):
            filepath = os.path.join(LISTS_DIR, f"{src['name']}.txt")
            if os.path.exists(filepath):
                ips = _parse_blocklist(filepath, src.get("format", "plain"))
                total_list_ips += len(ips)

    return {
        "enabled": state.get("enabled", True),
        "total_blocked_ips": total_list_ips + len(state.get("blocked", {})),
        "list_ips": total_list_ips,
        "manual_blocks": len(state.get("blocked", {})),
        "whitelisted": len(state.get("whitelist", {})),
        "active_sources": len([s for s in state.get("sources", []) if s.get("enabled", True)]),
        "packets_dropped": counters["dropped"],
        "last_update": state.get("last_update"),
        "nftables_available": _check_nftables()
    }


@app.get("/history", dependencies=[Depends(require_jwt)])
async def get_history(limit: int = 100, offset: int = 0):
    """Get block history."""
    history = _load_history()
    # Return in reverse chronological order
    history = list(reversed(history))
    total = len(history)
    history = history[offset:offset + limit]

    return {"history": history, "total": total}


@app.post("/import", dependencies=[Depends(require_jwt)])
async def import_list(req: ImportRequest):
    """Import IP list from content."""
    lines = req.content.strip().split('\n')
    ips = []

    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue

        if req.format == "csv":
            parts = line.split(',')
            if parts:
                ip = parts[0].strip()
        else:
            ip = line.split('#')[0].strip()

        if _validate_ip(ip):
            ips.append(ip)

    if not ips:
        raise HTTPException(status_code=400, detail="No valid IPs found")

    # Save to file
    filepath = os.path.join(LISTS_DIR, f"{req.name}.txt")
    with open(filepath, 'w') as f:
        f.write('\n'.join(ips))

    # Add as source
    state = _load_state()
    state.setdefault("sources", []).append({
        "id": str(uuid.uuid4())[:8],
        "name": req.name,
        "url": "imported",
        "enabled": True,
        "format": "plain",
        "category": "imported",
        "auto_update": False,
        "added": datetime.now().isoformat()
    })
    _save_state(state)

    # Reload sets
    _reload_all_sets(state)

    _add_history_entry("imported", "-", req.name, f"Imported {len(ips)} IPs")

    return {"success": True, "imported": len(ips)}


@app.get("/export", dependencies=[Depends(require_jwt)])
async def export_list(include_manual: bool = True, include_lists: bool = True):
    """Export current blocked IPs."""
    state = _load_state()
    ips = set()

    if include_manual:
        ips.update(state.get("blocked", {}).keys())

    if include_lists:
        for src in state.get("sources", []):
            if src.get("enabled", True):
                filepath = os.path.join(LISTS_DIR, f"{src['name']}.txt")
                list_ips = _parse_blocklist(filepath, src.get("format", "plain"))
                ips.update(list_ips)

    # Remove whitelisted
    ips -= set(state.get("whitelist", {}).keys())

    content = '\n'.join(sorted(ips))

    return {
        "content": content,
        "count": len(ips),
        "generated": datetime.now().isoformat()
    }


@app.post("/apply", dependencies=[Depends(require_jwt)])
async def apply_rules():
    """Apply all rules to nftables."""
    if not _check_nftables():
        raise HTTPException(status_code=500, detail="nftables not available")

    state = _load_state()

    # Generate and write nft config
    nft_config = _generate_nft_config(state)
    try:
        Path("/etc/nftables.d").mkdir(parents=True, exist_ok=True)
        with open(NFT_CONF, 'w') as f:
            f.write(nft_config)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    # Apply rules
    if not _apply_nft_rules():
        raise HTTPException(status_code=500, detail="Failed to apply nftables rules")

    # Reload sets
    blocked_v4, blocked_v6 = _reload_all_sets(state)

    return {
        "success": True,
        "blocked_v4": blocked_v4,
        "blocked_v6": blocked_v6
    }


@app.get("/info", dependencies=[Depends(require_jwt)])
async def info():
    """Protected info endpoint."""
    return {"config": dict(config)}
