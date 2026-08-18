# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""HAProxy router — WAF enable/disable and route sync."""
import json
import re
import subprocess
import shutil
from pathlib import Path
from typing import Dict, List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from secubox_core.auth import require_jwt
from secubox_core.logger import get_logger

try:
    import toml
except ImportError:
    toml = None

router = APIRouter()
log = get_logger("mitmproxy.haproxy")

CONFIG_FILE = Path("/etc/secubox/mitmproxy.toml")
HAPROXY_CFG = Path("/etc/haproxy/haproxy.cfg")
HAPROXY_BACKUP = Path("/etc/haproxy/haproxy.cfg.waf-backup")
ROUTES_FILE = Path("/data/mitmproxy-waf/data/routes.json")


class HAProxyStatus(BaseModel):
    waf_enabled: bool
    backend_exists: bool
    routes_count: int


class RoutesResponse(BaseModel):
    routes: Dict[str, List]


class ActionResponse(BaseModel):
    success: bool
    message: str


def _load_config() -> dict:
    """Load mitmproxy config."""
    if toml and CONFIG_FILE.exists():
        return toml.load(CONFIG_FILE)
    return {}


def _save_config(config: dict) -> None:
    """Save mitmproxy config."""
    if toml:
        with open(CONFIG_FILE, "w") as f:
            toml.dump(config, f)


def _haproxy_has_waf_backend() -> bool:
    """Check if HAProxy config has mitmproxy_waf backend."""
    if not HAPROXY_CFG.exists():
        return False
    content = HAPROXY_CFG.read_text()
    return "backend mitmproxy_waf" in content


def _parse_haproxy_backends() -> Dict[str, tuple]:
    """Parse HAProxy config to extract vhost → backend mappings."""
    routes = {}

    if not HAPROXY_CFG.exists():
        return routes

    content = HAPROXY_CFG.read_text()

    # Find backend definitions and their servers
    backends = {}
    current_backend = None

    for line in content.split("\n"):
        line = line.strip()

        # Backend definition
        if line.startswith("backend "):
            current_backend = line.split()[1]
            backends[current_backend] = None

        # Server definition inside backend
        elif current_backend and line.startswith("server "):
            # server name ip:port ...
            parts = line.split()
            if len(parts) >= 3:
                addr = parts[2]
                if ":" in addr:
                    ip, port = addr.rsplit(":", 1)
                    try:
                        backends[current_backend] = (ip, int(port))
                    except ValueError:
                        pass

    # Find use_backend rules to map hosts to backends
    for line in content.split("\n"):
        # use_backend backend_name if { hdr(host) -i hostname }
        match = re.search(r'use_backend\s+(\S+)\s+if\s+\{\s*hdr\(host\)\s+-i\s+(\S+)', line)
        if match:
            backend_name, hostname = match.groups()
            if backend_name in backends and backends[backend_name]:
                routes[hostname] = list(backends[backend_name])

    return routes


@router.get("/status", response_model=HAProxyStatus)
async def get_haproxy_status(user=Depends(require_jwt)):
    """Get HAProxy WAF integration status."""
    config = _load_config()

    routes_count = 0
    if ROUTES_FILE.exists():
        try:
            routes = json.loads(ROUTES_FILE.read_text())
            routes_count = len(routes)
        except Exception:
            pass

    return HAProxyStatus(
        waf_enabled=config.get("haproxy", {}).get("enabled", False),
        backend_exists=_haproxy_has_waf_backend(),
        routes_count=routes_count
    )


@router.post("/enable", response_model=ActionResponse)
async def enable_waf(user=Depends(require_jwt)):
    """Enable WAF inspection for HAProxy traffic."""
    if not HAPROXY_CFG.exists():
        raise HTTPException(400, "HAProxy config not found")

    config = _load_config()
    proxy_port = config.get("proxy", {}).get("listen_port", 8890)

    # Backup current config
    shutil.copy(HAPROXY_CFG, HAPROXY_BACKUP)

    content = HAPROXY_CFG.read_text()

    # Add mitmproxy_waf backend if not exists
    if "backend mitmproxy_waf" not in content:
        waf_backend = f"""
# SecuBox WAF Backend
backend mitmproxy_waf
    mode http
    server waf 127.0.0.1:{proxy_port} check
"""
        # Add before first backend or at end
        if "backend " in content:
            idx = content.index("backend ")
            content = content[:idx] + waf_backend + "\n" + content[idx:]
        else:
            content += waf_backend

        HAPROXY_CFG.write_text(content)

    # Sync routes
    await sync_routes(user)

    # Update config
    if "haproxy" not in config:
        config["haproxy"] = {}
    config["haproxy"]["enabled"] = True
    _save_config(config)

    # Reload HAProxy
    result = subprocess.run(["systemctl", "reload", "haproxy"], capture_output=True)
    if result.returncode != 0:
        log.error(f"Failed to reload HAProxy: {result.stderr}")

    log.info("WAF enabled for HAProxy")
    return ActionResponse(success=True, message="WAF enabled")


@router.post("/disable", response_model=ActionResponse)
async def disable_waf(user=Depends(require_jwt)):
    """Disable WAF inspection (restore original routing)."""
    config = _load_config()

    # Restore backup if exists
    if HAPROXY_BACKUP.exists():
        shutil.copy(HAPROXY_BACKUP, HAPROXY_CFG)

        # Reload HAProxy
        subprocess.run(["systemctl", "reload", "haproxy"], capture_output=True)

    # Update config
    if "haproxy" not in config:
        config["haproxy"] = {}
    config["haproxy"]["enabled"] = False
    _save_config(config)

    log.info("WAF disabled for HAProxy")
    return ActionResponse(success=True, message="WAF disabled")


@router.post("/sync", response_model=ActionResponse)
async def sync_routes(user=Depends(require_jwt)):
    """Sync HAProxy vhosts to mitmproxy routes."""
    routes = _parse_haproxy_backends()

    ROUTES_FILE.parent.mkdir(parents=True, exist_ok=True)
    ROUTES_FILE.write_text(json.dumps(routes, indent=2))

    log.info(f"Synced {len(routes)} routes to mitmproxy")
    return ActionResponse(success=True, message=f"Synced {len(routes)} routes")


@router.get("/routes", response_model=RoutesResponse)
async def get_routes(user=Depends(require_jwt)):
    """Get current route mappings."""
    routes = {}

    if ROUTES_FILE.exists():
        try:
            routes = json.loads(ROUTES_FILE.read_text())
        except Exception:
            pass

    return RoutesResponse(routes=routes)
