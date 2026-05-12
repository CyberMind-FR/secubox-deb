# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Status router — Container status and control endpoints."""
import subprocess
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from secubox_core.auth import require_jwt
from secubox_core.logger import get_logger

try:
    import toml
except ImportError:
    toml = None

CONFIG_FILE = Path("/etc/secubox/mitmproxy.toml")

router = APIRouter()
log = get_logger("mitmproxy.status")

CONTAINER_NAME = "mitmproxy-waf"


class StatusResponse(BaseModel):
    # Core status
    container_exists: bool
    container_running: bool
    mitmproxy_running: bool
    running: bool = False  # Alias for WebUI compatibility
    # Stats
    threats_today: int = 0
    autobans_today: int = 0
    autobans_pending: int = 0
    autobans_total: int = 0
    by_category: dict = {}
    by_severity: dict = {}
    # Config (for WebUI display)
    mode: str = "transparent"
    wan_protection_enabled: bool = False
    crowdsec_feed: bool = True
    block_bots: bool = True
    autoban_enabled: bool = True
    proxy_port: int = 8890
    web_port: int = 8091


class ActionResponse(BaseModel):
    success: bool
    message: str


def _lxc_exists() -> bool:
    """Check if LXC container exists."""
    result = subprocess.run(["lxc-ls"], capture_output=True, text=True)
    return CONTAINER_NAME in result.stdout.split()


def _lxc_running() -> bool:
    """Check if LXC container is running."""
    result = subprocess.run(
        ["lxc-info", "-n", CONTAINER_NAME, "-s"],
        capture_output=True, text=True
    )
    return "RUNNING" in result.stdout


def _mitmproxy_running() -> bool:
    """Check if mitmproxy is running inside container."""
    if not _lxc_running():
        return False
    result = subprocess.run(
        ["lxc-attach", "-n", CONTAINER_NAME, "--", "pgrep", "-f", "mitmdump"],
        capture_output=True
    )
    return result.returncode == 0


def _load_config() -> dict:
    """Load TOML configuration."""
    if toml and CONFIG_FILE.exists():
        return toml.load(CONFIG_FILE)
    return {}


@router.get("/status", response_model=StatusResponse)
async def get_status(user=Depends(require_jwt)):
    """Get container and WAF status."""
    from ..main import get_stats_cache

    stats = get_stats_cache()
    config = _load_config()
    is_running = _mitmproxy_running()

    return StatusResponse(
        container_exists=_lxc_exists(),
        container_running=_lxc_running(),
        mitmproxy_running=is_running,
        running=is_running,
        threats_today=stats.get("threats_today", 0),
        autobans_today=stats.get("autobans_today", 0),
        autobans_pending=stats.get("autobans_pending", 0),
        autobans_total=stats.get("autobans_total", 0),
        by_category=stats.get("by_category", {}),
        by_severity=stats.get("by_severity", {}),
        mode=config.get("proxy", {}).get("mode", "transparent"),
        wan_protection_enabled=config.get("haproxy", {}).get("wan_protection", False),
        crowdsec_feed=config.get("crowdsec", {}).get("enabled", True),
        block_bots=config.get("waf_rules", {}).get("block_bots", True),
        autoban_enabled=config.get("autoban", {}).get("enabled", True),
        proxy_port=config.get("proxy", {}).get("listen_port", 8890),
        web_port=config.get("proxy", {}).get("web_port", 8091)
    )


@router.post("/start", response_model=ActionResponse)
async def start_container(user=Depends(require_jwt)):
    """Start the WAF container."""
    if not _lxc_exists():
        raise HTTPException(400, "Container not installed. Run: mitmproxyctl install")

    if _lxc_running():
        return ActionResponse(success=True, message="Container already running")

    result = subprocess.run(["mitmproxyctl", "start"], capture_output=True, text=True)

    if result.returncode == 0:
        return ActionResponse(success=True, message="Container started")
    else:
        raise HTTPException(500, f"Failed to start: {result.stderr}")


@router.post("/stop", response_model=ActionResponse)
async def stop_container(user=Depends(require_jwt)):
    """Stop the WAF container."""
    if not _lxc_running():
        return ActionResponse(success=True, message="Container not running")

    result = subprocess.run(["mitmproxyctl", "stop"], capture_output=True, text=True)

    if result.returncode == 0:
        return ActionResponse(success=True, message="Container stopped")
    else:
        raise HTTPException(500, f"Failed to stop: {result.stderr}")


@router.post("/restart", response_model=ActionResponse)
async def restart_container(user=Depends(require_jwt)):
    """Restart the WAF container."""
    result = subprocess.run(["mitmproxyctl", "restart"], capture_output=True, text=True)

    if result.returncode == 0:
        return ActionResponse(success=True, message="Container restarted")
    else:
        raise HTTPException(500, f"Failed to restart: {result.stderr}")


# --- WebUI compatibility endpoints ---

class ModeRequest(BaseModel):
    mode: str
    apply_now: bool = False


class SettingsRequest(BaseModel):
    wan_protection: Optional[bool] = None
    crowdsec_feed: Optional[bool] = None
    block_bots: Optional[bool] = None
    autoban_enabled: Optional[bool] = None
    apply_now: bool = False


def _save_config(config: dict) -> None:
    """Save TOML configuration."""
    if toml:
        CONFIG_FILE.write_text(toml.dumps(config))


@router.post("/set_mode", response_model=ActionResponse)
async def set_mode(req: ModeRequest, user=Depends(require_jwt)):
    """Set WAF mode (transparent, inspection, block)."""
    config = _load_config()
    if "proxy" not in config:
        config["proxy"] = {}
    config["proxy"]["mode"] = req.mode
    _save_config(config)

    if req.apply_now and _lxc_running():
        subprocess.run(["mitmproxyctl", "restart"], capture_output=True)

    return ActionResponse(success=True, message=f"Mode set to {req.mode}")


@router.post("/save_settings", response_model=ActionResponse)
async def save_settings(req: SettingsRequest, user=Depends(require_jwt)):
    """Save WebUI settings to config."""
    config = _load_config()

    if req.wan_protection is not None:
        if "haproxy" not in config:
            config["haproxy"] = {}
        config["haproxy"]["wan_protection"] = req.wan_protection

    if req.crowdsec_feed is not None:
        if "crowdsec" not in config:
            config["crowdsec"] = {}
        config["crowdsec"]["enabled"] = req.crowdsec_feed

    if req.block_bots is not None:
        if "waf_rules" not in config:
            config["waf_rules"] = {}
        config["waf_rules"]["block_bots"] = req.block_bots

    if req.autoban_enabled is not None:
        if "autoban" not in config:
            config["autoban"] = {}
        config["autoban"]["enabled"] = req.autoban_enabled

    _save_config(config)
    return ActionResponse(success=True, message="Settings saved")


@router.post("/setup_firewall", response_model=ActionResponse)
async def setup_firewall(user=Depends(require_jwt)):
    """Setup nftables rules for WAF traffic redirection."""
    # Add nftables rule to redirect HTTP/HTTPS through mitmproxy
    config = _load_config()
    proxy_port = config.get("proxy", {}).get("listen_port", 8890)

    cmds = [
        f"nft add table inet secubox_waf",
        f"nft add chain inet secubox_waf prerouting {{ type nat hook prerouting priority -100 \\; }}",
        f"nft add rule inet secubox_waf prerouting tcp dport {{ 80, 443 }} redirect to :{proxy_port}",
    ]

    for cmd in cmds:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            log.warning(f"Firewall command failed: {cmd} - {result.stderr}")

    return ActionResponse(success=True, message="Firewall rules applied")


@router.post("/clear_firewall", response_model=ActionResponse)
async def clear_firewall(user=Depends(require_jwt)):
    """Remove WAF firewall rules."""
    subprocess.run("nft delete table inet secubox_waf 2>/dev/null", shell=True)
    return ActionResponse(success=True, message="Firewall rules cleared")


@router.post("/wan_setup", response_model=ActionResponse)
async def wan_setup(user=Depends(require_jwt)):
    """Enable WAN protection via HAProxy."""
    config = _load_config()
    if "haproxy" not in config:
        config["haproxy"] = {}
    config["haproxy"]["wan_protection"] = True
    _save_config(config)

    # Reload HAProxy
    subprocess.run(["systemctl", "reload", "haproxy"], capture_output=True)
    return ActionResponse(success=True, message="WAN protection enabled")


@router.post("/wan_clear", response_model=ActionResponse)
async def wan_clear(user=Depends(require_jwt)):
    """Disable WAN protection."""
    config = _load_config()
    if "haproxy" not in config:
        config["haproxy"] = {}
    config["haproxy"]["wan_protection"] = False
    _save_config(config)

    subprocess.run(["systemctl", "reload", "haproxy"], capture_output=True)
    return ActionResponse(success=True, message="WAN protection disabled")
