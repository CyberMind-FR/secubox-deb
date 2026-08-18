# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Settings router — Configuration CRUD endpoints."""
from pathlib import Path
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from secubox_core.auth import require_jwt
from secubox_core.logger import get_logger

try:
    import toml
except ImportError:
    toml = None

router = APIRouter()
log = get_logger("mitmproxy.settings")

CONFIG_FILE = Path("/etc/secubox/mitmproxy.toml")


class ContainerSettings(BaseModel):
    name: str = "mitmproxy-waf"
    memory_limit: str = "256M"
    autostart: bool = True


class ProxySettings(BaseModel):
    listen_port: int = 8890
    web_port: int = 8091
    web_host: str = "127.0.0.1"
    data_path: str = "/srv/mitmproxy-waf"


class HAProxySettings(BaseModel):
    enabled: bool = False
    config_path: str = "/etc/haproxy/haproxy.cfg"
    backend_name: str = "mitmproxy_waf"


class AutobanSettings(BaseModel):
    enabled: bool = True
    sensitivity: str = "moderate"
    ban_duration: str = "4h"
    min_severity: str = "high"


class WhitelistSettings(BaseModel):
    ips: List[str] = ["127.0.0.1"]


class SettingsResponse(BaseModel):
    container: ContainerSettings
    proxy: ProxySettings
    haproxy: HAProxySettings
    autoban: AutobanSettings
    whitelist: WhitelistSettings


class SettingsUpdate(BaseModel):
    container: Optional[ContainerSettings] = None
    proxy: Optional[ProxySettings] = None
    haproxy: Optional[HAProxySettings] = None
    autoban: Optional[AutobanSettings] = None
    whitelist: Optional[WhitelistSettings] = None


def _load_config() -> dict:
    """Load configuration from TOML file."""
    if toml and CONFIG_FILE.exists():
        return toml.load(CONFIG_FILE)
    return {}


def _save_config(config: dict) -> None:
    """Save configuration to TOML file."""
    if not toml:
        raise HTTPException(500, "TOML library not available")

    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_FILE, "w") as f:
        toml.dump(config, f)


@router.get("/settings", response_model=SettingsResponse)
async def get_settings(user=Depends(require_jwt)):
    """Get current configuration."""
    config = _load_config()

    return SettingsResponse(
        container=ContainerSettings(**config.get("container", {})),
        proxy=ProxySettings(**config.get("proxy", {})),
        haproxy=HAProxySettings(**config.get("haproxy", {})),
        autoban=AutobanSettings(**config.get("autoban", {})),
        whitelist=WhitelistSettings(**config.get("whitelist", {}))
    )


@router.post("/settings", response_model=SettingsResponse)
async def update_settings(update: SettingsUpdate, user=Depends(require_jwt)):
    """Update configuration."""
    config = _load_config()

    if update.container:
        config["container"] = update.container.dict()
    if update.proxy:
        config["proxy"] = update.proxy.dict()
    if update.haproxy:
        config["haproxy"] = update.haproxy.dict()
    if update.autoban:
        config["autoban"] = update.autoban.dict()
    if update.whitelist:
        config["whitelist"] = update.whitelist.dict()

    _save_config(config)
    log.info("Configuration updated")

    return await get_settings(user)
