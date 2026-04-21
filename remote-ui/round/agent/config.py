"""
SecuBox Eye Remote — Configuration loader
Loads device and SecuBox connection config from TOML file.

CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
"""
from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

DEFAULT_CONFIG_PATH = Path("/etc/secubox-eye/config.toml")


@dataclass
class DeviceConfig:
    """Eye Remote device configuration."""
    id: str
    name: str = "Eye Remote"


@dataclass
class SecuBoxConfig:
    """Configuration for one SecuBox connection."""
    name: str
    host: str
    token: str
    active: bool = False
    fallback: Optional[str] = None
    poll_interval: float = 2.0


@dataclass
class Config:
    """Full agent configuration."""
    device: DeviceConfig
    secuboxes: list[SecuBoxConfig] = field(default_factory=list)


def load_config(path: Path = DEFAULT_CONFIG_PATH) -> Config:
    """
    Load configuration from TOML file.

    Args:
        path: Path to config file

    Returns:
        Parsed Config object
    """
    with open(path, "rb") as f:
        data = tomllib.load(f)

    device_data = data.get("device", {})
    device = DeviceConfig(
        id=device_data.get("id", "eye-unknown"),
        name=device_data.get("name", "Eye Remote"),
    )

    secuboxes = []
    for sb_data in data.get("secubox", []):
        secuboxes.append(SecuBoxConfig(
            name=sb_data.get("name", "SecuBox"),
            host=sb_data.get("host", "10.55.0.1"),
            token=sb_data.get("token", ""),
            active=sb_data.get("active", False),
            fallback=sb_data.get("fallback"),
            poll_interval=sb_data.get("poll_interval", 2.0),
        ))

    return Config(device=device, secuboxes=secuboxes)


def get_active_secubox(config: Config) -> Optional[SecuBoxConfig]:
    """
    Get the currently active SecuBox config.

    Returns:
        Active SecuBox config or None if none active
    """
    for sb in config.secuboxes:
        if sb.active:
            return sb
    return config.secuboxes[0] if config.secuboxes else None


def set_active_secubox(config: Config, name: str) -> bool:
    """
    Set a SecuBox as active by name.

    Args:
        config: Config object
        name: Name of SecuBox to activate

    Returns:
        True if found and activated
    """
    found = False
    for sb in config.secuboxes:
        if sb.name == name:
            sb.active = True
            found = True
        else:
            sb.active = False
    return found
