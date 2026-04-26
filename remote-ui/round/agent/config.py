"""
SecuBox Eye Remote — Configuration loader
Loads device and SecuBox connection config from TOML file.

CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate
"""
from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, List

DEFAULT_CONFIG_PATH = Path("/etc/secubox/eye-remote/eye-remote.toml")


@dataclass
class DeviceConfig:
    """Eye Remote device configuration."""
    id: str = "eye-remote-001"
    name: str = "Eye Remote"


@dataclass
class DisplayConfig:
    """Display settings."""
    brightness: int = 80
    timeout_seconds: int = 300
    theme: str = "neon"  # neon | classic | minimal


@dataclass
class ModeConfig:
    """Mode switching settings."""
    default: str = "auto"  # auto | dashboard | local | flash | gateway
    auto_fallback_seconds: int = 60
    reconnect_interval_seconds: int = 10


@dataclass
class WebConfig:
    """Web Remote server settings."""
    enabled: bool = True
    port: int = 8080
    bind: str = "0.0.0.0"


@dataclass
class SecuBoxConfig:
    """Configuration for one SecuBox connection."""
    id: str = ""
    name: str = "SecuBox"
    host: str = "10.55.0.1"
    port: int = 8000
    token: str = ""
    transport: str = "otg"  # otg | wifi | manual
    active: bool = False
    fallback: Optional[str] = None
    poll_interval: float = 2.0


@dataclass
class SecuBoxesConfig:
    """SecuBox fleet configuration."""
    primary: str = ""
    devices: List[SecuBoxConfig] = field(default_factory=list)


@dataclass
class Config:
    """Full agent configuration."""
    device: DeviceConfig = field(default_factory=DeviceConfig)
    display: DisplayConfig = field(default_factory=DisplayConfig)
    mode: ModeConfig = field(default_factory=ModeConfig)
    web: WebConfig = field(default_factory=WebConfig)
    secuboxes: SecuBoxesConfig = field(default_factory=SecuBoxesConfig)


def load_config(path: Path = DEFAULT_CONFIG_PATH) -> Config:
    """
    Load configuration from TOML file.

    Args:
        path: Path to config file

    Returns:
        Parsed Config object
    """
    if not path.exists():
        return Config()

    with open(path, "rb") as f:
        data = tomllib.load(f)

    # Parse device config
    device_data = data.get("device", {})
    device = DeviceConfig(
        id=device_data.get("id", "eye-remote-001"),
        name=device_data.get("name", "Eye Remote"),
    )

    # Parse display config
    display_data = data.get("display", {})
    display = DisplayConfig(
        brightness=display_data.get("brightness", 80),
        timeout_seconds=display_data.get("timeout_seconds", 300),
        theme=display_data.get("theme", "neon"),
    )

    # Parse mode config
    mode_data = data.get("mode", {})
    mode = ModeConfig(
        default=mode_data.get("default", "auto"),
        auto_fallback_seconds=mode_data.get("auto_fallback_seconds", 60),
        reconnect_interval_seconds=mode_data.get("reconnect_interval_seconds", 10),
    )

    # Parse web config
    web_data = data.get("web", {})
    web = WebConfig(
        enabled=web_data.get("enabled", True),
        port=web_data.get("port", 8080),
        bind=web_data.get("bind", "0.0.0.0"),
    )

    # Parse secuboxes config
    secuboxes_data = data.get("secuboxes", {})
    primary = secuboxes_data.get("primary", "")

    devices = []
    for sb_data in secuboxes_data.get("devices", []):
        devices.append(SecuBoxConfig(
            id=sb_data.get("id", ""),
            name=sb_data.get("name", "SecuBox"),
            host=sb_data.get("host", "10.55.0.1"),
            port=sb_data.get("port", 8000),
            token=sb_data.get("token", ""),
            transport=sb_data.get("transport", "otg"),
            active=sb_data.get("active", False),
            fallback=sb_data.get("fallback"),
            poll_interval=sb_data.get("poll_interval", 2.0),
        ))

    # Backward compatibility: support old "secubox" array format
    for sb_data in data.get("secubox", []):
        devices.append(SecuBoxConfig(
            name=sb_data.get("name", "SecuBox"),
            host=sb_data.get("host", "10.55.0.1"),
            port=sb_data.get("port", 8000),
            token=sb_data.get("token", ""),
            transport=sb_data.get("transport", "otg"),
            active=sb_data.get("active", False),
            fallback=sb_data.get("fallback"),
            poll_interval=sb_data.get("poll_interval", 2.0),
        ))

    secuboxes = SecuBoxesConfig(primary=primary, devices=devices)

    return Config(
        device=device,
        display=display,
        mode=mode,
        web=web,
        secuboxes=secuboxes,
    )


def get_active_secubox(config: Config) -> Optional[SecuBoxConfig]:
    """
    Get the currently active SecuBox config.

    Returns:
        Active SecuBox config or None if none active
    """
    # Check for explicitly active device
    for sb in config.secuboxes.devices:
        if sb.active:
            return sb

    # Check for primary device by ID
    if config.secuboxes.primary:
        for sb in config.secuboxes.devices:
            if sb.id == config.secuboxes.primary:
                return sb

    # Fallback to first device
    return config.secuboxes.devices[0] if config.secuboxes.devices else None


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
    for sb in config.secuboxes.devices:
        if sb.name == name:
            sb.active = True
            found = True
        else:
            sb.active = False
    return found
