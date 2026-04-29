#!/usr/bin/env python3
"""
SecuBox Eye Remote - Gadget Configuration

Manages USB gadget configuration from TOML file.
Supports ECM, ACM, Mass Storage, and Composite modes.

CyberMind - https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
"""

import os
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, Dict, Any

# Try to import tomllib (Python 3.11+) or tomli
try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib  # type: ignore
    except ImportError:
        tomllib = None  # type: ignore


CONFIG_PATHS = [
    Path("/etc/secubox/eye-remote/gadget.toml"),
    Path("/boot/firmware/secubox/gadget.toml"),
    Path.home() / ".config/secubox/gadget.toml",
    Path(__file__).parent.parent.parent / "config" / "gadget.toml",
]

DEFAULT_CONFIG = """
[gadget]
default_mode = "composite"
auto_switch = true
vendor_id = "0x1d6b"
product_id = "0x0104"
manufacturer = "SecuBox"
product = "Eye Remote"
serial_number = ""

[ecm]
host_ip = "10.55.0.1"
device_ip = "10.55.0.2"
netmask = "255.255.255.252"
host_mac = ""
device_mac = ""

[acm]
baudrate = 115200
console_enabled = true

[mass_storage]
partition = "/srv/eye-remote/storage.img"
readonly = false
removable = true
cdrom = false
"""


@dataclass
class EcmConfig:
    """ECM (Ethernet) gadget configuration."""
    host_ip: str = "10.55.0.1"
    device_ip: str = "10.55.0.2"
    netmask: str = "255.255.255.252"
    host_mac: str = ""  # Auto-generated if empty
    device_mac: str = ""  # Auto-generated if empty


@dataclass
class AcmConfig:
    """ACM (Serial) gadget configuration."""
    baudrate: int = 115200
    console_enabled: bool = True


@dataclass
class MassStorageConfig:
    """Mass Storage gadget configuration."""
    partition: str = "/srv/eye-remote/storage.img"
    readonly: bool = False
    removable: bool = True
    cdrom: bool = False


@dataclass
class GadgetConfig:
    """Main gadget configuration."""
    default_mode: str = "composite"
    auto_switch: bool = True
    vendor_id: str = "0x1d6b"
    product_id: str = "0x0104"
    manufacturer: str = "SecuBox"
    product: str = "Eye Remote"
    serial_number: str = ""

    ecm: EcmConfig = field(default_factory=EcmConfig)
    acm: AcmConfig = field(default_factory=AcmConfig)
    mass_storage: MassStorageConfig = field(default_factory=MassStorageConfig)

    _config_path: Optional[Path] = field(default=None, repr=False)


def _get_serial_from_cpuinfo() -> str:
    """Get serial number from /proc/cpuinfo (Pi-specific)."""
    try:
        with open("/proc/cpuinfo", "r") as f:
            for line in f:
                if line.startswith("Serial"):
                    return line.split(":")[1].strip()[-8:]
    except Exception:
        pass
    return "00000000"


def _generate_mac(prefix: str = "02:00:00") -> str:
    """Generate deterministic MAC address from CPU serial."""
    serial = _get_serial_from_cpuinfo()
    # Use serial to generate last 3 octets
    mac_suffix = ":".join([serial[i:i+2] for i in range(2, 8, 2)])
    return f"{prefix}:{mac_suffix}"


def load_config() -> GadgetConfig:
    """Load gadget configuration from file."""
    config = GadgetConfig()

    # Find config file
    config_path: Optional[Path] = None
    for path in CONFIG_PATHS:
        if path.exists():
            config_path = path
            break

    if config_path and tomllib:
        try:
            with open(config_path, "rb") as f:
                data = tomllib.load(f)

            # Parse [gadget] section
            gadget_data = data.get("gadget", {})
            config.default_mode = gadget_data.get("default_mode", config.default_mode)
            config.auto_switch = gadget_data.get("auto_switch", config.auto_switch)
            config.vendor_id = gadget_data.get("vendor_id", config.vendor_id)
            config.product_id = gadget_data.get("product_id", config.product_id)
            config.manufacturer = gadget_data.get("manufacturer", config.manufacturer)
            config.product = gadget_data.get("product", config.product)
            config.serial_number = gadget_data.get("serial_number", config.serial_number)

            # Parse [ecm] section
            ecm_data = data.get("ecm", {})
            config.ecm = EcmConfig(
                host_ip=ecm_data.get("host_ip", config.ecm.host_ip),
                device_ip=ecm_data.get("device_ip", config.ecm.device_ip),
                netmask=ecm_data.get("netmask", config.ecm.netmask),
                host_mac=ecm_data.get("host_mac", config.ecm.host_mac),
                device_mac=ecm_data.get("device_mac", config.ecm.device_mac),
            )

            # Parse [acm] section
            acm_data = data.get("acm", {})
            config.acm = AcmConfig(
                baudrate=acm_data.get("baudrate", config.acm.baudrate),
                console_enabled=acm_data.get("console_enabled", config.acm.console_enabled),
            )

            # Parse [mass_storage] section
            storage_data = data.get("mass_storage", {})
            config.mass_storage = MassStorageConfig(
                partition=storage_data.get("partition", config.mass_storage.partition),
                readonly=storage_data.get("readonly", config.mass_storage.readonly),
                removable=storage_data.get("removable", config.mass_storage.removable),
                cdrom=storage_data.get("cdrom", config.mass_storage.cdrom),
            )

            config._config_path = config_path

        except Exception as e:
            print(f"Error loading config from {config_path}: {e}")

    # Auto-generate serial if empty
    if not config.serial_number:
        config.serial_number = _get_serial_from_cpuinfo()

    # Auto-generate MAC addresses if empty
    if not config.ecm.host_mac:
        config.ecm.host_mac = _generate_mac("02:00:00")
    if not config.ecm.device_mac:
        config.ecm.device_mac = _generate_mac("02:00:01")

    return config


def save_config(config: GadgetConfig, path: Optional[Path] = None) -> bool:
    """Save gadget configuration to file."""
    if path is None:
        path = config._config_path or CONFIG_PATHS[0]

    try:
        # Ensure directory exists
        path.parent.mkdir(parents=True, exist_ok=True)

        # Build TOML content
        content = f"""# SecuBox Eye Remote - Gadget Configuration
# Auto-generated - edit with care

[gadget]
default_mode = "{config.default_mode}"
auto_switch = {str(config.auto_switch).lower()}
vendor_id = "{config.vendor_id}"
product_id = "{config.product_id}"
manufacturer = "{config.manufacturer}"
product = "{config.product}"
serial_number = "{config.serial_number}"

[ecm]
host_ip = "{config.ecm.host_ip}"
device_ip = "{config.ecm.device_ip}"
netmask = "{config.ecm.netmask}"
host_mac = "{config.ecm.host_mac}"
device_mac = "{config.ecm.device_mac}"

[acm]
baudrate = {config.acm.baudrate}
console_enabled = {str(config.acm.console_enabled).lower()}

[mass_storage]
partition = "{config.mass_storage.partition}"
readonly = {str(config.mass_storage.readonly).lower()}
removable = {str(config.mass_storage.removable).lower()}
cdrom = {str(config.mass_storage.cdrom).lower()}
"""

        path.write_text(content)
        config._config_path = path
        return True

    except Exception as e:
        print(f"Error saving config to {path}: {e}")
        return False


# Singleton config instance
_config: Optional[GadgetConfig] = None


def get_config() -> GadgetConfig:
    """Get singleton config instance."""
    global _config
    if _config is None:
        _config = load_config()
    return _config


def reload_config() -> GadgetConfig:
    """Reload config from file."""
    global _config
    _config = load_config()
    return _config
