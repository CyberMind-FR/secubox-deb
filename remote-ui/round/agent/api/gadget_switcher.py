#!/usr/bin/env python3
"""
SecuBox Eye Remote - Gadget Mode Switcher

Switches USB gadget modes via configfs/libcomposite.
Requires root privileges for actual mode changes.

CyberMind - https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
"""

import os
import subprocess
import time
from pathlib import Path
from enum import Enum
from dataclasses import dataclass
from typing import Optional, List, Tuple

from .gadget_config import get_config, GadgetConfig


class SwitchResult(Enum):
    """Result of mode switch operation."""
    SUCCESS = "success"
    ALREADY_ACTIVE = "already_active"
    PERMISSION_DENIED = "permission_denied"
    UDC_NOT_FOUND = "udc_not_found"
    CONFIGFS_ERROR = "configfs_error"
    SCRIPT_ERROR = "script_error"
    TIMEOUT = "timeout"


@dataclass
class SwitchStatus:
    """Status of a mode switch operation."""
    result: SwitchResult
    message: str
    previous_mode: str
    current_mode: str
    duration_ms: float = 0.0


# ConfigFS paths
CONFIGFS_BASE = Path("/sys/kernel/config/usb_gadget")
GADGET_NAME = "secubox"
GADGET_PATH = CONFIGFS_BASE / GADGET_NAME

# Mode switch script (runs with sudo)
SWITCH_SCRIPT = Path("/usr/lib/secubox/eye-gadget-switch.sh")
FALLBACK_SCRIPT = Path(__file__).parent.parent.parent / "scripts" / "eye-gadget-switch.sh"


def _find_udc() -> Optional[str]:
    """Find available UDC (USB Device Controller)."""
    udc_path = Path("/sys/class/udc")
    if udc_path.exists():
        udcs = list(udc_path.iterdir())
        if udcs:
            return udcs[0].name
    return None


def _get_current_udc() -> Optional[str]:
    """Get currently bound UDC."""
    udc_file = GADGET_PATH / "UDC"
    if udc_file.exists():
        try:
            return udc_file.read_text().strip() or None
        except Exception:
            pass
    return None


def _get_active_functions() -> List[str]:
    """Get list of active gadget functions."""
    functions = []
    configs_path = GADGET_PATH / "configs" / "c.1"

    if configs_path.exists():
        try:
            for item in configs_path.iterdir():
                if item.is_symlink():
                    functions.append(item.name)
        except Exception:
            pass

    return functions


def _detect_current_mode() -> str:
    """Detect current gadget mode from active functions."""
    functions = _get_active_functions()

    has_ecm = any("ecm" in f or "eem" in f or "rndis" in f for f in functions)
    has_acm = any("acm" in f for f in functions)
    has_storage = any("mass_storage" in f for f in functions)

    if has_ecm and has_acm and has_storage:
        return "composite"
    elif has_ecm and has_acm:
        return "composite"
    elif has_ecm:
        return "ecm"
    elif has_acm:
        return "acm"
    elif has_storage:
        return "mass_storage"

    return "none"


def _run_switch_script(mode: str, config: GadgetConfig) -> Tuple[bool, str]:
    """Run the mode switch script."""
    # Find script
    script = SWITCH_SCRIPT if SWITCH_SCRIPT.exists() else FALLBACK_SCRIPT

    if not script.exists():
        return False, f"Switch script not found: {script}"

    # Build environment with config
    env = os.environ.copy()
    env.update({
        "GADGET_MODE": mode,
        "GADGET_VENDOR_ID": config.vendor_id,
        "GADGET_PRODUCT_ID": config.product_id,
        "GADGET_MANUFACTURER": config.manufacturer,
        "GADGET_PRODUCT": config.product,
        "GADGET_SERIAL": config.serial_number,
        "ECM_HOST_IP": config.ecm.host_ip,
        "ECM_DEVICE_IP": config.ecm.device_ip,
        "ECM_HOST_MAC": config.ecm.host_mac,
        "ECM_DEVICE_MAC": config.ecm.device_mac,
        "ACM_BAUDRATE": str(config.acm.baudrate),
        "STORAGE_FILE": config.mass_storage.partition,
        "STORAGE_READONLY": "1" if config.mass_storage.readonly else "0",
    })

    try:
        # Try with sudo first
        result = subprocess.run(
            ["sudo", str(script), mode],
            capture_output=True,
            text=True,
            timeout=10,
            env=env
        )

        if result.returncode == 0:
            return True, result.stdout.strip() or "Mode switched successfully"
        else:
            return False, result.stderr.strip() or f"Script returned {result.returncode}"

    except subprocess.TimeoutExpired:
        return False, "Script timeout"
    except FileNotFoundError:
        return False, "sudo not found"
    except Exception as e:
        return False, str(e)


def _switch_mode_direct(mode: str, config: GadgetConfig) -> Tuple[bool, str]:
    """Switch mode directly via configfs (requires root)."""
    if os.geteuid() != 0:
        return False, "Root privileges required"

    udc = _find_udc()
    if not udc:
        return False, "No UDC found"

    try:
        # Unbind current gadget
        udc_file = GADGET_PATH / "UDC"
        if udc_file.exists():
            current = udc_file.read_text().strip()
            if current:
                udc_file.write_text("")
                time.sleep(0.1)

        # Remove old function symlinks
        configs_path = GADGET_PATH / "configs" / "c.1"
        if configs_path.exists():
            for item in configs_path.iterdir():
                if item.is_symlink():
                    item.unlink()

        # Create new function symlinks based on mode
        functions_path = GADGET_PATH / "functions"

        if mode == "ecm" or mode == "composite":
            ecm_func = functions_path / "ecm.usb0"
            if ecm_func.exists():
                (configs_path / "ecm.usb0").symlink_to(ecm_func)

        if mode == "acm" or mode == "composite":
            acm_func = functions_path / "acm.usb0"
            if acm_func.exists():
                (configs_path / "acm.usb0").symlink_to(acm_func)

        if mode == "mass_storage" or mode == "composite":
            storage_func = functions_path / "mass_storage.usb0"
            if storage_func.exists():
                (configs_path / "mass_storage.usb0").symlink_to(storage_func)

        # Rebind gadget
        if mode != "none":
            time.sleep(0.1)
            udc_file.write_text(udc)

        return True, f"Switched to {mode}"

    except PermissionError:
        return False, "Permission denied"
    except Exception as e:
        return False, str(e)


def switch_mode(mode: str) -> SwitchStatus:
    """Switch to specified gadget mode.

    Args:
        mode: One of 'none', 'ecm', 'acm', 'mass_storage', 'composite'

    Returns:
        SwitchStatus with result details
    """
    start_time = time.time()
    config = get_config()
    previous_mode = _detect_current_mode()

    # Validate mode
    valid_modes = ["none", "ecm", "acm", "mass_storage", "composite"]
    if mode not in valid_modes:
        return SwitchStatus(
            result=SwitchResult.CONFIGFS_ERROR,
            message=f"Invalid mode: {mode}. Valid modes: {valid_modes}",
            previous_mode=previous_mode,
            current_mode=previous_mode,
            duration_ms=(time.time() - start_time) * 1000
        )

    # Check if already in requested mode
    if mode == previous_mode:
        return SwitchStatus(
            result=SwitchResult.ALREADY_ACTIVE,
            message=f"Already in {mode} mode",
            previous_mode=previous_mode,
            current_mode=mode,
            duration_ms=(time.time() - start_time) * 1000
        )

    # Try script first (handles sudo)
    success, message = _run_switch_script(mode, config)

    if not success:
        # Fall back to direct configfs if we're root
        if os.geteuid() == 0:
            success, message = _switch_mode_direct(mode, config)

    # Verify the switch
    time.sleep(0.2)
    current_mode = _detect_current_mode()

    if success and current_mode == mode:
        result = SwitchResult.SUCCESS
    elif success:
        result = SwitchResult.SUCCESS
        message = f"{message} (mode may take time to activate)"
    elif "permission" in message.lower():
        result = SwitchResult.PERMISSION_DENIED
    elif "udc" in message.lower():
        result = SwitchResult.UDC_NOT_FOUND
    elif "timeout" in message.lower():
        result = SwitchResult.TIMEOUT
    elif "script" in message.lower():
        result = SwitchResult.SCRIPT_ERROR
    else:
        result = SwitchResult.CONFIGFS_ERROR

    return SwitchStatus(
        result=result,
        message=message,
        previous_mode=previous_mode,
        current_mode=current_mode,
        duration_ms=(time.time() - start_time) * 1000
    )


def get_available_modes() -> List[str]:
    """Get list of available gadget modes based on system capabilities."""
    modes = ["none"]

    # Check for UDC
    if not _find_udc():
        return modes

    # Check configfs
    if not CONFIGFS_BASE.exists():
        return modes

    # Check available functions
    functions_path = GADGET_PATH / "functions"
    if functions_path.exists():
        has_ecm = (functions_path / "ecm.usb0").exists()
        has_acm = (functions_path / "acm.usb0").exists()
        has_storage = (functions_path / "mass_storage.usb0").exists()

        if has_ecm:
            modes.append("ecm")
        if has_acm:
            modes.append("acm")
        if has_storage:
            modes.append("mass_storage")
        if has_ecm and has_acm:
            modes.append("composite")
    else:
        # Assume all modes available if gadget not yet created
        modes.extend(["ecm", "acm", "mass_storage", "composite"])

    return modes


def get_current_mode() -> str:
    """Get current gadget mode."""
    return _detect_current_mode()


def is_gadget_bound() -> bool:
    """Check if gadget is bound to UDC."""
    return _get_current_udc() is not None
