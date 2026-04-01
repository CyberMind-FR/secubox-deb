"""
secubox_core.kiosk — Kiosk mode and board detection utilities
=============================================================
- kiosk_status()         -> Current kiosk mode status
- kiosk_enable(mode)     -> Enable kiosk mode (x11/wayland)
- kiosk_disable()        -> Disable kiosk mode
- detect_board_type()    -> Auto-detect board type
- get_board_profile()    -> Get SecuBox profile for board
- get_interface_class()  -> Classify interfaces into WAN/LAN/SFP
"""
from __future__ import annotations
import subprocess
from pathlib import Path
from typing import Literal, Optional

from .logger import get_logger

log = get_logger("kiosk")

# ══════════════════════════════════════════════════════════════════
# Kiosk Mode Management
# ══════════════════════════════════════════════════════════════════

KIOSK_ENABLED_MARKER = Path("/var/lib/secubox/.kiosk-enabled")
KIOSK_MODE_FILE = Path("/var/lib/secubox/.kiosk-mode")
KIOSK_SETUP_SCRIPT = Path("/usr/sbin/secubox-kiosk-setup")


def kiosk_status() -> dict:
    """
    Get current kiosk mode status.

    Returns:
        {
            "enabled": bool,
            "mode": "x11" | "wayland" | "disabled",
            "service_active": bool,
            "service_enabled": bool,
        }
    """
    enabled = KIOSK_ENABLED_MARKER.exists()
    mode = "disabled"

    if KIOSK_MODE_FILE.exists():
        try:
            mode = KIOSK_MODE_FILE.read_text().strip()
        except Exception:
            mode = "unknown"

    # Check service status
    service_active = False
    service_enabled = False

    for service_name in ("secubox-kiosk", "secubox-kiosk-wayland"):
        try:
            r = subprocess.run(
                ["systemctl", "is-active", service_name],
                capture_output=True, text=True, timeout=5
            )
            if r.stdout.strip() == "active":
                service_active = True
                break
        except Exception:
            pass

        try:
            r = subprocess.run(
                ["systemctl", "is-enabled", service_name],
                capture_output=True, text=True, timeout=5
            )
            if r.stdout.strip() == "enabled":
                service_enabled = True
        except Exception:
            pass

    return {
        "enabled": enabled,
        "mode": mode if enabled else "disabled",
        "service_active": service_active,
        "service_enabled": service_enabled,
    }


def kiosk_enable(mode: Literal["x11", "wayland"] = "x11") -> dict:
    """
    Enable kiosk mode.

    Args:
        mode: Display mode - "x11" (recommended for VMs) or "wayland" (native hardware)

    Returns:
        {"success": bool, "error": str | None, "mode": str}
    """
    if mode not in ("x11", "wayland"):
        return {"success": False, "error": f"Invalid mode: {mode}", "mode": mode}

    if not KIOSK_SETUP_SCRIPT.exists():
        return {"success": False, "error": "Kiosk setup script not installed", "mode": mode}

    try:
        mode_flag = f"--{mode}"
        r = subprocess.run(
            [str(KIOSK_SETUP_SCRIPT), "enable", mode_flag],
            capture_output=True, text=True, timeout=120
        )

        if r.returncode == 0:
            log.info("Kiosk mode enabled: %s", mode)
            return {"success": True, "error": None, "mode": mode}
        else:
            error = r.stderr.strip() or r.stdout.strip() or "Unknown error"
            return {"success": False, "error": error, "mode": mode}

    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Setup timed out", "mode": mode}
    except Exception as e:
        return {"success": False, "error": str(e), "mode": mode}


def kiosk_disable() -> dict:
    """
    Disable kiosk mode.

    Returns:
        {"success": bool, "error": str | None}
    """
    if not KIOSK_SETUP_SCRIPT.exists():
        return {"success": False, "error": "Kiosk setup script not installed"}

    try:
        r = subprocess.run(
            [str(KIOSK_SETUP_SCRIPT), "disable"],
            capture_output=True, text=True, timeout=60
        )

        if r.returncode == 0:
            log.info("Kiosk mode disabled")
            return {"success": True, "error": None}
        else:
            error = r.stderr.strip() or r.stdout.strip() or "Unknown error"
            return {"success": False, "error": error}

    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Disable timed out"}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ══════════════════════════════════════════════════════════════════
# Board Detection
# ══════════════════════════════════════════════════════════════════

BOARD_PROFILES = {
    "mochabin": "full",
    "espressobin-v7": "lite",
    "espressobin-ultra": "lite",
    "x64-vm": "full",
    "x64-baremetal": "full",
    "rpi": "lite",
    "unknown": "lite",
}

BOARD_CAPABILITIES = {
    "mochabin": {
        "sfp_ports": 2,
        "lan_ports": 4,
        "cpu_cores": 4,
        "max_ram_gb": 8,
        "storage": ["eMMC", "SD", "USB", "SATA"],
        "features": ["SFP+", "DSA Switch", "Hardware NAT", "Crypto Offload"],
    },
    "espressobin-v7": {
        "sfp_ports": 0,
        "lan_ports": 2,
        "cpu_cores": 2,
        "max_ram_gb": 2,
        "storage": ["SD", "USB", "SATA"],
        "features": ["DSA Switch", "Crypto Offload"],
    },
    "espressobin-ultra": {
        "sfp_ports": 0,
        "lan_ports": 4,
        "cpu_cores": 2,
        "max_ram_gb": 4,
        "storage": ["eMMC", "SD", "USB", "SATA"],
        "features": ["DSA Switch", "Crypto Offload"],
    },
    "x64-vm": {
        "sfp_ports": 0,
        "lan_ports": "variable",
        "cpu_cores": "variable",
        "max_ram_gb": "variable",
        "storage": ["Virtual Disk"],
        "features": ["Full Software", "No Hardware Offload"],
    },
    "x64-baremetal": {
        "sfp_ports": "variable",
        "lan_ports": "variable",
        "cpu_cores": "variable",
        "max_ram_gb": "variable",
        "storage": ["SSD", "NVMe", "HDD"],
        "features": ["Full Software", "Hardware Dependent"],
    },
    "rpi": {
        "sfp_ports": 0,
        "lan_ports": 1,
        "cpu_cores": 4,
        "max_ram_gb": 8,
        "storage": ["SD", "USB"],
        "features": ["GPIO", "No Hardware NAT"],
    },
}


def detect_board_type() -> str:
    """
    Auto-detect board type from device-tree or DMI.

    Returns:
        Board type string: "mochabin", "espressobin-v7", "espressobin-ultra",
                          "x64-vm", "x64-baremetal", "rpi", or "unknown"
    """
    board = "unknown"

    # ARM: Check device-tree model
    model_path = Path("/proc/device-tree/model")
    if model_path.exists():
        try:
            model = model_path.read_text(errors="replace").strip().rstrip("\x00").lower()

            if "mochabin" in model or "7040" in model:
                board = "mochabin"
            elif "espressobin ultra" in model:
                board = "espressobin-ultra"
            elif "espressobin" in model or "3720" in model:
                board = "espressobin-v7"
            elif "raspberry" in model:
                board = "rpi"
            elif "marvell armada" in model:
                # Try to identify specific Armada variant
                compat_path = Path("/proc/device-tree/compatible")
                if compat_path.exists():
                    compat = compat_path.read_text(errors="replace").lower()
                    if "7040" in compat:
                        board = "mochabin"
                    elif "3720" in compat:
                        board = "espressobin-v7"
        except Exception as e:
            log.warning("Error reading device-tree: %s", e)

    # x64: Check DMI
    elif Path("/sys/class/dmi/id/product_name").exists():
        try:
            product = Path("/sys/class/dmi/id/product_name").read_text().strip().lower()

            vm_indicators = ["virtualbox", "qemu", "vmware", "kvm", "virtual machine", "bochs"]
            if any(vm in product for vm in vm_indicators):
                board = "x64-vm"
            else:
                board = "x64-baremetal"
        except Exception as e:
            log.warning("Error reading DMI: %s", e)
            board = "x64-unknown"

    return board


def get_board_profile(board_type: Optional[str] = None) -> str:
    """
    Get SecuBox profile for the given or detected board type.

    Args:
        board_type: Optional board type. If None, auto-detect.

    Returns:
        Profile string: "full" or "lite"
    """
    if board_type is None:
        board_type = detect_board_type()

    return BOARD_PROFILES.get(board_type, "lite")


def get_board_capabilities(board_type: Optional[str] = None) -> dict:
    """
    Get capabilities for the given or detected board type.

    Args:
        board_type: Optional board type. If None, auto-detect.

    Returns:
        Capabilities dict with sfp_ports, lan_ports, cpu_cores, etc.
    """
    if board_type is None:
        board_type = detect_board_type()

    return BOARD_CAPABILITIES.get(board_type, {
        "sfp_ports": 0,
        "lan_ports": "unknown",
        "cpu_cores": "unknown",
        "max_ram_gb": "unknown",
        "storage": ["unknown"],
        "features": [],
    })


def get_board_model() -> str:
    """
    Get the full board model string.

    Returns:
        Model string from device-tree or DMI
    """
    # Try device-tree first (ARM)
    model_path = Path("/proc/device-tree/model")
    if model_path.exists():
        try:
            return model_path.read_text(errors="replace").strip().rstrip("\x00")
        except Exception:
            pass

    # Try DMI (x64)
    dmi_product = Path("/sys/class/dmi/id/product_name")
    dmi_vendor = Path("/sys/class/dmi/id/sys_vendor")
    if dmi_product.exists():
        try:
            model = dmi_product.read_text().strip()
            if dmi_vendor.exists():
                vendor = dmi_vendor.read_text().strip()
                return f"{vendor} {model}"
            return model
        except Exception:
            pass

    return "Unknown"


# ══════════════════════════════════════════════════════════════════
# Network Interface Classification
# ══════════════════════════════════════════════════════════════════

def get_physical_interfaces() -> list[str]:
    """
    Get list of physical network interface names.

    Returns:
        List of interface names (excludes lo, veth, docker, wg, tun, tap, virbr)
    """
    interfaces = []

    net_path = Path("/sys/class/net")
    if not net_path.exists():
        return interfaces

    for iface_path in net_path.iterdir():
        name = iface_path.name

        # Skip non-physical interfaces
        if name in ("lo",):
            continue
        if name.startswith(("veth", "docker", "br-", "wg", "tun", "tap", "virbr")):
            continue

        # Check if it's a physical device or known pattern
        device_path = iface_path / "device"
        if device_path.exists() or name.startswith(("eth", "lan", "enp", "eno", "ens")):
            interfaces.append(name)

    return sorted(interfaces)


def check_interface_carrier(interface: str) -> bool:
    """
    Check if interface has carrier (cable connected).

    Args:
        interface: Interface name

    Returns:
        True if carrier detected, False otherwise
    """
    carrier_path = Path(f"/sys/class/net/{interface}/carrier")
    if carrier_path.exists():
        try:
            return carrier_path.read_text().strip() == "1"
        except Exception:
            pass
    return False


def get_interface_classification(board_type: Optional[str] = None) -> dict:
    """
    Classify physical interfaces into WAN/LAN/SFP based on board type.

    Args:
        board_type: Optional board type. If None, auto-detect.

    Returns:
        {"wan": [...], "lan": [...], "sfp": [...]}
    """
    if board_type is None:
        board_type = detect_board_type()

    interfaces = get_physical_interfaces()
    result = {"wan": [], "lan": [], "sfp": []}

    if board_type == "mochabin":
        # MOCHAbin: eth0=WAN, eth1-4=LAN, eth5-6=SFP
        for name in interfaces:
            if name == "eth0":
                result["wan"].append(name)
            elif name in ("eth5", "eth6") or name.startswith("sfp"):
                result["sfp"].append(name)
            elif name.startswith(("eth", "lan")):
                result["lan"].append(name)

    elif board_type in ("espressobin-v7", "espressobin-ultra"):
        # ESPRESSObin: eth0=WAN, lan0/lan1=LAN
        for name in interfaces:
            if name == "eth0":
                result["wan"].append(name)
            elif name.startswith("lan"):
                result["lan"].append(name)

    else:
        # x64 or unknown: use carrier detection and naming convention
        carrier_ifaces = [n for n in interfaces if check_interface_carrier(n)]

        if carrier_ifaces:
            # Prefer common WAN interface names
            wan_candidates = ["eth0", "enp0s3", "enp1s0", "eno1", "ens33"]
            for cand in wan_candidates:
                if cand in carrier_ifaces:
                    result["wan"].append(cand)
                    break

            if not result["wan"] and carrier_ifaces:
                result["wan"].append(carrier_ifaces[0])

            # Rest with carrier = LAN
            result["lan"] = [n for n in carrier_ifaces if n not in result["wan"]]
        else:
            # No carrier detected: use naming convention
            for name in interfaces:
                if name in ("eth0", "enp0s3", "enp1s0", "eno1", "ens33"):
                    result["wan"].append(name)
                else:
                    result["lan"].append(name)

    return result
