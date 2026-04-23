#!/usr/bin/env python3
"""Configure USB network interface for OTG connection.

For Linux/Mac hosts: Only configure usb1 (ECM) to avoid routing issues.
The composite gadget creates:
  - usb0: RNDIS (Windows compatible)
  - usb1: ECM (Linux/Mac compatible via cdc_ether driver)

Linux hosts use the cdc_ether driver which maps to usb1.
Configuring both interfaces with the same IP causes asymmetric routing.

CyberMind - https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
"""
import subprocess
import time
from pathlib import Path

LOG = "/var/log/usb_network_debug.log"


def log(msg: str) -> None:
    """Log message to file and stdout."""
    with open(LOG, "a") as f:
        f.write(f"{time.strftime('%H:%M:%S')} {msg}\n")
    print(msg)


def configure_interface(iface: str, ip: str) -> bool:
    """Configure a USB network interface with IP address."""
    if not Path(f"/sys/class/net/{iface}").exists():
        return False

    log(f"Configuring {iface} with {ip}")

    # Flush existing addresses
    r = subprocess.run(["/sbin/ip", "addr", "flush", "dev", iface],
                       capture_output=True, text=True)
    log(f"  flush: rc={r.returncode}")

    # Add IP address
    r = subprocess.run(["/sbin/ip", "addr", "add", ip, "dev", iface],
                       capture_output=True, text=True)
    log(f"  addr add: rc={r.returncode}")

    # Bring interface up
    r = subprocess.run(["/sbin/ip", "link", "set", iface, "up"],
                       capture_output=True, text=True)
    log(f"  link up: rc={r.returncode}")

    # Show final state
    r = subprocess.run(["ip", "addr", "show", iface], capture_output=True, text=True)
    log(f"  state:\n{r.stdout}")

    return r.returncode == 0


def main() -> bool:
    """Configure USB network interface."""
    log("=== USB Network Config Started ===")
    log("Linux/Mac hosts use ECM (usb1), Windows uses RNDIS (usb0)")

    # Wait for usb1 (ECM) interface - this is what Linux hosts use
    for attempt in range(30):
        if Path("/sys/class/net/usb1").exists():
            log(f"usb1 (ECM) found at attempt {attempt + 1}")
            configure_interface("usb1", "10.55.0.2/30")
            log("=== USB Network Config Complete ===")
            return True
        time.sleep(1)

    # Fallback to usb0 if usb1 doesn't appear (Windows host or single-function gadget)
    if Path("/sys/class/net/usb0").exists():
        log("usb1 not found, falling back to usb0 (RNDIS)")
        configure_interface("usb0", "10.55.0.2/30")
        return True

    log("ERROR: No USB interfaces found after 30 seconds")
    return False


if __name__ == "__main__":
    main()
