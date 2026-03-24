"""SecuBox Device-Intel API - Asset Discovery and Fingerprinting"""
import asyncio
import subprocess
import re
import os
import json
from pathlib import Path
from datetime import datetime
from typing import Optional
from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel
from secubox_core.auth import require_jwt
from secubox_core.config import get_config

app = FastAPI(title="SecuBox Device-Intel")
config = get_config("device-intel")

# OUI database path (install via apt: ieee-data)
OUI_DB_PATH = "/usr/share/ieee-data/oui.txt"
DEVICES_FILE = "/var/lib/secubox/device-intel/devices.json"
DHCP_LEASES = "/var/lib/dhcp/dhcpd.leases"
DNSMASQ_LEASES = "/var/lib/misc/dnsmasq.leases"

# Ensure state directory exists
Path("/var/lib/secubox/device-intel").mkdir(parents=True, exist_ok=True)


class DeviceNote(BaseModel):
    mac: str
    note: str


class DeviceTag(BaseModel):
    mac: str
    tags: list[str]


def _load_oui_db() -> dict:
    """Load MAC vendor database."""
    oui = {}
    if not os.path.exists(OUI_DB_PATH):
        return oui
    try:
        with open(OUI_DB_PATH, 'r', errors='ignore') as f:
            for line in f:
                if "(hex)" in line:
                    parts = line.split("(hex)")
                    if len(parts) >= 2:
                        mac_prefix = parts[0].strip().replace("-", ":").upper()[:8]
                        vendor = parts[1].strip()
                        oui[mac_prefix] = vendor
    except Exception:
        pass
    return oui


def _get_vendor(mac: str, oui_db: dict) -> str:
    """Look up vendor from MAC address."""
    mac_upper = mac.upper().replace("-", ":")
    prefix = mac_upper[:8]
    return oui_db.get(prefix, "Unknown")


def _load_devices() -> dict:
    """Load known devices from state file."""
    if os.path.exists(DEVICES_FILE):
        try:
            with open(DEVICES_FILE, 'r') as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def _save_devices(devices: dict):
    """Save devices to state file."""
    try:
        with open(DEVICES_FILE, 'w') as f:
            json.dump(devices, f, indent=2)
    except Exception:
        pass


def _get_arp_table() -> list[dict]:
    """Get ARP table entries."""
    devices = []
    try:
        result = subprocess.run(
            ["ip", "neigh", "show"],
            capture_output=True, text=True, timeout=10
        )
        for line in result.stdout.strip().split('\n'):
            if not line:
                continue
            # Format: 192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
            parts = line.split()
            if len(parts) >= 5 and "lladdr" in parts:
                ip = parts[0]
                dev_idx = parts.index("dev") + 1 if "dev" in parts else -1
                lladdr_idx = parts.index("lladdr") + 1 if "lladdr" in parts else -1
                iface = parts[dev_idx] if dev_idx > 0 and dev_idx < len(parts) else ""
                mac = parts[lladdr_idx] if lladdr_idx > 0 and lladdr_idx < len(parts) else ""
                state = parts[-1] if parts[-1] in ["REACHABLE", "STALE", "DELAY", "PROBE", "FAILED", "PERMANENT"] else "UNKNOWN"
                if mac and re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', mac):
                    devices.append({
                        "ip": ip,
                        "mac": mac.upper(),
                        "interface": iface,
                        "state": state
                    })
    except Exception:
        pass
    return devices


def _get_dhcp_leases() -> dict:
    """Get DHCP lease information."""
    leases = {}

    # Try dnsmasq format first
    if os.path.exists(DNSMASQ_LEASES):
        try:
            with open(DNSMASQ_LEASES, 'r') as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 4:
                        # Format: timestamp mac ip hostname *
                        mac = parts[1].upper()
                        leases[mac] = {
                            "ip": parts[2],
                            "hostname": parts[3] if parts[3] != "*" else "",
                            "expires": int(parts[0]) if parts[0].isdigit() else 0
                        }
        except Exception:
            pass

    # Try ISC DHCP format
    if os.path.exists(DHCP_LEASES):
        try:
            with open(DHCP_LEASES, 'r') as f:
                content = f.read()
                lease_blocks = re.findall(r'lease\s+([\d.]+)\s*{([^}]+)}', content, re.MULTILINE)
                for ip, block in lease_blocks:
                    mac_match = re.search(r'hardware ethernet\s+([0-9a-fA-F:]+)', block)
                    hostname_match = re.search(r'client-hostname\s+"([^"]+)"', block)
                    if mac_match:
                        mac = mac_match.group(1).upper()
                        leases[mac] = {
                            "ip": ip,
                            "hostname": hostname_match.group(1) if hostname_match else "",
                            "expires": 0
                        }
        except Exception:
            pass

    return leases


async def _scan_network(interface: str = "eth0", subnet: str = None) -> list[dict]:
    """Perform ARP scan on network."""
    devices = []

    # Get subnet if not provided
    if not subnet:
        try:
            result = subprocess.run(
                ["ip", "-4", "addr", "show", interface],
                capture_output=True, text=True, timeout=5
            )
            match = re.search(r'inet\s+(\d+\.\d+\.\d+)\.\d+/(\d+)', result.stdout)
            if match:
                subnet = f"{match.group(1)}.0/{match.group(2)}"
        except Exception:
            subnet = "192.168.1.0/24"

    # Use nmap for ARP scan if available
    try:
        result = subprocess.run(
            ["nmap", "-sn", "-PR", subnet, "-oG", "-"],
            capture_output=True, text=True, timeout=60
        )
        for line in result.stdout.split('\n'):
            if "Host:" in line and "Status: Up" in line:
                ip_match = re.search(r'Host:\s+(\d+\.\d+\.\d+\.\d+)', line)
                if ip_match:
                    devices.append({"ip": ip_match.group(1)})
    except FileNotFoundError:
        # Fallback to arping
        try:
            for i in range(1, 255):
                ip = f"{subnet.rsplit('.', 2)[0]}.{i}"
                subprocess.run(
                    ["arping", "-c", "1", "-w", "1", ip],
                    capture_output=True, timeout=2
                )
        except Exception:
            pass

    return devices


def _get_network_interfaces() -> list[dict]:
    """Get list of network interfaces."""
    interfaces = []
    try:
        result = subprocess.run(
            ["ip", "-j", "link", "show"],
            capture_output=True, text=True, timeout=10
        )
        data = json.loads(result.stdout)
        for iface in data:
            if iface.get("ifname") not in ["lo"]:
                interfaces.append({
                    "name": iface.get("ifname", ""),
                    "mac": iface.get("address", ""),
                    "state": iface.get("operstate", "UNKNOWN"),
                    "mtu": iface.get("mtu", 1500)
                })
    except Exception:
        # Fallback
        try:
            result = subprocess.run(
                ["ip", "link", "show"],
                capture_output=True, text=True, timeout=10
            )
            for line in result.stdout.split('\n'):
                match = re.match(r'^\d+:\s+(\w+):', line)
                if match and match.group(1) != "lo":
                    interfaces.append({"name": match.group(1)})
        except Exception:
            pass
    return interfaces


@app.get("/status")
async def status():
    """Public status endpoint."""
    return {
        "module": "device-intel",
        "status": "ok",
        "version": "1.0.0"
    }


@app.get("/devices", dependencies=[Depends(require_jwt)])
async def get_devices():
    """Get all discovered devices with enriched data."""
    oui_db = _load_oui_db()
    known_devices = _load_devices()
    arp_devices = _get_arp_table()
    dhcp_leases = _get_dhcp_leases()

    devices = []
    seen_macs = set()

    for dev in arp_devices:
        mac = dev["mac"]
        if mac in seen_macs:
            continue
        seen_macs.add(mac)

        lease = dhcp_leases.get(mac, {})
        known = known_devices.get(mac, {})

        devices.append({
            "mac": mac,
            "ip": dev["ip"],
            "interface": dev["interface"],
            "state": dev["state"],
            "vendor": _get_vendor(mac, oui_db),
            "hostname": lease.get("hostname", known.get("hostname", "")),
            "first_seen": known.get("first_seen", datetime.now().isoformat()),
            "last_seen": datetime.now().isoformat(),
            "note": known.get("note", ""),
            "tags": known.get("tags", []),
            "trusted": known.get("trusted", False)
        })

    return {
        "devices": devices,
        "total": len(devices)
    }


@app.get("/device/{mac}", dependencies=[Depends(require_jwt)])
async def get_device(mac: str):
    """Get detailed info for a specific device."""
    oui_db = _load_oui_db()
    known_devices = _load_devices()
    arp_devices = _get_arp_table()
    dhcp_leases = _get_dhcp_leases()

    mac_upper = mac.upper()

    # Find in ARP table
    arp_info = next((d for d in arp_devices if d["mac"] == mac_upper), {})
    lease = dhcp_leases.get(mac_upper, {})
    known = known_devices.get(mac_upper, {})

    if not arp_info and not known:
        raise HTTPException(status_code=404, detail="Device not found")

    return {
        "mac": mac_upper,
        "ip": arp_info.get("ip", lease.get("ip", known.get("ip", ""))),
        "interface": arp_info.get("interface", ""),
        "state": arp_info.get("state", "UNKNOWN"),
        "vendor": _get_vendor(mac_upper, oui_db),
        "hostname": lease.get("hostname", known.get("hostname", "")),
        "first_seen": known.get("first_seen", datetime.now().isoformat()),
        "last_seen": datetime.now().isoformat(),
        "note": known.get("note", ""),
        "tags": known.get("tags", []),
        "trusted": known.get("trusted", False),
        "lease_expires": lease.get("expires", 0)
    }


@app.post("/device/note", dependencies=[Depends(require_jwt)])
async def set_device_note(data: DeviceNote):
    """Set a note for a device."""
    devices = _load_devices()
    mac = data.mac.upper()

    if mac not in devices:
        devices[mac] = {"first_seen": datetime.now().isoformat()}

    devices[mac]["note"] = data.note
    _save_devices(devices)

    return {"success": True, "mac": mac}


@app.post("/device/tags", dependencies=[Depends(require_jwt)])
async def set_device_tags(data: DeviceTag):
    """Set tags for a device."""
    devices = _load_devices()
    mac = data.mac.upper()

    if mac not in devices:
        devices[mac] = {"first_seen": datetime.now().isoformat()}

    devices[mac]["tags"] = data.tags
    _save_devices(devices)

    return {"success": True, "mac": mac}


@app.post("/device/{mac}/trust", dependencies=[Depends(require_jwt)])
async def trust_device(mac: str, trusted: bool = True):
    """Mark a device as trusted or untrusted."""
    devices = _load_devices()
    mac_upper = mac.upper()

    if mac_upper not in devices:
        devices[mac_upper] = {"first_seen": datetime.now().isoformat()}

    devices[mac_upper]["trusted"] = trusted
    _save_devices(devices)

    return {"success": True, "mac": mac_upper, "trusted": trusted}


@app.post("/scan", dependencies=[Depends(require_jwt)])
async def scan_network(interface: str = "eth0"):
    """Trigger network scan for device discovery."""
    await _scan_network(interface)

    # Refresh ARP table after scan
    arp_devices = _get_arp_table()

    return {
        "success": True,
        "interface": interface,
        "devices_found": len(arp_devices)
    }


@app.get("/interfaces", dependencies=[Depends(require_jwt)])
async def get_interfaces():
    """Get list of network interfaces."""
    return {"interfaces": _get_network_interfaces()}


@app.get("/stats", dependencies=[Depends(require_jwt)])
async def get_stats():
    """Get device discovery statistics."""
    known_devices = _load_devices()
    arp_devices = _get_arp_table()

    trusted = sum(1 for d in known_devices.values() if d.get("trusted", False))
    tagged = sum(1 for d in known_devices.values() if d.get("tags", []))

    return {
        "total_known": len(known_devices),
        "currently_online": len(arp_devices),
        "trusted_devices": trusted,
        "tagged_devices": tagged
    }


@app.get("/info", dependencies=[Depends(require_jwt)])
async def info():
    """Protected info endpoint."""
    return {"config": dict(config)}
