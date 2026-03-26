"""SecuBox Device-Intel API - Asset Discovery and Fingerprinting

Enhanced with OpenWRT/SecuBox device detection:
- MAC vendor fingerprinting for router manufacturers
- HTTP probe for LuCI interface detection
- DHCP hostname pattern matching
- mDNS/Avahi service discovery
"""
import asyncio
import subprocess
import re
import os
import json
import socket
from pathlib import Path
from datetime import datetime
from typing import Optional
from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel
from secubox_core.auth import require_jwt
from secubox_core.config import get_config

app = FastAPI(title="SecuBox Device-Intel", version="1.2.1")
config = get_config("device-intel")

# OUI database path (install via apt: ieee-data)
OUI_DB_PATH = "/usr/share/ieee-data/oui.txt"
DEVICES_FILE = "/var/lib/secubox/device-intel/devices.json"
DHCP_LEASES = "/var/lib/dhcp/dhcpd.leases"
DNSMASQ_LEASES = "/var/lib/misc/dnsmasq.leases"

# Ensure state directory exists
Path("/var/lib/secubox/device-intel").mkdir(parents=True, exist_ok=True)

# OpenWRT/Router MAC vendor prefixes (common manufacturers)
ROUTER_VENDORS = {
    "TP-LINK": ["EC:08:6B", "50:C7:BF", "14:CC:20", "AC:84:C6", "C0:25:E9", "E4:F4:C6"],
    "Ubiquiti": ["DC:9F:DB", "24:A4:3C", "80:2A:A8", "F0:9F:C2", "78:8A:20", "68:72:51"],
    "GL.iNet": ["E4:95:6E", "94:83:C4"],
    "Netgear": ["A0:63:91", "20:0C:C8", "C0:FF:D4", "9C:D3:6D", "10:0D:7F"],
    "Asus": ["04:D9:F5", "AC:9E:17", "50:46:5D", "38:D5:47", "1C:87:2C"],
    "Linksys": ["20:AA:4B", "C0:56:27", "58:6D:8F", "A4:2B:8C"],
    "D-Link": ["1C:7E:E5", "28:10:7B", "90:94:E4", "C4:A8:1D", "78:54:2E"],
    "MikroTik": ["D4:01:C3", "4C:5E:0C", "6C:3B:6B", "C4:AD:34", "E4:8D:8C"],
    "OpenWrt": ["02:00:00"],  # OpenWrt default MAC prefix
    "Xiaomi": ["64:09:80", "78:11:DC", "28:6C:07", "50:64:2B"],
    "Huawei": ["48:46:FB", "20:F3:A3", "E0:24:7F", "88:CE:FA"],
}

# OpenWRT hostname patterns
OPENWRT_HOSTNAMES = [
    r"^openwrt",
    r"^lede",
    r"^gl-",  # GL.iNet
    r"^router",
    r"^secubox",
    r"^espressobin",
    r"^mochabin",
]


class DeviceNote(BaseModel):
    mac: str
    note: str


class DeviceTag(BaseModel):
    mac: str
    tags: list[str]


class OpenWRTProbeResult(BaseModel):
    ip: str
    is_openwrt: bool
    luci_detected: bool
    secubox_detected: bool
    version: Optional[str] = None
    hostname: Optional[str] = None


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


def _is_router_vendor(mac: str) -> tuple[bool, str]:
    """Check if MAC belongs to a known router vendor."""
    mac_upper = mac.upper().replace("-", ":")
    prefix = mac_upper[:8]

    for vendor, prefixes in ROUTER_VENDORS.items():
        for p in prefixes:
            if prefix.startswith(p.upper()):
                return True, vendor
    return False, ""


def _is_openwrt_hostname(hostname: str) -> bool:
    """Check if hostname matches OpenWRT patterns."""
    if not hostname:
        return False
    hostname_lower = hostname.lower()
    for pattern in OPENWRT_HOSTNAMES:
        if re.match(pattern, hostname_lower):
            return True
    return False


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


async def _probe_luci(ip: str, timeout: float = 2.0) -> dict:
    """Probe an IP for LuCI/OpenWRT interface."""
    result = {
        "luci_detected": False,
        "secubox_detected": False,
        "version": None,
        "model": None,
        "gl_inet": False,
        "secubox_theme": None
    }

    async def curl_get(url: str, return_body: bool = False) -> tuple[str, str]:
        """Helper to run curl and return status code and optionally body."""
        args = ["curl", "-s", "--connect-timeout", str(timeout), "-k"]
        if not return_body:
            args.extend(["-o", "/dev/null", "-w", "%{http_code}"])
        args.append(url)
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout + 1)
        return stdout.decode().strip(), stdout.decode() if return_body else ""

    # Try HTTP probe for LuCI
    for scheme in ["http", "https"]:
        if result["luci_detected"]:
            break
        try:
            code, _ = await curl_get(f"{scheme}://{ip}/cgi-bin/luci")
            if code in ["200", "301", "302", "401", "403"]:
                result["luci_detected"] = True

                # Get LuCI page to extract version/model
                _, body = await curl_get(f"{scheme}://{ip}/cgi-bin/luci", return_body=True)
                body_lower = body.lower()

                # Extract model from title (e.g., "GL-MT3000 - Dashboard - LuCI")
                import re
                model_match = re.search(r'<title>([^<]+)</title>', body, re.IGNORECASE)
                if model_match:
                    title = model_match.group(1)
                    if " - " in title:
                        result["model"] = title.split(" - ")[0].strip()

                # Extract LuCI version
                ver_match = re.search(r'git-[\d.]+-[a-f0-9]+', body)
                if ver_match:
                    result["version"] = ver_match.group(0)

                # Check for SecuBox - look for specific markers
                secubox_markers = [
                    "data-secubox-theme",
                    "luci-static/secubox",
                    "secubox-auth-hook",
                    "secubox-portal",
                    "secubox-public",
                    "luci-app-secubox",
                    "/luci/admin/secubox",
                    "secubox-dashboard",
                ]
                for marker in secubox_markers:
                    if marker in body_lower:
                        result["secubox_detected"] = True
                        break

                # Extract SecuBox theme if present
                theme_match = re.search(r'data-secubox-theme="([^"]+)"', body)
                if theme_match:
                    result["secubox_theme"] = theme_match.group(1)

                # Try alternative LuCI version format (e.g., luci.js?v=26.021.66732~...)
                if not result["version"]:
                    alt_ver_match = re.search(r'luci\.js\?v=([\d.~a-f0-9-]+)', body)
                    if alt_ver_match:
                        result["version"] = alt_ver_match.group(1)

        except (asyncio.TimeoutError, Exception):
            pass

    # Check for GL.iNet custom UI
    if not result["luci_detected"]:
        try:
            _, body = await curl_get(f"http://{ip}/", return_body=True)
            if "gl-ui" in body.lower() or "gl.inet" in body.lower():
                result["gl_inet"] = True
                # GL.iNet routers have LuCI at /cgi-bin/luci
                result["luci_detected"] = True
        except (asyncio.TimeoutError, Exception):
            pass

    return result


async def _discover_mdns_services() -> list[dict]:
    """Discover devices via mDNS/Avahi."""
    services = []

    try:
        # Use avahi-browse to discover services
        proc = await asyncio.create_subprocess_exec(
            "avahi-browse", "-t", "-r", "-p", "_http._tcp",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)

        for line in stdout.decode().split('\n'):
            if line.startswith('='):
                parts = line.split(';')
                if len(parts) >= 8:
                    services.append({
                        "name": parts[3],
                        "type": parts[4],
                        "hostname": parts[6],
                        "ip": parts[7],
                        "port": int(parts[8]) if parts[8].isdigit() else 80
                    })
    except (asyncio.TimeoutError, FileNotFoundError, Exception):
        pass

    return services


async def _scan_network(interface: str = "eth0", subnet: str = None) -> list[dict]:
    """Perform ARP scan on network."""
    devices = []

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
        "version": "1.1.0",
        "features": ["arp_scan", "dhcp_leases", "vendor_lookup", "openwrt_detection", "mdns_discovery"]
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
        hostname = lease.get("hostname", known.get("hostname", ""))

        # Check if it's a router vendor
        is_router, router_vendor = _is_router_vendor(mac)
        is_openwrt = _is_openwrt_hostname(hostname) or known.get("is_openwrt", False)

        devices.append({
            "mac": mac,
            "ip": dev["ip"],
            "interface": dev["interface"],
            "state": dev["state"],
            "vendor": _get_vendor(mac, oui_db),
            "hostname": hostname,
            "first_seen": known.get("first_seen", datetime.now().isoformat()),
            "last_seen": datetime.now().isoformat(),
            "note": known.get("note", ""),
            "tags": known.get("tags", []),
            "trusted": known.get("trusted", False),
            "is_router": is_router,
            "router_vendor": router_vendor,
            "is_openwrt": is_openwrt,
            "is_secubox": known.get("is_secubox", False),
            "secubox_version": known.get("secubox_version", None),
        })

    return {
        "devices": devices,
        "total": len(devices),
        "routers": sum(1 for d in devices if d["is_router"]),
        "openwrt_devices": sum(1 for d in devices if d["is_openwrt"]),
        "secubox_devices": sum(1 for d in devices if d["is_secubox"])
    }


@app.get("/device/{mac}", dependencies=[Depends(require_jwt)])
async def get_device(mac: str):
    """Get detailed info for a specific device."""
    oui_db = _load_oui_db()
    known_devices = _load_devices()
    arp_devices = _get_arp_table()
    dhcp_leases = _get_dhcp_leases()

    mac_upper = mac.upper()
    arp_info = next((d for d in arp_devices if d["mac"] == mac_upper), {})
    lease = dhcp_leases.get(mac_upper, {})
    known = known_devices.get(mac_upper, {})

    if not arp_info and not known:
        raise HTTPException(status_code=404, detail="Device not found")

    hostname = lease.get("hostname", known.get("hostname", ""))
    is_router, router_vendor = _is_router_vendor(mac_upper)
    is_openwrt = _is_openwrt_hostname(hostname) or known.get("is_openwrt", False)

    return {
        "mac": mac_upper,
        "ip": arp_info.get("ip", lease.get("ip", known.get("ip", ""))),
        "interface": arp_info.get("interface", ""),
        "state": arp_info.get("state", "UNKNOWN"),
        "vendor": _get_vendor(mac_upper, oui_db),
        "hostname": hostname,
        "first_seen": known.get("first_seen", datetime.now().isoformat()),
        "last_seen": datetime.now().isoformat(),
        "note": known.get("note", ""),
        "tags": known.get("tags", []),
        "trusted": known.get("trusted", False),
        "lease_expires": lease.get("expires", 0),
        "is_router": is_router,
        "router_vendor": router_vendor,
        "is_openwrt": is_openwrt,
        "is_secubox": known.get("is_secubox", False),
        "secubox_version": known.get("secubox_version", None),
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
    arp_devices = _get_arp_table()

    return {
        "success": True,
        "interface": interface,
        "devices_found": len(arp_devices)
    }


@app.post("/probe/openwrt", dependencies=[Depends(require_jwt)])
async def probe_openwrt_devices():
    """Probe all devices for OpenWRT/LuCI interface."""
    arp_devices = _get_arp_table()
    known_devices = _load_devices()
    results = []

    # Probe each device in parallel (max 10 concurrent)
    semaphore = asyncio.Semaphore(10)

    async def probe_with_semaphore(dev):
        async with semaphore:
            ip = dev["ip"]
            mac = dev["mac"]
            probe_result = await _probe_luci(ip, timeout=3.0)

            # Update known devices if OpenWRT detected
            if probe_result["luci_detected"]:
                if mac not in known_devices:
                    known_devices[mac] = {"first_seen": datetime.now().isoformat()}
                known_devices[mac]["is_openwrt"] = True
                known_devices[mac]["is_secubox"] = probe_result["secubox_detected"]
                known_devices[mac]["is_gl_inet"] = probe_result.get("gl_inet", False)
                known_devices[mac]["model"] = probe_result.get("model")
                known_devices[mac]["luci_version"] = probe_result.get("version")
                known_devices[mac]["ip"] = ip
                known_devices[mac]["last_probed"] = datetime.now().isoformat()

            return {
                "ip": ip,
                "mac": mac,
                "is_openwrt": probe_result["luci_detected"],
                "is_secubox": probe_result["secubox_detected"],
                "is_gl_inet": probe_result.get("gl_inet", False),
                "model": probe_result.get("model"),
                "version": probe_result.get("version")
            }

    tasks = [probe_with_semaphore(dev) for dev in arp_devices]
    results = await asyncio.gather(*tasks)

    # Save updated device info
    _save_devices(known_devices)

    openwrt_count = sum(1 for r in results if r["is_openwrt"])
    secubox_count = sum(1 for r in results if r["is_secubox"])

    return {
        "success": True,
        "total_probed": len(results),
        "openwrt_detected": openwrt_count,
        "secubox_detected": secubox_count,
        "results": results
    }


@app.post("/probe/openwrt/{ip}", dependencies=[Depends(require_jwt)])
async def probe_single_openwrt(ip: str):
    """Probe a single IP for OpenWRT/LuCI interface."""
    probe_result = await _probe_luci(ip, timeout=5.0)

    # Get MAC from ARP if available
    mac = None
    for dev in _get_arp_table():
        if dev["ip"] == ip:
            mac = dev["mac"]
            break

    # Check MAC vendor
    vendor = None
    is_router = False
    if mac:
        mac_prefix = mac[:8].upper()
        for vendor_name, prefixes in ROUTER_VENDORS.items():
            if mac_prefix in prefixes:
                vendor = vendor_name
                is_router = True
                break
        if not vendor:
            oui_db = _load_oui_db()
            vendor = _get_vendor(mac, oui_db)

    return {
        "ip": ip,
        "mac": mac,
        "vendor": vendor,
        "is_router": is_router,
        "is_openwrt": probe_result["luci_detected"],
        "is_secubox": probe_result["secubox_detected"],
        "is_gl_inet": probe_result.get("gl_inet", False),
        "model": probe_result.get("model"),
        "version": probe_result.get("version"),
        "secubox_theme": probe_result.get("secubox_theme")
    }


@app.get("/openwrt", dependencies=[Depends(require_jwt)])
async def get_openwrt_devices():
    """Get all detected OpenWRT/SecuBox devices."""
    known_devices = _load_devices()
    arp_devices = _get_arp_table()
    dhcp_leases = _get_dhcp_leases()
    oui_db = _load_oui_db()

    openwrt_devices = []

    for mac, info in known_devices.items():
        if info.get("is_openwrt") or info.get("is_secubox"):
            arp_info = next((d for d in arp_devices if d["mac"] == mac), {})
            lease = dhcp_leases.get(mac, {})

            openwrt_devices.append({
                "mac": mac,
                "ip": arp_info.get("ip", info.get("ip", "")),
                "hostname": lease.get("hostname", info.get("hostname", "")),
                "vendor": _get_vendor(mac, oui_db),
                "is_openwrt": info.get("is_openwrt", False),
                "is_secubox": info.get("is_secubox", False),
                "is_gl_inet": info.get("is_gl_inet", False),
                "model": info.get("model"),
                "luci_version": info.get("luci_version"),
                "secubox_version": info.get("secubox_version"),
                "online": bool(arp_info),
                "last_probed": info.get("last_probed"),
                "first_seen": info.get("first_seen"),
            })

    return {
        "devices": openwrt_devices,
        "total": len(openwrt_devices),
        "online": sum(1 for d in openwrt_devices if d["online"])
    }


@app.get("/mdns", dependencies=[Depends(require_jwt)])
async def discover_mdns():
    """Discover devices via mDNS/Avahi."""
    services = await _discover_mdns_services()
    return {
        "services": services,
        "total": len(services)
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
    openwrt = sum(1 for d in known_devices.values() if d.get("is_openwrt", False))
    secubox = sum(1 for d in known_devices.values() if d.get("is_secubox", False))
    gl_inet = sum(1 for d in known_devices.values() if d.get("is_gl_inet", False))

    return {
        "total_known": len(known_devices),
        "currently_online": len(arp_devices),
        "trusted_devices": trusted,
        "tagged_devices": tagged,
        "openwrt_devices": openwrt,
        "secubox_devices": secubox,
        "gl_inet_devices": gl_inet
    }


@app.get("/info", dependencies=[Depends(require_jwt)])
async def info():
    """Protected info endpoint."""
    return {"config": dict(config)}


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy", "service": "secubox-device-intel", "version": "1.1.0"}
