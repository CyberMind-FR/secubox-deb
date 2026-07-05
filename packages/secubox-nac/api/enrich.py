# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-nac — absorbed enrichers: OUI vendor lookup,
device-type classification, risk scoring, OpenWrt fingerprint (#817 Task 3).

Lifts the pure logic from the three legacy modules being retired:
- `packages/secubox-mac-guard/api/main.py` `_load_oui_db()`/`_get_vendor()`
  -> `load_oui()`/`oui_vendor()`.
- `packages/secubox-iot-guard/api/main.py` `IoTGuard.type_indicators` +
  `classify_device()` + `calculate_risk_score()`
  -> `classify_device_type()`/`risk_score()`.
- `packages/secubox-device-intel/api/main.py` `ROUTER_VENDORS` +
  `OPENWRT_HOSTNAMES` + `_is_router_vendor()`/`_is_openwrt_hostname()`
  -> `openwrt_fingerprint()`.

Pure stdlib, no FastAPI import. Import of this module has no side
effects: `load_oui()` only touches disk when called.
"""
from __future__ import annotations

import re

from .store import canon_mac

# --- OUI vendor lookup (from secubox-mac-guard's `_load_oui_db`/`_get_vendor`) ---


def load_oui(path: str = "/usr/share/ieee-data/oui.txt") -> dict:
    """Load the IEEE OUI database into a `{prefix: vendor}` map.

    `prefix` is the first 3 octets, lowercase, colon-separated (e.g.
    `aa:bb:cc`), so it can be looked up directly from a `canon_mac()`
    result. A missing or unreadable file yields `{}` — never raises.
    """
    oui: dict = {}
    try:
        with open(path, "r", errors="ignore") as f:
            for line in f:
                if "(hex)" not in line:
                    continue
                parts = line.split("(hex)")
                if len(parts) < 2:
                    continue
                prefix = parts[0].strip().replace("-", ":").lower()
                vendor = parts[1].strip()
                if prefix:
                    oui[prefix] = vendor
    except OSError:
        return {}
    return oui


def oui_vendor(mac: str, oui_map: dict) -> str:
    """Look up the vendor for `mac`'s first-3-octet prefix in `oui_map`."""
    mac = canon_mac(mac)
    if not mac:
        return "Unknown"
    prefix = ":".join(mac.split(":")[:3])
    return oui_map.get(prefix, "Unknown")


# --- Device-type classification + risk scoring (from secubox-iot-guard) ---

# Keyword map, order matters (first match wins) — from IoTGuard.type_indicators
_TYPE_INDICATORS = {
    "camera": ["camera", "ipcam", "hikvision", "dahua", "axis", "wyze", "ring", "nest"],
    "smart_tv": ["tv", "roku", "firetv", "chromecast", "appletv", "samsung", "lg", "sony"],
    "smart_speaker": ["echo", "alexa", "google-home", "homepod", "sonos"],
    "smart_home": ["philips-hue", "wemo", "smartthings", "tuya", "zigbee", "zwave"],
    "printer": ["printer", "hp", "epson", "canon", "brother", "xerox"],
    "router": ["router", "gateway", "ubiquiti", "mikrotik", "cisco", "netgear"],
    "phone": ["iphone", "android", "pixel", "samsung", "oneplus", "xiaomi"],
}

# Device-type risk contribution — from IoTGuard.calculate_risk_score's type_risk
_TYPE_RISK = {
    "camera": 20,
    "iot_sensor": 15,
    "smart_home": 15,
    "industrial": 25,
    "unknown": 10,
}

# Risky open ports — from IoTGuard.calculate_risk_score (telnet, ftp, http, rtsp)
_RISKY_PORTS = {23, 21, 80, 8080, 8443, 554}


def classify_device_type(hostname: str, vendor: str) -> str:
    """Classify a device from hostname + OUI vendor into a lowercase type
    string (e.g. "camera", "phone", "unknown")."""
    combined = f"{hostname or ''} {vendor or ''}".lower()
    for device_type, indicators in _TYPE_INDICATORS.items():
        for indicator in indicators:
            if indicator in combined:
                return device_type
    return "unknown"


def risk_score(device_type: str, is_router: bool, open_ports=None) -> tuple:
    """Score a device 0-100 and bucket it into low/medium/high.

    Base 50 + device-type risk + open-ports risk; a device already
    known to be a router is treated as trusted infrastructure and gets
    a discount rather than a penalty.
    """
    score = 50
    score += _TYPE_RISK.get(device_type, 0)
    if is_router:
        score -= 10
    for port in (open_ports or []):
        if port in _RISKY_PORTS:
            score += 5
    score = min(100, max(0, score))
    if score < 34:
        level = "low"
    elif score < 67:
        level = "medium"
    else:
        level = "high"
    return score, level


# --- OpenWrt / router fingerprint (from secubox-device-intel) ---

# OpenWRT/Router MAC vendor prefixes — from device-intel's ROUTER_VENDORS
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

# OpenWRT hostname patterns — from device-intel's OPENWRT_HOSTNAMES
OPENWRT_HOSTNAMES = [
    r"^openwrt",
    r"^lede",
    r"^gl-",  # GL.iNet
    r"^router",
    r"^secubox",
    r"^espressobin",
    r"^mochabin",
]

def _is_router_vendor(mac: str) -> tuple:
    """Check if MAC belongs to a known router vendor. From device-intel's
    `_is_router_vendor`."""
    mac_upper = mac.upper().replace("-", ":")
    prefix = mac_upper[:8]
    for vendor, prefixes in ROUTER_VENDORS.items():
        for p in prefixes:
            if prefix.startswith(p.upper()):
                return True, vendor
    return False, ""


def _is_openwrt_hostname(hostname: str) -> bool:
    """Check if hostname matches OpenWRT patterns. From device-intel's
    `_is_openwrt_hostname`."""
    if not hostname:
        return False
    hostname_lower = hostname.lower()
    for pattern in OPENWRT_HOSTNAMES:
        if re.match(pattern, hostname_lower):
            return True
    return False


def openwrt_fingerprint(hostname: str, mac: str = "") -> dict:
    """Fingerprint a device as OpenWrt/router from hostname (+ optional MAC).

    Returns `{is_openwrt, is_router, router_vendor}`. The active LuCI HTTP
    probe (device-intel's `_probe_luci`) is a separate on-demand endpoint
    (Task 6), not part of this passive fingerprint.
    """
    is_openwrt = _is_openwrt_hostname(hostname)
    is_router, vendor = _is_router_vendor(mac) if mac else (False, "")
    return {
        "is_openwrt": is_openwrt,
        "is_router": is_openwrt or is_router,
        "router_vendor": vendor or None,
    }
