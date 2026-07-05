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

#820 (ref #817 follow-up): `classify_device_type` coverage expanded +
`reclassify_all()` backfill added — see the two sections below.
"""
from __future__ import annotations

import logging
import re

from .discovery import discover
from .store import canon_mac

logger = logging.getLogger("secubox.nac.enrich")

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


def oui_vendor(mac: str, oui_map: dict) -> str | None:
    """Look up the vendor for `mac`'s first-3-octet prefix in `oui_map`.

    #817 whole-branch fix (I4): returns `None` on a miss (bad MAC or
    unknown prefix), NOT the sentinel string "Unknown". A non-null
    "Unknown" would overwrite a real, previously-migrated vendor through
    `upsert`'s best-value COALESCE merge; `None` lets the stored value
    survive (and callers omit the field entirely when it is None).
    """
    mac = canon_mac(mac)
    if not mac:
        return None
    prefix = ":".join(mac.split(":")[:3])
    return oui_map.get(prefix)


# --- Device-type classification + risk scoring (from secubox-iot-guard) ---

# Keyword map, order matters (first match wins) — from IoTGuard.type_indicators,
# greatly expanded (#820, ref #817) to cut the "unknown" rate on the live
# 277-device board inventory. Categories are ordered deliberately, not
# alphabetically, to resolve substring-shadowing between them:
#   - camera before smart_speaker/smart_home so "nest-cam" wins over the
#     broader "nest-" (smart_home) / "nest-audio" (smart_speaker) patterns.
#   - tablet before phone so "galaxy-tab" wins over phone's bare "galaxy".
# `router` was NARROWED (not just expanded): the pre-820 list included
# "netgear", which directly regresses risk_score's rogue-AP signal (a
# generic Netgear device is common consumer gear, not necessarily a
# router) — see the RISK NOTE on `classify_device_type` below. Every
# other pre-820 indicator is kept verbatim; only new indicators were
# added to the remaining categories.
_TYPE_INDICATORS = {
    "camera": [
        "camera", "cam", "ipcam", "hikvision", "dahua", "axis", "wyze", "ring",
        "nest-cam", "reolink", "foscam", "doorbell",
    ],
    "smart_tv": [
        "tv", "roku", "firetv", "chromecast", "appletv", "samsung", "lg", "sony",
        "bravia", "aquos", "fire-tv", "apple-tv", "shield", "googletv",
        "lg-webos", "samsung-tizen",
    ],
    "smart_speaker": [
        "echo", "alexa", "google-home", "homepod", "sonos",
        "nest-audio", "nest-mini", "speaker",
    ],
    "smart_home": [
        "philips-hue", "wemo", "smartthings", "tuya", "zigbee", "zwave",
        "hue", "lifx", "tasmota", "shelly", "sonoff", "esphome", "esp32",
        "esp8266", "tradfri", "meross", "nest-", "thermostat", "doorlock",
        "smartplug",
    ],
    "printer": [
        "printer", "hp", "epson", "canon", "brother", "xerox",
        "print", "officejet", "laserjet", "lexmark", "kyocera",
    ],
    # RISK NOTE: keep this CONSERVATIVE — `risk_score()` treats
    # device_type=="router" as the rogue-AP signal (a newly-seen router
    # scores HIGH regardless of ports). Only unambiguous
    # networking-vendor/hostname indicators belong here. Generic
    # consumer-router brands (tp-link/netgear/asus/samsung/...) make many
    # kinds of devices and must NOT land here — see `_VENDOR_TYPE` below,
    # which deliberately omits them too (or routes them elsewhere, e.g.
    # tp-link -> iot).
    "router": [
        "router", "gateway", "ubiquiti", "mikrotik", "cisco",
        "openwrt", "dd-wrt", "access-point", "accesspoint", "-ap-",
        "unifi", "ubnt", "edgerouter",
    ],
    "nas": ["nas", "synology", "diskstation", "qnap", "truenas", "freenas", "unraid"],
    "game_console": ["playstation", "ps4", "ps5", "xbox", "nintendo", "switch-", "steamdeck"],
    "wearable": ["watch", "fitbit", "garmin", "wearable", "smartband", "mi-band"],
    # tablet before phone: "ipad"/"galaxy-tab" must win over phone's bare
    # "galaxy" (Galaxy Tab hostnames contain both substrings).
    "tablet": ["ipad", "tablet", "galaxy-tab", "kindle"],
    "phone": [
        "iphone", "android", "pixel", "samsung", "oneplus", "xiaomi",
        "galaxy", "samsung-", "redmi", "huawei", "oppo", "mobile", "phone",
    ],
    "laptop": ["laptop", "notebook", "macbook", "thinkpad", "xps", "zenbook"],
    "computer": [
        "pc", "desktop", "imac", "windows", "ubuntu", "linux", "fedora",
        "debian", "workstation", "hackintosh", "raspberrypi", "raspberry-pi", "raspi",
    ],
    "iot": ["iot", "sensor", "plc", "homeassistant", "hassio", "printer-scale"],
}

# OUI-vendor -> type fallback (#820), consulted ONLY when the hostname/
# vendor keyword pass above matched nothing at all. Ordered list (first
# match wins), substrings matched against the lowercased vendor string
# alone. Deliberately conservative on `router` — see the RISK NOTE above;
# generic multi-purpose brands (tp-link, asus, netgear, ...) are routed
# to a non-router type (or omitted entirely, falling through to
# `unknown`) rather than `router`.
_VENDOR_TYPE = [
    ("hikvision", "camera"),
    ("dahua", "camera"),
    ("axis", "camera"),
    ("reolink", "camera"),
    ("sonos", "smart_speaker"),
    ("amazon", "smart_speaker"),
    ("google", "smart_home"),
    ("hewlett", "printer"),
    ("canon", "printer"),
    ("epson", "printer"),
    ("brother", "printer"),
    ("ubiquiti", "router"),
    ("mikrotik", "router"),
    ("cisco", "router"),
    ("synology", "nas"),
    ("qnap", "nas"),
    ("sony interactive", "game_console"),
    ("nintendo", "game_console"),
    ("microsoft", "game_console"),
    ("espressif", "iot"),
    ("tuya", "iot"),
    ("shelly", "iot"),
    ("sonoff", "iot"),
    ("tp-link", "iot"),  # NOTE: tp-link makes routers AND iot gear — default iot, never router.
    ("raspberry", "computer"),
    ("intel", "computer"),
    ("dell", "computer"),
    ("lenovo", "computer"),
    ("asustek", "computer"),
    ("fitbit", "wearable"),
    ("garmin", "wearable"),
    ("apple", "phone"),
    ("samsung", "phone"),
]

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
    string (e.g. "camera", "phone", "unknown").

    Two passes (#820, ref #817): the hostname/vendor keyword pass
    (`_TYPE_INDICATORS`) runs first, as before. Only when it matches
    NOTHING does an OUI-vendor-only fallback (`_VENDOR_TYPE`) run — this
    keeps a hostname-level match always authoritative, and only guesses
    from the vendor brand when the hostname gave no signal at all.
    Return value is always one of the fixed set the webui `TYPE_ICON`
    maps understand (router, phone, computer, laptop, tablet, camera,
    smart_tv, smart_speaker, smart_home, printer, nas, game_console,
    wearable, iot, unknown).
    """
    combined = f"{hostname or ''} {vendor or ''}".lower()
    for device_type, indicators in _TYPE_INDICATORS.items():
        for indicator in indicators:
            if indicator in combined:
                return device_type

    vendor_lower = (vendor or "").lower()
    if vendor_lower:
        for indicator, device_type in _VENDOR_TYPE:
            if indicator in vendor_lower:
                return device_type

    return "unknown"


def risk_score(device_type: str, is_router: bool, is_known: bool = False, open_ports=None) -> tuple:
    """Score a device 0-100 and bucket it into low/medium/high.

    #817 addendum (Task 10): routers are scored on a dedicated axis —
    trust, not device-type/port heuristics. A router/gateway already
    KNOWN (allow-listed or already present in the store) is trusted
    infrastructure -> LOW risk. A NEWLY-seen/unknown router is a
    rogue-AP signal -> HIGH risk, regardless of open ports. The old flat
    -10 "trusted router" discount is removed; non-router devices keep
    the existing base-50 + type-risk + open-ports scoring unchanged.
    """
    if is_router or device_type == "router":
        score = 20 if is_known else 85
        score = min(100, max(0, score))
        if score < 34:
            level = "low"
        elif score < 67:
            level = "medium"
        else:
            level = "high"
        return score, level

    score = 50
    score += _TYPE_RISK.get(device_type, 0)
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
        "is_router": is_router,
        "router_vendor": vendor or None,
    }


# --- Backfill: reclassify + resolve source for every stored device (#820, ref #817) ---

# Legacy-module source tags migrated by `store.migrate_legacy()`. These
# modules are being retired, so any row still carrying one of these tags
# has never been re-confirmed by a live discovery cycle since migration.
_LEGACY_SOURCE_TAGS = {"mac-guard", "device-intel", "iot-guard"}


def reclassify_all(store, *, discover_kwargs: dict | None = None) -> dict:
    """Backfill `device_type`/`risk_score`/`risk_level`/`source` for every
    device already in `store`.

    Mirrors exactly how `Collector.cycle_once()` enriches a freshly
    discovered device (`api/collector.py`): `classify_device_type()` on
    the stored `hostname`/`oui_vendor`, then `openwrt_fingerprint()`'s
    `is_router` promotes an "unknown" classification to "router" (the
    same Part-B rogue-AP fallback), then `risk_score()`. `is_known` is
    always `True` here — every row processed already exists in the
    store, which is exactly `Collector`'s own definition of "known".
    `device_type`/`risk_score`/`risk_level` are only WRITTEN when the
    freshly computed `device_type` isn't "unknown" (same omit-on-unknown
    rule `Collector` and `upsert()`'s best-value merge already rely on)
    so a device that no longer matches any indicator keeps whatever
    classification it already had — never regresses a good, previously
    learned value to "unknown".

    Source resolution (#820 Task 2b): a single live `discovery.discover()`
    merge builds a `{mac: source}` map (dnsmasq/isc/arp). For each stored
    device: if its mac is in that live map, `source` becomes the live
    value (the device is still on the network, just seen through a
    different lens than whatever wrote it originally). Otherwise, if the
    CURRENT stored `source` is one of the retired legacy-module tags
    (`_LEGACY_SOURCE_TAGS`), it is relabelled `'imported'` — the device
    isn't currently visible, so a live source can no longer be
    attributed. Any other current source (already a live value like
    'arp', or already 'imported') is left untouched. `discover()` itself
    is fail-safe (never raises) and returns `[]` off-board; when that
    happens every legacy-tagged row just becomes 'imported', never a
    crash.

    Uses ONLY `store.get`/`store.list`/`store.upsert` — the store's own
    `threading.Lock`-protected public API, never a raw connection.
    Idempotent: re-running with no new discovery data or code changes
    yields `changed == 0`. Fail-safe per device: a device whose row can't
    be processed is skipped (and logged), never aborting the loop.

    Returns `{"total": N, "changed": N, "skipped": N}`.
    """
    try:
        live_devices = discover(**(discover_kwargs or {}))
    except Exception:  # noqa: BLE001 - discovery must never abort the backfill
        logger.warning("reclassify_all: discover() failed", exc_info=True)
        live_devices = []

    live_source_by_mac = {
        d["mac"]: d.get("source") for d in live_devices if d.get("mac")
    }

    total = 0
    changed = 0
    skipped = 0

    for row in store.list(limit=1_000_000):
        total += 1
        mac = row.get("mac")
        try:
            if not mac:
                continue

            hostname = row.get("hostname") or ""
            vendor = row.get("oui_vendor") or ""
            device_type = classify_device_type(hostname, vendor)
            fp = openwrt_fingerprint(hostname, mac)
            if device_type == "unknown" and fp["is_router"]:
                device_type = "router"

            update: dict = {"mac": mac}
            row_changed = False

            if device_type != "unknown":
                score, level = risk_score(device_type, fp["is_router"], True)
                if (
                    device_type != row.get("device_type")
                    or score != row.get("risk_score")
                    or level != row.get("risk_level")
                ):
                    update["device_type"] = device_type
                    update["risk_score"] = score
                    update["risk_level"] = level
                    row_changed = True

            current_source = row.get("source")
            new_source = live_source_by_mac.get(mac)
            if new_source is None and current_source in _LEGACY_SOURCE_TAGS:
                new_source = "imported"
            if new_source is not None and new_source != current_source:
                update["source"] = new_source
                row_changed = True

            if row_changed:
                store.upsert(update)
                changed += 1
        except Exception:  # noqa: BLE001 - one bad row must never abort the backfill
            skipped += 1
            logger.warning("reclassify_all: skipping device mac=%r", mac, exc_info=True)

    return {"total": total, "changed": changed, "skipped": skipped}
