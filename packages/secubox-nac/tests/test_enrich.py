# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-nac — tests for the absorbed enrichers (#817 Task 3).
"""

import pytest


def test_classify_and_risk():
    from api.enrich import classify_device_type, risk_score
    assert classify_device_type("living-room-camera", "Hikvision") == "camera"
    assert classify_device_type("Johns-iPhone", "Apple") == "phone"
    lvl = risk_score("camera", is_router=False)[1]
    assert lvl in {"low", "medium", "high"}


def test_risk_router_known_low():
    """#817 addendum (Task 10): a KNOWN router (allow-listed or already in
    the store) is trusted infrastructure -> LOW risk."""
    from api.enrich import risk_score
    score, level = risk_score("router", is_router=True, is_known=True)
    assert level == "low"
    assert 0 <= score <= 100


def test_risk_router_unknown_high():
    """#817 addendum (Task 10): a NEWLY-seen/unknown router is a rogue-AP
    signal -> HIGH risk, regardless of open ports."""
    from api.enrich import risk_score
    score, level = risk_score("router", is_router=True, is_known=False)
    assert level == "high"
    assert 0 <= score <= 100


def test_oui_and_openwrt(tmp_path):
    from api.enrich import load_oui, oui_vendor, openwrt_fingerprint
    ouif = tmp_path / "oui.txt"
    ouif.write_text("AA-BB-CC   (hex)\t\tAcme Corp\n")
    m = load_oui(str(ouif))
    assert oui_vendor("aa:bb:cc:00:00:20", m) == "Acme Corp"
    fp = openwrt_fingerprint("OpenWrt")
    assert fp["is_openwrt"] is True


def test_openwrt_hostname_not_router():
    """A hostname matching an OpenWrt pattern but with a non-router-vendor
    MAC is an OpenWrt-flagged device, not automatically a router. Router
    status must come strictly from the vendor-MAC check (#817 review fix).
    """
    from api.enrich import openwrt_fingerprint
    fp = openwrt_fingerprint("router-guest", mac="AA:BB:CC:00:00:20")
    assert fp["is_openwrt"] is True
    assert fp["is_router"] is False
    assert fp["router_vendor"] is None


def test_classify_unknown():
    from api.enrich import classify_device_type
    assert classify_device_type("random-host", "NoVendor") == "unknown"


def test_load_oui_missing_file():
    from api.enrich import load_oui
    assert load_oui("/nonexistent/oui.txt") == {}


def test_oui_vendor_unmatched():
    """#817 whole-branch fix (I4): a miss returns None, not the sentinel
    string "Unknown" (a non-null value would clobber a migrated vendor
    through the store's best-value COALESCE merge)."""
    from api.enrich import oui_vendor
    assert oui_vendor("11:22:33:44:55:66", {}) is None
    # A malformed MAC is also a miss -> None (was "Unknown").
    assert oui_vendor("not-a-mac", {}) is None


# --- #820 (ref #817 follow-up): expanded classifier coverage ---


@pytest.mark.parametrize("hostname,vendor,expected", [
    ("living-room-camera", "Hikvision", "camera"),
    ("front-doorbell", "", "camera"),
    ("Johns-iPhone", "Apple", "phone"),
    ("android-abc123", "", "phone"),
    ("Galaxy-S21", "", "phone"),
    ("Galaxy-Tab-S8", "", "tablet"),
    ("Johns-iPad", "Apple", "tablet"),
    ("kindle-paperwhite", "", "tablet"),
    ("Johns-MacBook-Pro", "Apple", "laptop"),
    ("thinkpad-x1", "", "laptop"),
    ("office-desktop-pc", "", "computer"),
    ("ubuntu-server", "", "computer"),
    ("living-room-tv", "", "smart_tv"),
    ("bravia-tv", "Sony", "smart_tv"),
    ("kitchen-echo", "Amazon", "smart_speaker"),
    ("sonos-one", "", "smart_speaker"),
    ("hue-bridge", "Philips", "smart_home"),
    ("hall-thermostat", "", "smart_home"),
    ("office-printer", "HP", "printer"),
    ("laserjet-pro", "", "printer"),
    ("home-router", "", "router"),
    ("edgerouter-x", "Ubiquiti", "router"),
    ("synology-ds920", "", "nas"),
    ("qnap-nas01", "", "nas"),
    ("living-room-ps5", "", "game_console"),
    ("nintendo-switch-console", "", "game_console"),
    ("fitbit-charge", "", "wearable"),
    ("random-host", "NoVendor", "unknown"),
])
def test_expanded_indicator_coverage(hostname, vendor, expected):
    from api.enrich import classify_device_type
    assert classify_device_type(hostname, vendor) == expected


def test_vendor_fallback_camera():
    """Hostname gives no signal at all -> falls back to the OUI vendor
    (this particular vendor string also happens to contain the "hikvision"
    hostname keyword, so it resolves the same way via either pass)."""
    from api.enrich import classify_device_type
    assert classify_device_type("", "Hikvision Digital Technology") == "camera"


def test_vendor_fallback_smart_speaker():
    from api.enrich import classify_device_type
    assert classify_device_type("", "Sonos, Inc.") == "smart_speaker"


def test_vendor_fallback_game_console_no_keyword_collision():
    """"Microsoft" (Xbox) is NOT in any hostname keyword list, so this
    resolves ONLY through the `_VENDOR_TYPE` fallback, never the keyword
    pass — proves the fallback actually runs, not just that the result
    happens to be right."""
    from api.enrich import classify_device_type
    assert classify_device_type("unnamed-device", "Microsoft Corporation") == "game_console"


def test_vendor_fallback_wearable():
    from api.enrich import classify_device_type
    assert classify_device_type("unnamed-device", "Fitbit Inc") == "wearable"


def test_vendor_fallback_apple_generic_phone():
    """An Apple-vendor device whose hostname says nothing router/tablet/
    laptop-specific falls back to phone. "apple" alone (no "tv" suffix) is
    not in any hostname keyword list, so this only resolves via
    `_VENDOR_TYPE` too."""
    from api.enrich import classify_device_type
    assert classify_device_type("unnamed-device", "Apple, Inc.") == "phone"


def test_vendor_fallback_computer_no_keyword_collision():
    """"Dell"/"Lenovo"/raw "raspberry" (no "pi" suffix) aren't in any
    hostname keyword list either — fallback-only path to "computer"."""
    from api.enrich import classify_device_type
    assert classify_device_type("unnamed-device", "Dell Inc.") == "computer"
    assert classify_device_type("unnamed-device", "Lenovo") == "computer"
    assert classify_device_type("unnamed-device", "Raspberry Pi Foundation") == "computer"


def test_vendor_fallback_tplink_is_iot_not_router():
    """#817/#820 RISK NOTE: TP-Link makes routers AND IoT gear — the
    conservative default is iot, never router. "tp-link" is not in any
    hostname keyword list, so this only resolves via `_VENDOR_TYPE`."""
    from api.enrich import classify_device_type
    assert classify_device_type("unnamed-device", "TP-Link Technologies Co Ltd") == "iot"


def test_router_stays_conservative_generic_vendors():
    """Hard constraint: generic multi-purpose brands must NOT become
    "router" from a generic hostname — only unambiguous networking gear
    does (unifi/mikrotik/edgerouter/openwrt/ubiquiti/cisco)."""
    from api.enrich import classify_device_type
    assert classify_device_type("unnamed-device", "TP-Link Technologies Co Ltd") != "router"
    assert classify_device_type("unnamed-device", "NETGEAR") != "router"
    assert classify_device_type("unnamed-device", "ASUSTeK COMPUTER INC.") != "router"
    assert classify_device_type("unnamed-device", "Samsung Electronics") != "router"


def test_router_mikrotik_vendor_classifies_router():
    from api.enrich import classify_device_type
    assert classify_device_type("unnamed-device", "MikroTikls SIA") == "router"
