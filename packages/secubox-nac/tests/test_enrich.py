# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-nac — tests for the absorbed enrichers (#817 Task 3).
"""


def test_classify_and_risk():
    from api.enrich import classify_device_type, risk_score
    assert classify_device_type("living-room-camera", "Hikvision") == "camera"
    assert classify_device_type("Johns-iPhone", "Apple") == "phone"
    lvl = risk_score("camera", is_router=False)[1]
    assert lvl in {"low", "medium", "high"}


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
