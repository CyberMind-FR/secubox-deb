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
