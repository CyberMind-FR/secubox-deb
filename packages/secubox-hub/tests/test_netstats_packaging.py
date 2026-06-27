# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Packaging wires the collector, timer, nft tap, and sudoers (ref #758)."""
from pathlib import Path

PKG = Path(__file__).resolve().parents[1]


def test_units_exist():
    assert (PKG / "debian" / "secubox-netstats.service").exists()
    assert (PKG / "debian" / "secubox-netstats.timer").exists()


def test_rules_installs_collector_and_units_and_tap():
    rules = (PKG / "debian" / "rules").read_text()
    assert "sbin/secubox-netstats-collect" in rules
    assert "secubox-netstats.service" in rules
    assert "secubox-netstats.timer" in rules
    assert "zz-secubox-netstats-tap.nft" in rules
    # crowdsec read grant added to the sudoers fragment
    assert "inet crowdsec" in rules


def test_postinst_deploys_tap_and_enables_timer():
    post = (PKG / "debian" / "postinst").read_text()
    assert "zz-secubox-netstats-tap.nft" in post
    assert "secubox-netstats.timer" in post
