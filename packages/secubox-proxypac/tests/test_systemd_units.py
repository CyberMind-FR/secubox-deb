# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-ProxyPAC :: systemd units and config verification
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_gen_service_runs_cli_as_secubox():
    s = (ROOT / "systemd" / "secubox-proxypac-gen.service").read_text()
    assert "ExecStart=/usr/sbin/proxypac-gen" in s
    assert "User=secubox" in s and "Type=oneshot" in s


def test_path_unit_watches_rulesdir():
    p = (ROOT / "systemd" / "secubox-proxypac-gen.path").read_text()
    assert "PathModified=/etc/secubox/proxypac/rules.d" in p
    assert "Unit=secubox-proxypac-gen.service" in p


def test_timer_is_fallback():
    t = (ROOT / "systemd" / "secubox-proxypac-gen.timer").read_text()
    assert "OnUnitActiveSec=" in t


def test_dnsmasq_sets_option_252():
    d = (ROOT / "conf" / "dnsmasq-wpad.conf").read_text()
    assert "dhcp-option=252" in d
