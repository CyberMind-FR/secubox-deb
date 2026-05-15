# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Tests for secubox_common.modules — canonical Hamiltonian module table."""
from secubox_common import modules, theme


def test_modules_hamiltonian_order():
    names = [m.name for m in modules.MODULES]
    assert names == ["AUTH", "WALL", "BOOT", "MIND", "ROOT", "MESH"]


def test_each_module_has_required_fields():
    for m in modules.MODULES:
        assert m.name
        assert isinstance(m.colour, tuple) and len(m.colour) == 3
        assert m.icon_name == m.name.lower()
        assert m.metric
        assert callable(m.extract)


def test_extract_returns_unit_interval_for_typical_values():
    sample = {
        "cpu_percent": 50,
        "mem_percent": 75,
        "disk_percent": 30,
        "load_avg_1": 2.0,
        "cpu_temp": 60,
        "wifi_rssi": -60,
    }
    for m in modules.MODULES:
        v = m.extract(sample)
        assert 0.0 <= v <= 1.0, f"{m.name} extract returned {v} out of [0,1]"


def test_extract_clamps_high_values():
    high = {
        "cpu_percent": 999, "mem_percent": 999, "disk_percent": 999,
        "load_avg_1": 999, "cpu_temp": 999, "wifi_rssi": 999,
    }
    for m in modules.MODULES:
        assert m.extract(high) == 1.0


def test_extract_clamps_low_values_and_missing():
    low = {}  # all metrics missing → defaults
    for m in modules.MODULES:
        v = m.extract(low)
        assert 0.0 <= v <= 1.0


def test_modules_use_theme_colours():
    expected = {
        "AUTH": theme.AUTH, "WALL": theme.WALL, "BOOT": theme.BOOT,
        "MIND": theme.MIND, "ROOT": theme.ROOT, "MESH": theme.MESH,
    }
    for m in modules.MODULES:
        assert m.colour == expected[m.name]
