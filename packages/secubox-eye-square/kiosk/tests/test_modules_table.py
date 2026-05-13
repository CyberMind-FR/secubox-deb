# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Tests for modules_table.py — the 6-entry RINGS list + extractors."""
from __future__ import annotations

from secubox_eye_square_kiosk.modules_table import MODULES


def test_six_modules_in_hamiltonian_order():
    assert [m.name for m in MODULES] == ["AUTH", "WALL", "BOOT", "MIND", "ROOT", "MESH"]


def test_ring_radii_descend_in_steps_of_about_13px():
    radii = [m.radius for m in MODULES]
    assert radii == [214, 201, 188, 175, 162, 149]
    for a, b in zip(radii, radii[1:]):
        assert a - b == 13, "uniform 13px ring spacing"


def test_extractor_clamps_overshoot_to_one():
    auth = MODULES[0]
    assert auth.extract({"cpu_percent": 150.0}) == 1.0
    assert auth.extract({"cpu_percent": 50.0}) == 0.5
    assert auth.extract({"cpu_percent": -10.0}) == 0.0


def test_extractor_missing_metric_returns_zero():
    auth = MODULES[0]
    assert auth.extract({}) == 0.0


def test_root_temp_extractor_maps_35c_to_zero_and_85c_to_one():
    root = next(m for m in MODULES if m.name == "ROOT")
    assert root.extract({"cpu_temp": 35.0}) == 0.0
    assert root.extract({"cpu_temp": 85.0}) == 1.0
    assert abs(root.extract({"cpu_temp": 60.0}) - 0.5) < 0.001


def test_mesh_rssi_extractor_maps_minus90_to_zero_and_minus20_to_one():
    mesh = next(m for m in MODULES if m.name == "MESH")
    assert mesh.extract({"wifi_rssi": -90}) == 0.0
    assert mesh.extract({"wifi_rssi": -20}) == 1.0


def test_each_module_has_distinct_colour():
    colours = {m.colour for m in MODULES}
    assert len(colours) == 6
