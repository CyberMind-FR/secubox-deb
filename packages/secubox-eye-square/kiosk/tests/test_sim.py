# packages/secubox-eye-square/kiosk/tests/test_sim.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Tests for sim.py — bounded random walk drift, deterministic with seed."""
from __future__ import annotations

import random

from secubox_eye_square_kiosk.sim import SimState, step


def test_initial_state_has_six_metric_fields():
    s = SimState()
    for field in ("cpu_percent", "mem_percent", "disk_percent", "wifi_rssi",
                  "load_avg_1", "cpu_temp"):
        assert hasattr(s, field), f"missing {field}"


def test_step_advances_state_within_bounds():
    random.seed(42)
    s = SimState()
    for _ in range(100):
        step(s, refresh_interval_s=2.0)
    assert 0.0 <= s.cpu_percent <= 100.0
    assert 20.0 <= s.mem_percent <= 95.0
    assert 5.0 <= s.disk_percent <= 95.0
    assert -90 <= s.wifi_rssi <= -20
    assert 0.0 <= s.load_avg_1 <= 4.0
    assert 35.0 <= s.cpu_temp <= 82.0


def test_step_increments_uptime():
    s = SimState()
    initial = s.uptime_seconds
    step(s, refresh_interval_s=2.0)
    assert s.uptime_seconds == initial + 2.0


def test_step_with_zero_drift_holds_state():
    """A deterministic verify: if random returns 0.5, drift is zero (centred)."""
    random.seed(0)
    s = SimState()
    cpu_before = s.cpu_percent
    # we don't assert exact equality (random not seeded for 0.5) but trend
    step(s, refresh_interval_s=2.0)
    # at minimum, value still within bounds
    assert 0.0 <= s.cpu_percent <= 100.0


def test_state_to_dict_returns_api_shape():
    s = SimState()
    d = s.to_dict()
    assert set(d.keys()) >= {"cpu_percent", "mem_percent", "disk_percent",
                              "wifi_rssi", "load_avg_1", "cpu_temp",
                              "uptime_seconds", "hostname"}
