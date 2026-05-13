# packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/sim.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Simulation drift generator — Python port of Phase 1 sim.js.

When no SecuBox host responds, the kiosk uses these synthetic values so
the rings still animate plausibly. Random walk bounded to realistic ranges.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, asdict


@dataclass
class SimState:
    """Drift state — mutable, advanced by step()."""
    cpu_percent: float = 14.0
    mem_percent: float = 42.0
    disk_percent: float = 28.0
    wifi_rssi: int = -63
    load_avg_1: float = 0.18
    cpu_temp: float = 44.0
    uptime_seconds: float = 0.0
    hostname: str = "secubox-zero"

    def to_dict(self) -> dict:
        return asdict(self)


def _walk(value: float, drift: float, lo: float, hi: float) -> float:
    """One step of a bounded random walk."""
    new_value = value + (random.random() - 0.5) * drift
    return max(lo, min(hi, new_value))


def step(state: SimState, refresh_interval_s: float = 2.0) -> None:
    """Advance state in place. refresh_interval_s adds to uptime."""
    state.cpu_percent = _walk(state.cpu_percent, 12.0, 0.0, 100.0)
    state.mem_percent = _walk(state.mem_percent, 3.0, 20.0, 95.0)
    state.disk_percent = _walk(state.disk_percent, 0.7, 5.0, 95.0)
    state.wifi_rssi = int(_walk(float(state.wifi_rssi), 5.0, -90.0, -20.0))
    state.load_avg_1 = _walk(state.load_avg_1, 0.12, 0.0, 4.0)
    state.cpu_temp = _walk(state.cpu_temp, 1.5, 35.0, 82.0)
    state.uptime_seconds += refresh_interval_s
