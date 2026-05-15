# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Canonical 6-module table (Hamiltonian: AUTH → WALL → BOOT → MIND → ROOT → MESH).

Each Module bundles its rendering colour, the icon name used by
secubox_common.icons.load_module_icon, the metric key it reads from a
metrics dict, and an `extract` callable returning a 0..1 normalised
ratio for ring/arc fill.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Callable

from . import theme

# MIND extract divides load_avg by core count so the arc reads
# 100% when the CPU is fully saturated regardless of board: Pi Zero W
# (single-core), Pi 4B / Pi 400 (quad). Evaluated once at import time.
_CPU_COUNT: float = float(os.cpu_count() or 4)


def _clamp(v: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, v))


@dataclass(frozen=True)
class Module:
    name: str
    colour: tuple[int, int, int]
    icon_name: str
    metric: str
    extract: Callable[[dict], float]


MODULES: list[Module] = [
    Module(
        name="AUTH", colour=theme.AUTH, icon_name="auth",
        metric="cpu_percent",
        extract=lambda s: _clamp(s.get("cpu_percent", 0.0) / 100.0),
    ),
    Module(
        name="WALL", colour=theme.WALL, icon_name="wall",
        metric="mem_percent",
        extract=lambda s: _clamp(s.get("mem_percent", 0.0) / 100.0),
    ),
    Module(
        name="BOOT", colour=theme.BOOT, icon_name="boot",
        metric="disk_percent",
        extract=lambda s: _clamp(s.get("disk_percent", 0.0) / 100.0),
    ),
    Module(
        name="MIND", colour=theme.MIND, icon_name="mind",
        metric="load_avg_1",
        extract=lambda s: _clamp(s.get("load_avg_1", 0.0) / _CPU_COUNT),
    ),
    Module(
        name="ROOT", colour=theme.ROOT, icon_name="root",
        metric="cpu_temp",
        extract=lambda s: _clamp((s.get("cpu_temp", 35.0) - 35.0) / 50.0),
    ),
    Module(
        name="MESH", colour=theme.MESH, icon_name="mesh",
        metric="wifi_rssi",
        extract=lambda s: _clamp((s.get("wifi_rssi", -90) + 90.0) / 70.0),
    ),
]
