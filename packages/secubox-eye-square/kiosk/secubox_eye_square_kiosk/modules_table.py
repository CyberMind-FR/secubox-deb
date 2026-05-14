# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""6-module RINGS table — colour, ring radius, metric extractor.

Hamiltonian order: AUTH → WALL → BOOT → MIND → ROOT → MESH → AUTH.
Each entry corresponds to one concentric arc on the 480×480 round canvas.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from . import theme


@dataclass(frozen=True)
class Module:
    """One module's rendering metadata."""
    name: str                       # "AUTH", "WALL", ...
    colour: tuple[int, int, int]    # RGB tuple from theme.py
    radius: int                     # arc radius in pixels (centre at 240,240)
    metric: str                     # API field name, e.g. "cpu_percent"
    unit: str                       # display unit, e.g. "%"
    extract: Callable[[dict], float]  # (state-dict) → 0..1 fill ratio


def _clamp(v: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, v))


MODULES: list[Module] = [
    Module(
        name="AUTH",
        colour=theme.AUTH,
        radius=214,
        metric="cpu_percent",
        unit="%",
        extract=lambda s: _clamp(s.get("cpu_percent", 0.0) / 100.0),
    ),
    Module(
        name="WALL",
        colour=theme.WALL,
        radius=201,
        metric="mem_percent",
        unit="%",
        extract=lambda s: _clamp(s.get("mem_percent", 0.0) / 100.0),
    ),
    Module(
        name="BOOT",
        colour=theme.BOOT,
        radius=188,
        metric="disk_percent",
        unit="%",
        extract=lambda s: _clamp(s.get("disk_percent", 0.0) / 100.0),
    ),
    Module(
        name="MIND",
        colour=theme.MIND,
        radius=175,
        metric="load_avg_1",
        unit="×",
        extract=lambda s: _clamp(s.get("load_avg_1", 0.0) / 4.0),
    ),
    Module(
        name="ROOT",
        colour=theme.ROOT,
        radius=162,
        metric="cpu_temp",
        unit="°C",
        extract=lambda s: _clamp((s.get("cpu_temp", 35.0) - 35.0) / 50.0),
    ),
    Module(
        name="MESH",
        colour=theme.MESH,
        radius=149,
        metric="wifi_rssi",
        unit="dBm",
        extract=lambda s: _clamp((s.get("wifi_rssi", -90) + 90.0) / 70.0),
    ),
]
