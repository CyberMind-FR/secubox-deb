# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Concentric radar painter — port of fallback_manager._draw_offline_radar().

Stateless: given a `phase` in [0, 1) it draws the full radar frame
(ring backgrounds, balanced tube arcs, rotating segment-coloured sweep,
sweep head, centre hub) onto `img` centred on `center`.

`phase * 2π` is the sweep angle in radians, measured clockwise from
12 o'clock. Caller is responsible for advancing phase across frames
(typically `(time.monotonic() * rpm / 60) % 1`).
"""
from __future__ import annotations

import colorsys
import math
from collections.abc import Iterable

from PIL import Image, ImageDraw

from ..modules import Module

# Default radii match the deployed fallback_manager.py layout (6 rings).
DEFAULT_RADII: list[int] = [214, 188, 162, 136, 110, 84]

# Stroke width for ring backgrounds + tube arcs.
RING_WIDTH: int = 20

# Inner hub radius — masks the centre so it can host icons / metrics text.
HUB_RADIUS: int = 85

# Mapping module NAME → PIL arc centre angle so each tube arc sits at the
# position on the wheel that matches its colour. PIL convention: 0=3 o'clock,
# angles increase counter-clockwise. Decoupling angle from list order means
# the painter is invariant to MODULES iteration order — callers can pass
# secubox_common.MODULES (AUTH-first) or fallback_manager's local list
# (BOOT-first) and get the same wheel layout.
DEFAULT_NAME_TO_ANGLE: dict[str, int] = {
    "AUTH": 0,    # red-orange (3 o'clock)
    "WALL": 60,   # orange-yellow
    "ROOT": 120,  # green
    "MESH": 180,  # blue
    "MIND": 240,  # purple
    "BOOT": 300,  # deep red — closes the wheel between purple and red
}


def paint(
    img: Image.Image,
    center: tuple[int, int],
    modules: Iterable[Module],
    metrics: dict,
    radii: list[int] | None = None,
    phase: float = 0.0,
    ring_width: int = RING_WIDTH,
    hub_radius: int = HUB_RADIUS,
    draw_hub: bool = True,
    name_to_angle: dict[str, int] | None = None,
) -> None:
    """Paint one radar frame at `phase`.

    Args:
        img: target RGBA image; must be large enough that
            `radii[0] + 8` fits within ``min(img.size) / 2``.
        center: (cx, cy) — the radar centre in image coordinates.
        modules: ordered iterable of Module — drawn outermost-first.
        metrics: dict passed to `Module.extract` for each ring's fill ratio.
        radii: per-ring radius, outermost-first. Default matches the
            deployed Pi Zero W fallback radar.
        phase: 0..1 maps to 0..2π sweep angle (clockwise from 12 o'clock).
        ring_width: stroke width for ring backgrounds and tube arcs.
        hub_radius: radius of the dark centre disc.
        draw_hub: when False, callers can composite their own centre
            (e.g. the converged dashboard's central button + pod cluster).
    """
    if radii is None:
        radii = DEFAULT_RADII
    if name_to_angle is None:
        name_to_angle = DEFAULT_NAME_TO_ANGLE
    modules = list(modules)
    if len(modules) != len(radii):
        raise ValueError(
            f"modules ({len(modules)}) and radii ({len(radii)}) length mismatch"
        )

    draw = ImageDraw.Draw(img)
    cx, cy = center
    sweep_rad = (phase % 1.0) * 2.0 * math.pi

    _paint_ring_backgrounds(draw, cx, cy, radii, ring_width)
    _paint_tube_arcs(draw, cx, cy, modules, metrics, radii, ring_width,
                     name_to_angle)
    _paint_sweep(draw, cx, cy, modules, metrics, radii, sweep_rad)
    _paint_sweep_head(draw, cx, cy, modules[0].colour, radii[0], sweep_rad)
    if draw_hub:
        draw.ellipse(
            (cx - hub_radius, cy - hub_radius, cx + hub_radius, cy + hub_radius),
            fill=(12, 12, 22, 255),
        )


def _paint_ring_backgrounds(
    draw: ImageDraw.ImageDraw,
    cx: int,
    cy: int,
    radii: list[int],
    ring_width: int,
) -> None:
    for r in radii:
        draw.ellipse(
            (cx - r, cy - r, cx + r, cy + r),
            outline=(20, 20, 28, 255),
            width=ring_width,
        )


def _paint_tube_arcs(
    draw: ImageDraw.ImageDraw,
    cx: int,
    cy: int,
    modules: list[Module],
    metrics: dict,
    radii: list[int],
    ring_width: int,
    name_to_angle: dict[str, int],
) -> None:
    # PIL arc degrees: 0=3 o'clock, counter-clockwise. Each module's arc
    # sits at the wheel position matching its colour, looked up by name
    # — independent of caller's iteration order.
    for m, r in zip(modules, radii):
        pct = m.extract(metrics)
        if pct <= 0.0:
            continue
        # Fall back to evenly-spaced positions if name unknown — keeps the
        # painter robust against custom module sets without bringing in a
        # hard dependency on the canonical six.
        center_deg = name_to_angle.get(m.name, 0)
        half = (pct * 360.0) / 2.0
        start = center_deg + half
        end = center_deg - half

        # Outer dark edge (color × 1/3).
        dark = (m.colour[0] // 3, m.colour[1] // 3, m.colour[2] // 3, 255)
        draw.arc(
            (cx - r - 2, cy - r - 2, cx + r + 2, cy + r + 2),
            end, start, fill=dark, width=ring_width - 2,
        )
        # Main color band.
        draw.arc(
            (cx - r, cy - r, cx + r, cy + r),
            end, start, fill=m.colour + (255,), width=ring_width - 6,
        )
        # Inner light tube highlight.
        light = (
            min(255, m.colour[0] + 80),
            min(255, m.colour[1] + 80),
            min(255, m.colour[2] + 80),
            255,
        )
        draw.arc(
            (cx - r + 2, cy - r + 2, cx + r - 2, cy + r - 2),
            end, start, fill=light, width=4,
        )


def _paint_sweep(
    draw: ImageDraw.ImageDraw,
    cx: int,
    cy: int,
    modules: list[Module],
    metrics: dict,
    radii: list[int],
    sweep_rad: float,
) -> None:
    # Per-ring sweep segments coloured by that ring's metric.
    max_r = radii[0] + 8
    min_r = radii[-1] - 8

    for idx, m in enumerate(modules):
        r = radii[idx]
        # Segment bounds — each ring owns the slab between its midpoint
        # to the previous ring and its midpoint to the next ring.
        r_outer = max_r if idx == 0 else (radii[idx - 1] + r) // 2
        r_inner = min_r if idx == len(modules) - 1 else (r + radii[idx + 1]) // 2

        pct = m.extract(metrics)
        intensity = 0.5 + pct * 0.5

        # Fading trail behind the sweep line.
        for i in range(15):
            offset = -0.15 * (i / 15.0)
            a = sweep_rad + offset
            fade = 1.0 - (i / 15.0)
            x1 = cx + r_inner * math.sin(a)
            y1 = cy - r_inner * math.cos(a)
            x2 = cx + r_outer * math.sin(a)
            y2 = cy - r_outer * math.cos(a)
            seg = (
                int(m.colour[0] * fade * intensity),
                int(m.colour[1] * fade * intensity),
                int(m.colour[2] * fade * intensity),
                255,
            )
            draw.line([(x1, y1), (x2, y2)], fill=seg, width=2)

        # Main bright leading edge for this ring.
        x1 = cx + r_inner * math.sin(sweep_rad)
        y1 = cy - r_inner * math.cos(sweep_rad)
        x2 = cx + r_outer * math.sin(sweep_rad)
        y2 = cy - r_outer * math.cos(sweep_rad)
        bright = (
            min(255, m.colour[0] + 60),
            min(255, m.colour[1] + 60),
            min(255, m.colour[2] + 60),
            255,
        )
        draw.line([(x1, y1), (x2, y2)], fill=bright, width=3)


def _paint_sweep_head(
    draw: ImageDraw.ImageDraw,
    cx: int,
    cy: int,
    head_color: tuple[int, int, int],
    outer_r: int,
    sweep_rad: float,
) -> None:
    hx = cx + outer_r * math.sin(sweep_rad)
    hy = cy - outer_r * math.cos(sweep_rad)
    draw.ellipse(
        (hx - 4, hy - 4, hx + 4, hy + 4),
        fill=head_color + (255,),
    )


# Convenience for callers that want a quick HSV-rotating accent colour
# matching the current sweep position (used by the original radar variant
# but kept here for downstream painters that want it).
def sweep_accent(phase: float) -> tuple[int, int, int]:
    hue = phase % 1.0
    r, g, b = colorsys.hsv_to_rgb(hue, 0.9, 0.8)
    return (int(r * 255), int(g * 255), int(b * 255))
