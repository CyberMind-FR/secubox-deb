#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Generate the six root-menu icons for the radial dashboard.

Replaces the letter-in-circle placeholders previously emitted by
generate_menu_icons.py for these names. Each icon is drawn as a clean
vector glyph using PIL primitives, white (#e8e6d9) on a transparent
background, anti-aliased by 4x supersampling.

The radial renderer resizes to ICON_SIZE=40 at runtime; we ship 22 + 48
to match the existing asset filename convention.
"""
from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw

WHITE = (232, 230, 217, 255)  # --text-primary / #e8e6d9
TRANSPARENT = (0, 0, 0, 0)
SUPER = 4  # supersample factor for AA

ICONS = (
    "devices",
    "secubox",
    "local",
    "network",
    "security",
    "exit",
)


def _new(size: int) -> tuple[Image.Image, ImageDraw.ImageDraw, int]:
    """Return (image, draw, working size) at supersampled resolution."""
    big = size * SUPER
    img = Image.new("RGBA", (big, big), TRANSPARENT)
    return img, ImageDraw.Draw(img), big


def _finalize(img: Image.Image, target: int, path: Path) -> None:
    """Downsample to target with LANCZOS, save."""
    out = img.resize((target, target), Image.Resampling.LANCZOS)
    out.save(path, "PNG", optimize=True)


def draw_devices(size: int) -> Image.Image:
    img, d, s = _new(size)
    sw = max(2, s // 16)  # stroke width
    # Tablet (back, larger): rounded rectangle
    pad = s // 6
    d.rounded_rectangle(
        (pad, pad, s - pad, s - pad - s // 6),
        radius=s // 14,
        outline=WHITE,
        width=sw,
    )
    # Small phone overlay (front, lower-right)
    p_w = s * 5 // 12
    p_h = s * 7 // 12
    p_x = s - p_w - sw
    p_y = s - p_h - sw
    # Fill behind to mask the tablet edge for clean overlap
    d.rectangle((p_x - sw, p_y - sw, p_x + p_w + sw, p_y + p_h + sw), fill=TRANSPARENT)
    d.rounded_rectangle(
        (p_x, p_y, p_x + p_w, p_y + p_h),
        radius=s // 18,
        outline=WHITE,
        width=sw,
    )
    # Phone home-dot
    dot_r = max(1, s // 38)
    cx = p_x + p_w // 2
    cy = p_y + p_h - s // 14
    d.ellipse((cx - dot_r, cy - dot_r, cx + dot_r, cy + dot_r), fill=WHITE)
    return img


def draw_secubox(size: int) -> Image.Image:
    """SecuBox brand mark: a tilted cube outline (3 visible faces)."""
    img, d, s = _new(size)
    sw = max(2, s // 16)
    cx, cy = s // 2, s // 2
    r = s * 4 // 10  # half-diagonal
    # Six vertices of an isometric cube viewed from front-top-right
    top = (cx, cy - r)
    right = (cx + r * 13 // 15, cy - r // 3)
    left = (cx - r * 13 // 15, cy - r // 3)
    bottom = (cx, cy + r * 2 // 3)
    front_right = (cx + r * 13 // 15, cy + r // 2)
    front_left = (cx - r * 13 // 15, cy + r // 2)
    # Top diamond
    d.line([top, right], fill=WHITE, width=sw)
    d.line([right, cx_cy := (cx, cy - r // 12)], fill=WHITE, width=sw)
    d.line([cx_cy, left], fill=WHITE, width=sw)
    d.line([left, top], fill=WHITE, width=sw)
    # Vertical edges (down from each top corner)
    d.line([left, front_left], fill=WHITE, width=sw)
    d.line([cx_cy, bottom], fill=WHITE, width=sw)
    d.line([right, front_right], fill=WHITE, width=sw)
    # Front faces
    d.line([front_left, bottom], fill=WHITE, width=sw)
    d.line([bottom, front_right], fill=WHITE, width=sw)
    return img


def draw_local(size: int) -> Image.Image:
    """House silhouette: triangular roof + rectangular body."""
    img, d, s = _new(size)
    sw = max(2, s // 16)
    pad = s // 6
    # Body
    body_top = s * 9 // 20
    d.rectangle(
        (pad + s // 12, body_top, s - pad - s // 12, s - pad),
        outline=WHITE,
        width=sw,
    )
    # Roof (filled triangle, slightly overhanging)
    d.polygon(
        [
            (pad, body_top),
            (s // 2, pad),
            (s - pad, body_top),
        ],
        outline=WHITE,
        width=sw,
    )
    # Door
    door_w = s // 7
    door_h = s // 5
    door_x = s // 2 - door_w // 2
    door_y = s - pad - door_h
    d.rectangle((door_x, door_y, door_x + door_w, s - pad), outline=WHITE, width=sw)
    return img


def draw_network(size: int) -> Image.Image:
    """Globe: circle outline + 2 horizontal meridian arcs + vertical."""
    img, d, s = _new(size)
    sw = max(2, s // 16)
    pad = s // 6
    box = (pad, pad, s - pad, s - pad)
    # Globe outline
    d.ellipse(box, outline=WHITE, width=sw)
    # Vertical meridian
    cx = s // 2
    d.line([(cx, pad), (cx, s - pad)], fill=WHITE, width=sw)
    # Horizontal equator
    cy = s // 2
    d.line([(pad, cy), (s - pad, cy)], fill=WHITE, width=sw)
    # Curved meridians (ellipses with narrow widths)
    narrow = (s - pad * 2) // 3
    d.ellipse(
        (cx - narrow, pad, cx + narrow, s - pad),
        outline=WHITE,
        width=sw,
    )
    return img


def draw_security(size: int) -> Image.Image:
    """Shield with a centered checkmark."""
    img, d, s = _new(size)
    sw = max(2, s // 16)
    pad = s // 6
    # Shield outline — pentagonal: flat-top, curved-bottom
    top_y = pad
    mid_y = s * 5 // 8
    bot_y = s - pad
    left_x = pad
    right_x = s - pad
    cx = s // 2
    d.polygon(
        [
            (left_x, top_y),
            (right_x, top_y),
            (right_x, mid_y),
            (cx, bot_y),
            (left_x, mid_y),
        ],
        outline=WHITE,
        width=sw,
    )
    # Checkmark inside
    cm_lo = (s * 3 // 8, s * 9 // 20)
    cm_mid = (s * 7 // 16, s * 11 // 20)
    cm_hi = (s * 5 // 8, s * 7 // 20)
    d.line([cm_lo, cm_mid], fill=WHITE, width=sw)
    d.line([cm_mid, cm_hi], fill=WHITE, width=sw)
    return img


def draw_exit(size: int) -> Image.Image:
    """Open door (left rectangle) + arrow pointing right out of it."""
    img, d, s = _new(size)
    sw = max(2, s // 16)
    pad = s // 6
    # Door frame on the left half
    door_w = s * 3 // 10
    d.rectangle(
        (pad, pad, pad + door_w, s - pad),
        outline=WHITE,
        width=sw,
    )
    # Arrow shaft (horizontal, mid-height)
    sh_y = s // 2
    shaft_left = pad + door_w + s // 12
    shaft_right = s - pad - s // 10
    d.line([(shaft_left, sh_y), (shaft_right, sh_y)], fill=WHITE, width=sw)
    # Arrowhead (>)
    head = s // 5
    d.line(
        [(shaft_right - head, sh_y - head), (shaft_right, sh_y)],
        fill=WHITE,
        width=sw,
    )
    d.line(
        [(shaft_right - head, sh_y + head), (shaft_right, sh_y)],
        fill=WHITE,
        width=sw,
    )
    return img


DRAWERS = {
    "devices": draw_devices,
    "secubox": draw_secubox,
    "local": draw_local,
    "network": draw_network,
    "security": draw_security,
    "exit": draw_exit,
}


def main() -> None:
    here = Path(__file__).parent
    for name in ICONS:
        for size in (22, 48):
            img = DRAWERS[name](size)
            out = here / f"{name}-{size}.png"
            _finalize(img, size, out)
            print(f"Generated {out.name}  ({out.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
