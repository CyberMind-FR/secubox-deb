# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""DashboardCanvas base class.

Subclasses implement `layout(metrics)` to compose the form-factor-specific
frame. The base class owns the drawing primitives — stateless from the
canvas's perspective, all state passed in via arguments.
"""
from __future__ import annotations

from collections.abc import Iterable

from PIL import Image, ImageDraw

from . import theme
from .modules import Module


class DashboardCanvas:
    """Drawing primitives + abstract layout."""

    RING_WIDTH = 5
    RING_TRACK_COLOUR = (0x14, 0x14, 0x14, 255)

    def paint_background(self, img: Image.Image,
                         colour: tuple[int, int, int] = theme.COSMOS_BLACK) -> None:
        """Fill the entire image with a solid colour (alpha=255)."""
        draw = ImageDraw.Draw(img)
        draw.rectangle((0, 0, img.size[0], img.size[1]), fill=colour + (255,))

    def paint_rainbow_ring(self, img: Image.Image,
                           center: tuple[int, int],
                           radius_outer: int,
                           radius_inner: int,
                           stops: int = 256,
                           background: tuple[int, int, int] = theme.COSMOS_BLACK
                           ) -> None:
        """Annular rainbow gradient — HSV hue rotates 0..360° around the centre,
        rendered as `stops` thin arc segments between radius_inner and radius_outer.
        The inner disc is filled with `background` so gaps between this ring and
        downstream primitives blend with the dashboard's COSMOS_BLACK canvas."""
        import colorsys

        draw = ImageDraw.Draw(img)
        cx, cy = center
        bbox = (cx - radius_outer, cy - radius_outer,
                cx + radius_outer, cy + radius_outer)
        step_deg = 360.0 / stops
        # Pillow needs an outline at least 1px thick; use a filled pieslice
        # for each step, then erase the inner disc once.
        for i in range(stops):
            hue = i / stops
            r, g, b = colorsys.hsv_to_rgb(hue, 1.0, 1.0)
            colour = (int(r * 255), int(g * 255), int(b * 255), 255)
            start = i * step_deg - 90.0
            end = (i + 1) * step_deg - 90.0
            draw.pieslice(bbox, start=start, end=end, fill=colour)

        # Erase the inner disc back to the dashboard background colour.
        inner_bbox = (cx - radius_inner, cy - radius_inner,
                      cx + radius_inner, cy + radius_inner)
        draw.ellipse(inner_bbox, fill=background + (255,))

    def paint_concentric_arcs(self, img: Image.Image,
                              center: tuple[int, int],
                              modules: Iterable[Module],
                              metrics: dict,
                              radii: list[int]) -> None:
        """One concentric arc per module at each radius. Each ring has a
        very dark full-circle track and a coloured fill arc proportional
        to `module.extract(metrics)` (0..1), starting at 12 o'clock and
        sweeping clockwise."""
        draw = ImageDraw.Draw(img)
        cx, cy = center
        for m, r in zip(modules, radii):
            pct = m.extract(metrics)
            bbox = (cx - r, cy - r, cx + r, cy + r)
            # Dark track (full circle, slightly thicker for visual weight).
            draw.arc(bbox, start=-90, end=270,
                     fill=self.RING_TRACK_COLOUR,
                     width=self.RING_WIDTH + 2)
            # Coloured fill (only if > ~0.5%).
            if pct > 0.005:
                end_angle = -90 + 360 * pct
                draw.arc(bbox, start=-90, end=end_angle,
                         fill=m.colour + (255,), width=self.RING_WIDTH)

    def layout(self, metrics: dict) -> Image.Image:
        """Compose the form-factor-specific dashboard. Override in subclass."""
        raise NotImplementedError(
            "DashboardCanvas.layout() must be overridden in subclasses"
        )
