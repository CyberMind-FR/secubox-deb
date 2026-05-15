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
    ALERT_RIBBON_HEIGHT = 20

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

    def paint_pod_cluster(self, img: Image.Image,
                          modules: Iterable[Module],
                          center: tuple[int, int],
                          radius: int,
                          pod_size: int = 48) -> None:
        """Six pods arranged at angles 60° apart on a circle of the given
        radius. Each pod is a filled circle of `module.colour`; if the
        module's icon is present it's pasted on top, otherwise the first
        letter of the module name is drawn centred in white.
        """
        from . import icons as _icons
        import math

        draw = ImageDraw.Draw(img)
        cx, cy = center
        half = pod_size // 2

        for i, m in enumerate(modules):
            angle = math.radians(-90 + i * 60)
            px = int(cx + radius * math.cos(angle))
            py = int(cy + radius * math.sin(angle))

            # Colored disc background.
            draw.ellipse((px - half, py - half, px + half, py + half),
                         fill=m.colour + (255,))

            icon = _icons.load_module_icon(m.icon_name, pod_size)
            if icon is not None:
                # Centre the icon on the pod, alpha-composited.
                ix = px - icon.size[0] // 2
                iy = py - icon.size[1] // 2
                img.paste(icon, (ix, iy), icon)
            else:
                # Fallback: first letter in white.
                font = theme.load_default_font(max(10, pod_size // 2))
                letter = m.name[0]
                bbox = font.getbbox(letter)
                lw = bbox[2] - bbox[0]
                lh = bbox[3] - bbox[1]
                draw.text((px - lw // 2, py - lh // 2 - bbox[1]),
                          letter, fill=(255, 255, 255, 255), font=font)

    def paint_central_button(self, img: Image.Image,
                             center: tuple[int, int], size: int,
                             label: str = "") -> None:
        """Hollow white circle at `center` of radius `size`. Optional
        label drawn below in TEXT_PRIMARY."""
        draw = ImageDraw.Draw(img)
        cx, cy = center
        draw.ellipse((cx - size, cy - size, cx + size, cy + size),
                     outline=(255, 255, 255, 255), width=2)
        if label:
            font = theme.load_default_font(11)
            bbox = font.getbbox(label)
            lw = bbox[2] - bbox[0]
            draw.text((cx - lw // 2, cy + size + 4),
                      label, fill=theme.TEXT_PRIMARY + (255,), font=font)

    def paint_alert_ribbon(self, img: Image.Image, region_y: int,
                           text: str, severity: str) -> None:
        """Bottom strip: dark semi-transparent fill + coloured text.
        `region_y` is the top of the ribbon (typically img.height - 20)."""
        draw = ImageDraw.Draw(img)
        w = img.size[0]
        colour = theme.SEVERITY.get(severity, theme.TEXT_MUTED) + (255,)
        draw.rectangle((0, region_y, w, region_y + self.ALERT_RIBBON_HEIGHT),
                       fill=(0, 0, 0, 200))
        font = theme.load_default_font(11)
        draw.text((10, region_y + 4),
                  f"▲ {text}"[:50], fill=colour, font=font)

    def layout(self, metrics: dict) -> Image.Image:
        """Compose the form-factor-specific dashboard. Override in subclass."""
        raise NotImplementedError(
            "DashboardCanvas.layout() must be overridden in subclasses"
        )
