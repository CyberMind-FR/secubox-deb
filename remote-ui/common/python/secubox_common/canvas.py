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

from PIL import Image, ImageDraw

from . import theme


class DashboardCanvas:
    """Drawing primitives + abstract layout."""

    def paint_background(self, img: Image.Image,
                         colour: tuple[int, int, int] = theme.COSMOS_BLACK) -> None:
        """Fill the entire image with a solid colour (alpha=255)."""
        draw = ImageDraw.Draw(img)
        draw.rectangle((0, 0, img.size[0], img.size[1]), fill=colour + (255,))

    def layout(self, metrics: dict) -> Image.Image:
        """Compose the form-factor-specific dashboard. Override in subclass."""
        raise NotImplementedError(
            "DashboardCanvas.layout() must be overridden in subclasses"
        )
