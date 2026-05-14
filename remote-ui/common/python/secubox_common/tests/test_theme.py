# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Tests for secubox_common.theme — palette + DEFAULT_FONT loader."""
from PIL import ImageDraw, ImageFont, Image

from secubox_common import theme


def test_module_colors_are_rgb_byte_tuples():
    for name in ("AUTH", "WALL", "BOOT", "MIND", "ROOT", "MESH"):
        c = getattr(theme, name)
        assert isinstance(c, tuple) and len(c) == 3
        assert all(isinstance(b, int) and 0 <= b <= 255 for b in c)


def test_token_colors_present():
    for name in ("COSMOS_BLACK", "GOLD_HERMETIC", "CINNABAR",
                 "MATRIX_GREEN", "CYBER_CYAN", "VOID_PURPLE",
                 "TEXT_PRIMARY", "TEXT_MUTED"):
        c = getattr(theme, name)
        assert isinstance(c, tuple) and len(c) == 3


def test_severity_table_has_three_keys():
    assert set(theme.SEVERITY.keys()) == {"info", "warn", "crit"}


def test_load_default_font_returns_usable_font():
    font = theme.load_default_font(12)
    # Must be either a TrueType (DejaVu) or the legacy bitmap default.
    assert hasattr(font, "getbbox") or hasattr(font, "getmask")


def test_load_default_font_renders_unicode_without_crash():
    """Regression for the latin-1 bitmap default crash from PR #134."""
    img = Image.new("RGB", (60, 20), color=(0, 0, 0))
    draw = ImageDraw.Draw(img)
    draw.text((2, 2), "○ NOMINAL", fill=(0, 255, 0),
              font=theme.load_default_font(12))
