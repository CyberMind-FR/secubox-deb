# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Tests for theme.py — palette + default font loading."""
from __future__ import annotations

from PIL import ImageDraw, ImageFont, Image

from secubox_eye_square_kiosk import theme


def test_palette_tuples_are_3_channel_rgb():
    """All module + token colors are (R, G, B) byte tuples."""
    for name in (
        "AUTH", "WALL", "BOOT", "MIND", "ROOT", "MESH",
        "COSMOS_BLACK", "GOLD_HERMETIC", "CINNABAR", "MATRIX_GREEN",
        "CYBER_CYAN", "VOID_PURPLE", "TEXT_PRIMARY", "TEXT_MUTED",
    ):
        c = getattr(theme, name)
        assert isinstance(c, tuple)
        assert len(c) == 3
        assert all(isinstance(b, int) and 0 <= b <= 255 for b in c)


def test_default_font_loads_and_is_usable():
    """theme.DEFAULT_FONT must be a Pillow ImageFont able to render Unicode.

    On hosts without fonts-dejavu-core, theme.py falls back to
    ImageFont.load_default() — still a usable font, just no Unicode.
    """
    assert isinstance(theme.DEFAULT_FONT, ImageFont.ImageFont) or hasattr(
        theme.DEFAULT_FONT, "getbbox"
    )
    # Smoke test: draw via the font without exploding
    img = Image.new("RGB", (60, 20), color=(0, 0, 0))
    draw = ImageDraw.Draw(img)
    draw.text((2, 2), "AUTH", fill=(255, 255, 255), font=theme.DEFAULT_FONT)


def test_default_font_renders_unicode_when_dejavu_available(tmp_path):
    """If fonts-dejavu-core is installed (e.g. on the target image),
    drawing ○ should not raise UnicodeEncodeError — the bug from #133.
    Test is best-effort: if the test runner doesn't have DejaVu we skip
    the Unicode assertion, but the .text() call still must not raise."""
    img = Image.new("RGB", (60, 20), color=(0, 0, 0))
    draw = ImageDraw.Draw(img)
    # ○ = U+25CB, the glyph that crashed ring_dashboard.py before #133.
    draw.text((2, 2), "○ NOMINAL", fill=(0, 255, 0), font=theme.DEFAULT_FONT)
