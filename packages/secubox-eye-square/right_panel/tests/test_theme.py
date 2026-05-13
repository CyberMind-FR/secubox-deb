# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Tests for the theme module — parses common/css/palette.css."""
from __future__ import annotations

import textwrap
from pathlib import Path

from secubox_eye_square_right_panel.theme import parse_palette


def test_parse_palette_extracts_module_colours(tmp_path):
    css = textwrap.dedent("""
        :root {
          --auth: #C04E24;
          --wall: #9A6010;
          --boot: #803018;
          --mind: #3D35A0;
          --root: #0A5840;
          --mesh: #104A88;
          --cosmos-black: #080808;
        }
    """).strip()
    p = tmp_path / "palette.css"
    p.write_text(css)
    palette = parse_palette(p)
    assert palette["--auth"] == "#C04E24"
    assert palette["--mesh"] == "#104A88"
    assert palette["--cosmos-black"] == "#080808"


def test_parse_palette_skips_non_root_rules(tmp_path):
    css = textwrap.dedent("""
        :root { --auth: #C04E24; }
        body { color: #ffffff; }
        .pod { background: #000; }
    """).strip()
    p = tmp_path / "palette.css"
    p.write_text(css)
    palette = parse_palette(p)
    assert "--auth" in palette
    assert "color" not in palette
    assert "background" not in palette


def test_parse_palette_missing_file_returns_defaults(tmp_path):
    palette = parse_palette(tmp_path / "missing.css")
    # baked-in fallback present
    assert palette["--auth"] == "#C04E24"
    assert palette["--mesh"] == "#104A88"
    assert palette["--cosmos-black"] == "#080808"


def test_parse_palette_empty_file_returns_defaults(tmp_path):
    p = tmp_path / "empty.css"
    p.write_text("")
    palette = parse_palette(p)
    assert palette["--auth"] == "#C04E24"  # defaults still apply


def test_parse_palette_overrides_defaults(tmp_path):
    """A custom :root with one var should override that default but keep others."""
    p = tmp_path / "p.css"
    p.write_text(":root { --auth: #FF0000; }")
    palette = parse_palette(p)
    assert palette["--auth"] == "#FF0000"  # overridden
    assert palette["--wall"] == "#9A6010"  # default preserved
