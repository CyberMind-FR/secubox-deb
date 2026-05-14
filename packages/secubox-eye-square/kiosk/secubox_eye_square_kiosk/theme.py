# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Hardcoded SecuBox palette (RGB tuples for Pillow). Matches Phase 1 round/'s
literal hex values."""
from __future__ import annotations

# Module colours (from round/index.html literals — see Phase 1 spec)
AUTH = (0xC0, 0x4E, 0x24)
WALL = (0x9A, 0x60, 0x10)
BOOT = (0x80, 0x30, 0x18)
MIND = (0x3D, 0x35, 0xA0)
ROOT = (0x0A, 0x58, 0x40)
MESH = (0x10, 0x4A, 0x88)

# C3BOX shared tokens
COSMOS_BLACK = (0x08, 0x08, 0x08)
GOLD_HERMETIC = (0xC9, 0xA8, 0x4C)
CINNABAR = (0xE6, 0x39, 0x46)
MATRIX_GREEN = (0x00, 0xFF, 0x41)
CYBER_CYAN = (0x00, 0xD4, 0xFF)
VOID_PURPLE = (0x6E, 0x40, 0xC9)
TEXT_PRIMARY = (0xCC, 0xCC, 0xCC)
TEXT_MUTED = (0x4A, 0x4A, 0x4A)

# Severity dot colours (used by alerts tab)
SEVERITY = {
    "info": CYBER_CYAN,
    "warn": GOLD_HERMETIC,
    "crit": CINNABAR,
}

# Default font for all draw.text() calls in the kiosk. Pillow's
# load_default() on Bookworm is a latin-1 bitmap font that crashes on
# Unicode glyphs (○ ● ▶ ⚠). Loading DejaVuSans explicitly — apt
# dep python3-pil + fonts-dejavu-core (added in the same fix). Falls
# back to load_default() if the TTF isn't present (e.g. unit tests on
# a host without fonts-dejavu-core).
from PIL import ImageFont as _ImageFont  # noqa: E402

_DEJAVU = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
try:
    DEFAULT_FONT = _ImageFont.truetype(_DEJAVU, 12)
except OSError:
    DEFAULT_FONT = _ImageFont.load_default()
