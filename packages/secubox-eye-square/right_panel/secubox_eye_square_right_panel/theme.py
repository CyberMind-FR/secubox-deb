# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Palette parser. Reads remote-ui/common/css/palette.css and exposes a {var → hex} dict."""
from __future__ import annotations

import logging
import re
from pathlib import Path

log = logging.getLogger("eye_square_right_panel.theme")

# Baked-in defaults — match remote-ui/common/css/palette.css from Phase 1.
# These are returned (a) when the palette file is missing, (b) when the file
# is empty / has no :root block. Real values in the file override these.
_DEFAULT_PALETTE = {
    "--auth": "#C04E24",
    "--wall": "#9A6010",
    "--boot": "#803018",
    "--mind": "#3D35A0",
    "--root": "#0A5840",
    "--mesh": "#104A88",
    "--cosmos-black": "#080808",
    "--gold-hermetic": "#c9a84c",
    "--cinnabar": "#e63946",
    "--matrix-green": "#00ff41",
    "--cyber-cyan": "#00d4ff",
    "--void-purple": "#6e40c9",
    "--text-primary": "#ccc",
    "--text-muted": "#4a4a4a",
}

_ROOT_BLOCK = re.compile(r":root\s*\{([^}]*)\}", re.DOTALL)
_VAR_DECL = re.compile(r"(--[a-z0-9-]+)\s*:\s*([^;]+);")


def parse_palette(path: Path) -> dict[str, str]:
    """Parse the :root block of a CSS file. Returns var → value dict. Falls back to defaults."""
    result: dict[str, str] = dict(_DEFAULT_PALETTE)
    try:
        text = Path(path).read_text()
    except OSError as e:
        log.warning("palette.css not readable at %s: %s — returning defaults", path, e)
        return result

    match = _ROOT_BLOCK.search(text)
    if not match:
        if text.strip():
            log.warning("No :root block in %s — returning defaults", path)
        return result

    for var, value in _VAR_DECL.findall(match.group(1)):
        result[var] = value.strip()
    return result
