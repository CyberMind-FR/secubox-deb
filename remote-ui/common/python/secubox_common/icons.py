# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Module icon loader.

Resolves `<name>-<size>.png` across a search path list. The default
search order is:
  1. /var/www/common/assets/icons      (deployed image location — set by
                                        the build script when it embeds
                                        remote-ui/common/assets/icons/)
  2. <git-checkout>/remote-ui/common/assets/icons   (dev mode)

This fixes the bug where remote-ui/round/fb_dashboard.py hardcoded
ICONS_DIR = SCRIPT_DIR/assets/icons (which on the image points at
remote-ui/round/assets/icons/ — a directory without module icons) and
always fell back to first-letter placeholders.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from PIL import Image

log = logging.getLogger("secubox_common.icons")


# Mutable so tests + tools can override.
ICON_SEARCH_PATHS: list[Path] = [
    Path("/var/www/common/assets/icons"),
    # Dev checkout — secubox_common is at <repo>/remote-ui/common/python/secubox_common
    Path(__file__).resolve().parents[2] / "assets" / "icons",
]


_cache: dict[tuple[str, int], Optional[Image.Image]] = {}


def _cache_clear() -> None:
    """Test helper — invalidates the in-process cache."""
    _cache.clear()


def load_module_icon(name: str, size: int = 48) -> Optional[Image.Image]:
    """Return the PNG icon for the named module at the requested size.

    `name` is case-insensitive — `"AUTH"` and `"auth"` both find
    `auth-<size>.png`. Returns None if no file is found in any search
    path. The first call for a (name, size) miss is logged at WARNING;
    subsequent calls hit the negative cache and stay silent.
    """
    key = (name.lower(), int(size))
    if key in _cache:
        return _cache[key]

    filename = f"{key[0]}-{key[1]}.png"
    for d in ICON_SEARCH_PATHS:
        p = d / filename
        if p.exists():
            try:
                img = Image.open(p).convert("RGBA")
                _cache[key] = img
                return img
            except (OSError, ValueError) as e:
                log.warning("failed to load %s: %s", p, e)
                continue

    log.warning("module icon not found: %s (searched %s)",
                filename, [str(d) for d in ICON_SEARCH_PATHS])
    _cache[key] = None
    return None
