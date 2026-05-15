# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Tests for secubox_common.icons — path resolution + LRU cache."""
from pathlib import Path

from PIL import Image

from secubox_common import icons


def test_load_missing_icon_returns_none(monkeypatch, tmp_path):
    """No icon file anywhere → None, no exception."""
    monkeypatch.setattr(icons, "ICON_SEARCH_PATHS",
                        [tmp_path / "does-not-exist"])
    icons._cache_clear()
    assert icons.load_module_icon("auth", 48) is None


def test_load_existing_icon_returns_pil_image(monkeypatch, tmp_path):
    """Icon found in the search path is returned as a Pillow image."""
    iconsdir = tmp_path / "icons"
    iconsdir.mkdir()
    fake = Image.new("RGBA", (48, 48), (255, 0, 0, 255))
    fake.save(iconsdir / "auth-48.png")

    monkeypatch.setattr(icons, "ICON_SEARCH_PATHS", [iconsdir])
    icons._cache_clear()

    img = icons.load_module_icon("auth", 48)
    assert img is not None
    assert img.size == (48, 48)


def test_load_caches_by_name_and_size(monkeypatch, tmp_path):
    """Second call with same (name, size) returns the same object."""
    iconsdir = tmp_path / "icons"
    iconsdir.mkdir()
    Image.new("RGBA", (48, 48), (0, 255, 0, 255)).save(iconsdir / "wall-48.png")

    monkeypatch.setattr(icons, "ICON_SEARCH_PATHS", [iconsdir])
    icons._cache_clear()

    a = icons.load_module_icon("wall", 48)
    b = icons.load_module_icon("wall", 48)
    assert a is b


def test_search_paths_in_order(monkeypatch, tmp_path):
    """First path with the icon wins, even if later paths also have one."""
    first = tmp_path / "first"; first.mkdir()
    second = tmp_path / "second"; second.mkdir()
    Image.new("RGBA", (48, 48), (255, 0, 0, 255)).save(first / "boot-48.png")
    Image.new("RGBA", (48, 48), (0, 0, 255, 255)).save(second / "boot-48.png")

    monkeypatch.setattr(icons, "ICON_SEARCH_PATHS", [first, second])
    icons._cache_clear()

    img = icons.load_module_icon("boot", 48)
    # Pixel-sample to confirm we got the RED one (first path)
    px = img.getpixel((0, 0))
    assert px[:3] == (255, 0, 0)


def test_lowercase_name_normalisation(monkeypatch, tmp_path):
    """Caller can pass 'AUTH' or 'auth' — both find auth-48.png."""
    iconsdir = tmp_path / "icons"
    iconsdir.mkdir()
    Image.new("RGBA", (48, 48), (1, 2, 3, 255)).save(iconsdir / "auth-48.png")
    monkeypatch.setattr(icons, "ICON_SEARCH_PATHS", [iconsdir])
    icons._cache_clear()

    assert icons.load_module_icon("AUTH", 48) is not None
    assert icons.load_module_icon("auth", 48) is not None
