# packages/secubox-eye-square/kiosk/tests/test_framebuffer.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Tests for framebuffer.py — mmap blit + bpp auto-detect.

Uses a tmpfs file as fake /dev/fb0. The detection helpers
(_read_sysfs_bpp, FBIOGET_VSCREENINFO ioctl) gracefully fall back
to defaults when the path isn't a real fbdev character device,
which is exactly the test scenario.
"""
from __future__ import annotations

from pathlib import Path
from unittest import mock

import pytest
from PIL import Image

from secubox_eye_square_kiosk import framebuffer as fb_mod
from secubox_eye_square_kiosk.framebuffer import FrameBuffer


@pytest.fixture
def fake_fb_32bpp(tmp_path: Path) -> Path:
    """Create an 800×480×4 byte file simulating /dev/fb0 in 32bpp BGRA."""
    path = tmp_path / "fb0"
    path.write_bytes(b"\x00" * (800 * 480 * 4))
    return path


@pytest.fixture
def fake_fb_16bpp(tmp_path: Path) -> Path:
    """Create an 800×480×2 byte file simulating /dev/fb0 in 16bpp RGB565."""
    path = tmp_path / "fb0"
    path.write_bytes(b"\x00" * (800 * 480 * 2))
    return path


def test_open_and_size_32bpp(fake_fb_32bpp: Path):
    """When sysfs is unreadable, detection falls back to 32bpp BGRA."""
    fb = FrameBuffer(path=str(fake_fb_32bpp), width=800, height=480)
    assert fb.width == 800
    assert fb.height == 480
    assert fb.bpp == 4
    assert fb.size == 800 * 480 * 4
    assert fb.raw_mode == "BGRA"
    fb.close()


def test_blit_writes_bgra_bytes_at_32bpp(fake_fb_32bpp: Path):
    fb = FrameBuffer(path=str(fake_fb_32bpp), width=800, height=480)
    img = Image.new("RGBA", (800, 480), color=(255, 0, 0, 255))  # red
    fb.blit(img)
    fb.close()
    raw = fake_fb_32bpp.read_bytes()
    # First pixel: BGRA → blue=0, green=0, red=255, alpha=255
    assert raw[:4] == b"\x00\x00\xff\xff"


def test_blit_wrong_size_raises(fake_fb_32bpp: Path):
    fb = FrameBuffer(path=str(fake_fb_32bpp), width=800, height=480)
    img = Image.new("RGBA", (100, 100), color=(0, 0, 0, 255))
    with pytest.raises(ValueError, match="image size"):
        fb.blit(img)
    fb.close()


def test_env_override_picks_explicit_mode(monkeypatch, fake_fb_32bpp: Path):
    """EYE_SQUARE_FB_MODE overrides sysfs/ioctl detection."""
    monkeypatch.setenv("EYE_SQUARE_FB_MODE", "RGBA")
    fb = FrameBuffer(path=str(fake_fb_32bpp), width=800, height=480)
    assert fb.raw_mode == "RGBA"
    fb.close()


def test_detection_picks_rgb565_when_sysfs_reports_16bpp(
    monkeypatch, fake_fb_16bpp: Path
):
    """Force the sysfs reader to return 16 → kiosk uses RGB565 numpy path."""
    monkeypatch.setattr(fb_mod, "_read_sysfs_bpp", lambda _: 16)
    fb = FrameBuffer(path=str(fake_fb_16bpp), width=800, height=480)
    assert fb.bpp == 2
    assert fb.raw_mode == "RGB565"
    assert fb.size == 800 * 480 * 2
    fb.close()


def test_blit_rgb565_packs_via_numpy(monkeypatch, fake_fb_16bpp: Path):
    """Verify RGB565 numpy pack: R top 5 bits, G middle 6, B low 5,
    little-endian uint16 stored as memory bytes [low, high]."""
    monkeypatch.setattr(fb_mod, "_read_sysfs_bpp", lambda _: 16)
    fb = FrameBuffer(path=str(fake_fb_16bpp), width=800, height=480)
    img = Image.new("RGB", (800, 480), color=(0xFF, 0x00, 0x00))  # pure red
    fb.blit(img)
    fb.close()
    raw = fake_fb_16bpp.read_bytes()
    # Pure red (R=0xFF, G=0, B=0) packed as RGB565:
    #   pixel = ((0xFF & 0xF8) << 8) | ((0 & 0xFC) << 3) | (0 >> 3)
    #         = 0xF800
    # Stored little-endian: bytes [0x00, 0xF8]
    assert raw[:2] == b"\x00\xf8"
    # Pure red → same on every pixel
    assert raw[800 * 480 * 2 - 2 : 800 * 480 * 2] == b"\x00\xf8"


def test_blit_rgb565_black_packs_to_zero(monkeypatch, fake_fb_16bpp: Path):
    """Black (0, 0, 0) RGB565 = 0x0000 regardless of channel layout."""
    monkeypatch.setattr(fb_mod, "_read_sysfs_bpp", lambda _: 16)
    fb = FrameBuffer(path=str(fake_fb_16bpp), width=800, height=480)
    img = Image.new("RGB", (800, 480), color=(0, 0, 0))
    fb.blit(img)
    fb.close()
    raw = fake_fb_16bpp.read_bytes()
    assert raw[:2] == b"\x00\x00"
