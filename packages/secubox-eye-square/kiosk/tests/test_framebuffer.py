# packages/secubox-eye-square/kiosk/tests/test_framebuffer.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Tests for framebuffer.py — bpp + size auto-detect, RGB565 numpy pack,
and center-padding when the fb is larger than the kiosk's logical canvas."""
from __future__ import annotations

from pathlib import Path

import pytest
from PIL import Image

from secubox_eye_square_kiosk import framebuffer as fb_mod
from secubox_eye_square_kiosk.framebuffer import FrameBuffer


@pytest.fixture(autouse=True)
def _isolate_sysfs(monkeypatch):
    """Tests use fake fb files outside /dev/ — _read_sysfs_size would
    otherwise pick up the laptop's real /sys/class/graphics/fb0/virtual_size
    (e.g. 1920x1080) and break mmap sizing against the tmp fixture."""
    monkeypatch.setattr(fb_mod, "_read_sysfs_size",
                        lambda _path, fallback: fallback)
    yield


@pytest.fixture
def fake_fb_32bpp(tmp_path: Path) -> Path:
    """800x480 fb file (BGRA32). Sysfs is absent for the tmp path so
    detection falls back to logical defaults — width=height match."""
    path = tmp_path / "fb0"
    path.write_bytes(b"\x00" * (800 * 480 * 4))
    return path


@pytest.fixture
def fake_fb_16bpp_logical(tmp_path: Path) -> Path:
    """800x480 fb file in 16bpp."""
    path = tmp_path / "fb0"
    path.write_bytes(b"\x00" * (800 * 480 * 2))
    return path


@pytest.fixture
def fake_fb_16bpp_hdmi(tmp_path: Path) -> Path:
    """1920x1080 fb file in 16bpp — simulates Pi 400 + HDMI monitor."""
    path = tmp_path / "fb0"
    path.write_bytes(b"\x00" * (1920 * 1080 * 2))
    return path


def test_open_and_size_32bpp_default_logical(fake_fb_32bpp: Path):
    """When sysfs is unreadable, FrameBuffer falls back to logical 800x480."""
    fb = FrameBuffer(path=str(fake_fb_32bpp))
    assert fb.width == 800
    assert fb.height == 480
    assert fb.bpp == 4
    assert fb.size == 800 * 480 * 4
    assert fb.raw_mode == "BGRA"
    fb.close()


def test_blit_writes_bgra_bytes_at_32bpp(fake_fb_32bpp: Path):
    fb = FrameBuffer(path=str(fake_fb_32bpp))
    img = Image.new("RGBA", (800, 480), color=(255, 0, 0, 255))  # red
    fb.blit(img)
    fb.close()
    raw = fake_fb_32bpp.read_bytes()
    # First pixel: BGRA → blue=0, green=0, red=255, alpha=255 (alpha from black fill)
    assert raw[:4] == b"\x00\x00\xff\xff"


def test_blit_wrong_logical_size_raises(fake_fb_32bpp: Path):
    fb = FrameBuffer(path=str(fake_fb_32bpp))
    img = Image.new("RGBA", (100, 100), color=(0, 0, 0, 255))
    with pytest.raises(ValueError, match="image size"):
        fb.blit(img)
    fb.close()


def test_env_override_picks_explicit_mode(monkeypatch, fake_fb_32bpp: Path):
    monkeypatch.setenv("EYE_SQUARE_FB_MODE", "RGBA")
    fb = FrameBuffer(path=str(fake_fb_32bpp))
    assert fb.raw_mode == "RGBA"
    fb.close()


def test_detection_picks_rgb565_when_sysfs_reports_16bpp(
    monkeypatch, fake_fb_16bpp_logical: Path
):
    monkeypatch.setattr(fb_mod, "_read_sysfs_bpp", lambda _: 16)
    fb = FrameBuffer(path=str(fake_fb_16bpp_logical))
    assert fb.bpp == 2
    assert fb.raw_mode == "RGB565"
    assert fb.size == 800 * 480 * 2
    fb.close()


def test_blit_rgb565_packs_via_numpy(monkeypatch, fake_fb_16bpp_logical: Path):
    """RGB565 pure-red pack: pixel = 0xF800, LE bytes [0x00, 0xF8]."""
    monkeypatch.setattr(fb_mod, "_read_sysfs_bpp", lambda _: 16)
    fb = FrameBuffer(path=str(fake_fb_16bpp_logical))
    img = Image.new("RGB", (800, 480), color=(0xFF, 0x00, 0x00))
    fb.blit(img)
    fb.close()
    raw = fake_fb_16bpp_logical.read_bytes()
    assert raw[:2] == b"\x00\xf8"
    # Pure-red on every pixel
    assert raw[800 * 480 * 2 - 2 : 800 * 480 * 2] == b"\x00\xf8"


def test_blit_rgb565_black_packs_to_zero(monkeypatch, fake_fb_16bpp_logical: Path):
    monkeypatch.setattr(fb_mod, "_read_sysfs_bpp", lambda _: 16)
    fb = FrameBuffer(path=str(fake_fb_16bpp_logical))
    fb.blit(Image.new("RGB", (800, 480), color=(0, 0, 0)))
    fb.close()
    assert fake_fb_16bpp_logical.read_bytes()[:2] == b"\x00\x00"


# ---- center-pad tests (Pi 400 HDMI) ----

def test_fb_size_detection_uses_sysfs_when_available(
    monkeypatch, fake_fb_16bpp_hdmi: Path
):
    """Simulate a 1920x1080 HDMI fb. With the sysfs reader forced to that
    size, the kiosk's 800x480 logical canvas should be center-padded."""
    monkeypatch.setattr(fb_mod, "_read_sysfs_bpp", lambda _: 16)
    monkeypatch.setattr(fb_mod, "_read_sysfs_size", lambda *_: (1920, 1080))
    fb = FrameBuffer(path=str(fake_fb_16bpp_hdmi))
    assert fb.width == 1920
    assert fb.height == 1080
    assert fb.logical_width == 800
    assert fb.logical_height == 480
    assert fb.size == 1920 * 1080 * 2
    fb.close()


def test_blit_pads_into_larger_fb(monkeypatch, fake_fb_16bpp_hdmi: Path):
    """Kiosk renders 800x480 red square; fb is 1920x1080. Expected: the
    center 800x480 rows hold red pixels (0xF800), the outer rows are
    black (0x0000). The center starts at row (1080-480)/2 = 300 and
    column (1920-800)/2 = 560."""
    monkeypatch.setattr(fb_mod, "_read_sysfs_bpp", lambda _: 16)
    monkeypatch.setattr(fb_mod, "_read_sysfs_size", lambda *_: (1920, 1080))
    fb = FrameBuffer(path=str(fake_fb_16bpp_hdmi))
    img = Image.new("RGB", (800, 480), color=(0xFF, 0x00, 0x00))
    fb.blit(img)
    fb.close()
    raw = fake_fb_16bpp_hdmi.read_bytes()
    # Top-left pixel = black padding
    assert raw[:2] == b"\x00\x00"
    # Last pixel of first row = black padding
    assert raw[1919 * 2 : 1920 * 2] == b"\x00\x00"
    # Center pixel (row 540, col 960) should be red (in the padded region)
    center_offset = (540 * 1920 + 960) * 2
    assert raw[center_offset : center_offset + 2] == b"\x00\xf8"


def test_blit_no_pad_when_fb_equals_logical(
    monkeypatch, fake_fb_16bpp_logical: Path
):
    """sysfs reports 800x480 → no padding, fast path."""
    monkeypatch.setattr(fb_mod, "_read_sysfs_bpp", lambda _: 16)
    monkeypatch.setattr(fb_mod, "_read_sysfs_size", lambda *_: (800, 480))
    fb = FrameBuffer(path=str(fake_fb_16bpp_logical))
    assert fb.width == 800 and fb.height == 480
    img = Image.new("RGB", (800, 480), color=(0xFF, 0x00, 0x00))
    fb.blit(img)
    fb.close()
    raw = fake_fb_16bpp_logical.read_bytes()
    # Every pixel red — no padding
    assert raw[:2] == b"\x00\xf8"
    assert raw[-2:] == b"\x00\xf8"
