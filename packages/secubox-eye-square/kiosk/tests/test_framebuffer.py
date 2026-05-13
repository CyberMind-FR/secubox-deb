# packages/secubox-eye-square/kiosk/tests/test_framebuffer.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Tests for framebuffer.py — mmap blit. Uses a tmpfs file as fake /dev/fb0."""
from __future__ import annotations

from pathlib import Path

import pytest
from PIL import Image

from secubox_eye_square_kiosk.framebuffer import FrameBuffer


@pytest.fixture
def fake_fb(tmp_path: Path) -> Path:
    """Create a 800×480×4 bytes file simulating /dev/fb0 BGRA32."""
    path = tmp_path / "fb0"
    path.write_bytes(b"\x00" * (800 * 480 * 4))
    return path


def test_open_and_size(fake_fb: Path):
    fb = FrameBuffer(path=str(fake_fb), width=800, height=480, bpp=4)
    assert fb.width == 800
    assert fb.height == 480
    assert fb.bpp == 4
    assert fb.size == 800 * 480 * 4
    fb.close()


def test_blit_writes_image_bytes(fake_fb: Path):
    fb = FrameBuffer(path=str(fake_fb), width=800, height=480, bpp=4)
    img = Image.new("RGBA", (800, 480), color=(255, 0, 0, 255))  # red
    fb.blit(img)
    fb.close()
    raw = fake_fb.read_bytes()
    # First pixel: BGRA → blue=0, green=0, red=255, alpha=255
    assert raw[:4] == b"\x00\x00\xff\xff"


def test_blit_wrong_size_raises(fake_fb: Path):
    fb = FrameBuffer(path=str(fake_fb), width=800, height=480, bpp=4)
    img = Image.new("RGBA", (100, 100), color=(0, 0, 0, 255))
    with pytest.raises(ValueError, match="image size"):
        fb.blit(img)
    fb.close()
