# packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/framebuffer.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Direct /dev/fb0 framebuffer blit via mmap.

The Pi 4B's DSI panel exposes /dev/fb0 at 800×480, 32-bit BGRA when the
vc4-kms-v3d overlay is active. We open it once, mmap the full size, and
blit Pillow images into it on each render tick.
"""
from __future__ import annotations

import logging
import mmap
import os
from pathlib import Path

from PIL import Image

log = logging.getLogger("secubox_eye_square_kiosk.framebuffer")


class FrameBuffer:
    """Owns the mmap handle to /dev/fb0. Single-instance-per-process."""

    def __init__(self, path: str = "/dev/fb0", width: int = 800, height: int = 480, bpp: int = 4):
        self.path = path
        self.width = width
        self.height = height
        self.bpp = bpp
        self.size = width * height * bpp
        self.fd = os.open(path, os.O_RDWR)
        self.fb = mmap.mmap(self.fd, self.size, mmap.MAP_SHARED, mmap.PROT_WRITE)

    def blit(self, image: Image.Image) -> None:
        """Push a Pillow image to the framebuffer. Image must be RGBA at exact resolution."""
        if image.size != (self.width, self.height):
            raise ValueError(
                f"image size {image.size} doesn't match framebuffer {self.width}x{self.height}"
            )
        # Convert Pillow RGBA → BGRA for vc4-kms-v3d's little-endian BGRA32 layout
        bgra = image.tobytes("raw", "BGRA")
        self.fb.seek(0)
        self.fb.write(bgra)

    def close(self) -> None:
        self.fb.close()
        os.close(self.fd)

    def __enter__(self) -> "FrameBuffer":
        return self

    def __exit__(self, *_args) -> None:
        self.close()
