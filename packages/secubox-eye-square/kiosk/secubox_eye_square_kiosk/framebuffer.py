# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""/dev/fb0 blit with bpp auto-detect and numpy-based RGB565 packing.

Pi 4B 7-inch DSI via vc4drmfb is DRM_FORMAT_RGB565 (16bpp, R in top 5 bits).
Pillow has no RGB->RGB565 raw packer in versions >=9.4 — they were removed
upstream. We use numpy for fast vectorised packing instead.

Detection order:
  - read /sys/class/graphics/<dev>/bits_per_pixel
  - 16bpp: numpy pack to RGB565 little-endian uint16
  - 32bpp: ioctl FBIOGET_VSCREENINFO -> BGRA/RGBA/ARGB/ABGR Pillow raw mode
  - EYE_SQUARE_FB_MODE env var overrides for diagnostics
"""
from __future__ import annotations

import ctypes
import fcntl
import logging
import mmap
import os
from pathlib import Path

import numpy as np
from PIL import Image

log = logging.getLogger("secubox_eye_square_kiosk.framebuffer")
FBIOGET_VSCREENINFO = 0x4600


class _fb_bitfield(ctypes.Structure):
    _fields_ = [("offset", ctypes.c_uint32),
                ("length", ctypes.c_uint32),
                ("msb_right", ctypes.c_uint32)]


class _fb_var_screeninfo(ctypes.Structure):
    _fields_ = [
        ("xres", ctypes.c_uint32), ("yres", ctypes.c_uint32),
        ("xres_virtual", ctypes.c_uint32), ("yres_virtual", ctypes.c_uint32),
        ("xoffset", ctypes.c_uint32), ("yoffset", ctypes.c_uint32),
        ("bits_per_pixel", ctypes.c_uint32), ("grayscale", ctypes.c_uint32),
        ("red", _fb_bitfield), ("green", _fb_bitfield),
        ("blue", _fb_bitfield), ("transp", _fb_bitfield),
        ("_pad", ctypes.c_uint8 * 256),
    ]


_OFFSET_TO_MODE32 = {
    (16, 8, 0):  "BGRA",
    (0, 8, 16):  "RGBA",
    (8, 16, 24): "ARGB",
    (24, 16, 8): "ABGR",
}


def _read_sysfs_bpp(fb_path: str) -> int:
    name = os.path.basename(fb_path)
    p = Path(f"/sys/class/graphics/{name}/bits_per_pixel")
    try:
        return int(p.read_text().strip())
    except (OSError, ValueError):
        return 32


def _detect_mode(fd: int, fb_path: str) -> tuple[str, int]:
    override = os.environ.get("EYE_SQUARE_FB_MODE")
    bpp_bits = _read_sysfs_bpp(fb_path)
    bpp_bytes = max(1, bpp_bits // 8)
    log.warning("fb sysfs bpp=%dbits (%d bytes/pixel)", bpp_bits, bpp_bytes)
    if override:
        log.warning("EYE_SQUARE_FB_MODE override = %s", override)
        return override, bpp_bytes
    if bpp_bits == 16:
        return "RGB565", 2
    try:
        v = _fb_var_screeninfo()
        fcntl.ioctl(fd, FBIOGET_VSCREENINFO, v)
        log.warning(
            "fb_var_screeninfo %dx%d %dbpp R(%d,%d) G(%d,%d) B(%d,%d) A(%d,%d)",
            v.xres, v.yres, v.bits_per_pixel,
            v.red.offset, v.red.length,
            v.green.offset, v.green.length,
            v.blue.offset, v.blue.length,
            v.transp.offset, v.transp.length,
        )
        key = (v.red.offset, v.green.offset, v.blue.offset)
        return _OFFSET_TO_MODE32.get(key, "BGRA"), bpp_bytes
    except OSError as e:
        log.warning("FBIOGET_VSCREENINFO failed (%s)", e)
        return "BGRA", bpp_bytes


def _pack_rgb565(image: Image.Image) -> bytes:
    """Pack a Pillow RGBA/RGB image to RGB565 little-endian bytes via numpy.

    DRM_FORMAT_RGB565: R in top 5 bits, G in middle 6, B in low 5.
    Stored as little-endian uint16 in memory: bytes [G3B5, R5G3].
    """
    arr = np.asarray(image.convert("RGB"), dtype=np.uint16)
    r = arr[:, :, 0]
    g = arr[:, :, 1]
    b = arr[:, :, 2]
    pixels = ((r & 0xF8) << 8) | ((g & 0xFC) << 3) | (b >> 3)
    return pixels.astype("<u2").tobytes()


class FrameBuffer:
    def __init__(self, path="/dev/fb0", width=800, height=480):
        self.path, self.width, self.height = path, width, height
        self.fd = os.open(path, os.O_RDWR)
        self.raw_mode, self.bpp = _detect_mode(self.fd, path)
        self.size = width * height * self.bpp
        log.warning("fb opened: %s %dx%d bpp=%d mode=%s size=%d bytes",
                    path, width, height, self.bpp, self.raw_mode, self.size)
        self.fb = mmap.mmap(self.fd, self.size, mmap.MAP_SHARED, mmap.PROT_WRITE)

    def blit(self, image):
        if image.size != (self.width, self.height):
            raise ValueError(
                f"image size {image.size} != framebuffer {self.width}x{self.height}"
            )
        if self.raw_mode == "RGB565":
            raw = _pack_rgb565(image)
        else:
            raw = image.tobytes("raw", self.raw_mode)
        self.fb.seek(0)
        self.fb.write(raw)

    def close(self):
        self.fb.close()
        os.close(self.fd)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
