# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""/dev/fb0 blit with bpp + actual-size auto-detect and numpy RGB565 packing.

The kiosk draws to a fixed 800x480 logical canvas (designed for the Pi 4B
official 7" DSI panel). On other displays — Pi 400 + HDMI monitor, mainly —
the framebuffer is the panel's native resolution (e.g. 1920x1080) and the
kiosk's 800x480 writes get sliced into the wider memory layout. Symptom:
the ring dashboard appears as rainbow stripes tiled across the screen.

Fix: detect the framebuffer's actual width and height at init via
/sys/class/graphics/<dev>/virtual_size; center-pad the 800x480 kiosk frame
into a black canvas of fb size before encoding. Kiosk coordinate system
stays unchanged.

Pillow has no RGB->RGB565 raw packer in versions >=9.4 (removed upstream)
so we vectorise the 16bpp pack via numpy.

EYE_SQUARE_FB_MODE env var overrides the byte-order detection for diagnostics.
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
    try:
        return int(Path(f"/sys/class/graphics/{name}/bits_per_pixel").read_text().strip())
    except (OSError, ValueError):
        return 32


def _read_sysfs_size(fb_path: str, fallback: tuple[int, int]) -> tuple[int, int]:
    """Read virtual_size as a (width, height) tuple. Fall back if missing
    (e.g. unit tests using a regular file as a fake /dev/fb0)."""
    name = os.path.basename(fb_path)
    try:
        s = Path(f"/sys/class/graphics/{name}/virtual_size").read_text().strip()
        w, h = s.split(",")
        return int(w), int(h)
    except (OSError, ValueError):
        return fallback


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
    """Pack a Pillow RGB image to RGB565 little-endian bytes via numpy.

    DRM_FORMAT_RGB565: R in top 5 bits, G in middle 6, B in low 5.
    Stored as little-endian uint16 in memory.
    """
    arr = np.asarray(image.convert("RGB"), dtype=np.uint16)
    r = arr[:, :, 0]
    g = arr[:, :, 1]
    b = arr[:, :, 2]
    pixels = ((r & 0xF8) << 8) | ((g & 0xFC) << 3) | (b >> 3)
    return pixels.astype("<u2").tobytes()


class FrameBuffer:
    """Owns the mmap handle to /dev/fb0 and center-pads the kiosk's logical
    canvas into the actual fb resolution on every blit."""

    def __init__(self, path: str = "/dev/fb0",
                 logical_width: int = 800, logical_height: int = 480):
        self.path = path
        self.logical_width = logical_width
        self.logical_height = logical_height
        self.fd = os.open(path, os.O_RDWR)
        self.raw_mode, self.bpp = _detect_mode(self.fd, path)
        self.width, self.height = _read_sysfs_size(
            path, (logical_width, logical_height)
        )
        self.size = self.width * self.height * self.bpp
        if (self.width, self.height) != (logical_width, logical_height):
            log.warning(
                "fb actual size %dx%d != kiosk logical %dx%d — will center-pad",
                self.width, self.height, logical_width, logical_height,
            )
        log.warning("fb opened: %s actual=%dx%d logical=%dx%d bpp=%d mode=%s size=%d bytes",
                    path, self.width, self.height,
                    logical_width, logical_height, self.bpp, self.raw_mode, self.size)
        self.fb = mmap.mmap(self.fd, self.size, mmap.MAP_SHARED, mmap.PROT_WRITE)

    def _pad_to_fb(self, image: Image.Image) -> Image.Image:
        """Center-paste the kiosk's logical image into a black canvas of
        actual fb size. No-op if sizes already match."""
        if image.size == (self.width, self.height):
            return image
        canvas = Image.new("RGB", (self.width, self.height), (0, 0, 0))
        x_off = (self.width - image.size[0]) // 2
        y_off = (self.height - image.size[1]) // 2
        canvas.paste(image.convert("RGB"), (x_off, y_off))
        return canvas

    def blit(self, image: Image.Image) -> None:
        if image.size != (self.logical_width, self.logical_height):
            raise ValueError(
                f"image size {image.size} != logical "
                f"{self.logical_width}x{self.logical_height}"
            )
        padded = self._pad_to_fb(image)
        if self.raw_mode == "RGB565":
            raw = _pack_rgb565(padded)
        else:
            raw = padded.tobytes("raw", self.raw_mode)
        self.fb.seek(0)
        self.fb.write(raw)

    def close(self) -> None:
        self.fb.close()
        os.close(self.fd)

    def __enter__(self) -> "FrameBuffer":
        return self

    def __exit__(self, *_args) -> None:
        self.close()
