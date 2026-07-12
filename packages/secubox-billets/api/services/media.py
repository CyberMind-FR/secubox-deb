# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""
SecuBox-Deb :: billets media
CyberMind — https://cybermind.fr

Image ingestion for billet attachments. Uploads are NEVER trusted or stored
as-received: every image is decoded with Pillow, verified, then FULLY
re-encoded from pixels. Re-encoding is the security property — it drops EXIF
(incl. GPS, a CSPN privacy concern) and neutralises polyglot/appended-payload
files, because only the decoded raster survives. SVG is refused outright (an
XSS vector). A downscaled thumbnail (the vignette) is produced alongside.

All calls are synchronous CPU work (Pillow); callers on the async event loop
MUST run them via `asyncio.to_thread` so they never block the shared loop.
"""
from __future__ import annotations

import io
import os
from pathlib import Path

from PIL import Image, ImageOps

MAX_BYTES = 5 * 1024 * 1024          # 5 MiB hard cap per file
MAX_DIM = 4096                        # refuse absurd dimensions (decompression bombs)
THUMB_MAX = (480, 480)               # vignette bounding box

# Pillow format name -> (extension, mime). This is the allow-list; anything
# else (SVG, BMP, TIFF, ICO, …) is refused.
_ALLOWED: dict[str, tuple[str, str]] = {
    "PNG": ("png", "image/png"),
    "JPEG": ("jpg", "image/jpeg"),
    "WEBP": ("webp", "image/webp"),
    "GIF": ("gif", "image/gif"),
}

# Guard against decompression bombs before we allocate the full raster.
Image.MAX_IMAGE_PIXELS = MAX_DIM * MAX_DIM


class MediaError(ValueError):
    """Raised for any invalid / unsupported / oversized upload."""


def media_dir() -> Path:
    # Resolved at call time so BILLETS_MEDIA_DIR is honoured after import (tests).
    return Path(os.environ.get("BILLETS_MEDIA_DIR", "/var/lib/secubox/billets/media"))


def _encode(img: Image.Image, fmt: str) -> bytes:
    """Re-encode a PIL image to `fmt`, dropping all source metadata."""
    out = img
    if fmt == "JPEG" and img.mode not in ("RGB", "L"):
        out = img.convert("RGB")
    buf = io.BytesIO()
    kwargs: dict = {}
    if fmt == "GIF" and getattr(img, "is_animated", False):
        kwargs["save_all"] = True
    if fmt in ("JPEG", "WEBP"):
        kwargs["quality"] = 85
    out.save(buf, format=fmt, **kwargs)
    return buf.getvalue()


def process(raw: bytes) -> dict:
    """Validate + re-encode + thumbnail an uploaded image.

    Returns {ext, mime, width, height, data, thumb} where `data`/`thumb` are
    the cleaned bytes. Raises MediaError on anything that is not an allowed,
    well-formed image within limits."""
    if not raw:
        raise MediaError("empty upload")
    if len(raw) > MAX_BYTES:
        raise MediaError(f"file too large (> {MAX_BYTES // (1024 * 1024)} MiB)")
    try:
        probe = Image.open(io.BytesIO(raw))
        probe.verify()                      # structural check; leaves probe unusable
        img = Image.open(io.BytesIO(raw))   # reopen for actual pixel access
        img.load()
    except MediaError:
        raise
    except Exception as e:                  # noqa: BLE001 — Pillow raises many types
        raise MediaError(f"not a valid image: {e}") from None

    fmt = (img.format or "").upper()
    if fmt not in _ALLOWED:
        raise MediaError(f"unsupported image format: {fmt or 'unknown'}")
    ext, mime = _ALLOWED[fmt]

    width, height = img.size
    if width <= 0 or height <= 0 or width > MAX_DIM or height > MAX_DIM:
        raise MediaError(f"image dimensions out of range ({width}x{height})")

    img = ImageOps.exif_transpose(img)      # bake orientation in, then EXIF is gone
    data = _encode(img, fmt)

    # Thumbnail: first frame for animated GIFs, always a static vignette.
    thumb_img = img
    if getattr(thumb_img, "is_animated", False):
        thumb_img.seek(0)
    thumb_img = thumb_img.convert("RGBA") if fmt in ("PNG", "WEBP", "GIF") else thumb_img.convert("RGB")
    thumb_img.thumbnail(THUMB_MAX, Image.LANCZOS)
    thumb_fmt = "PNG" if fmt in ("PNG", "GIF") else fmt   # static thumb; keep alpha via PNG
    thumb = _encode(thumb_img, thumb_fmt)

    return {"ext": ext, "mime": mime, "width": width, "height": height,
            "data": data, "thumb": thumb}


def _thumb_ext(ext: str) -> str:
    return "png" if ext in ("png", "gif") else ext


def store(media_id: str, processed: dict, directory: Path | None = None) -> tuple[str, str]:
    """Write the cleaned image + thumbnail under `directory` (default media_dir()).
    Returns (filename, thumb_filename)."""
    d = directory or media_dir()
    d.mkdir(parents=True, exist_ok=True)
    filename = f"{media_id}.{processed['ext']}"
    thumb_name = f"{media_id}_t.{_thumb_ext(processed['ext'])}"
    (d / filename).write_bytes(processed["data"])
    (d / thumb_name).write_bytes(processed["thumb"])
    return filename, thumb_name


def delete_files(filename: str, thumb: str, directory: Path | None = None) -> None:
    """Remove an attachment's files (best-effort; missing files are ignored)."""
    d = directory or media_dir()
    for name in (filename, thumb):
        try:
            (d / name).unlink()
        except FileNotFoundError:
            pass
        except OSError:
            pass


def read_bytes(filename: str, directory: Path | None = None) -> bytes:
    """Read a stored media file (for the portable .sbxsite export)."""
    d = directory or media_dir()
    return (d / filename).read_bytes()
