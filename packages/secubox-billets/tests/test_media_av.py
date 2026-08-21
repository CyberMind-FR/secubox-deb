# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#1094 — audio/vidéo/pdf embarqués : acceptés au téléversement (stockés tels
quels, épinglés au contenu), et rendus en <video>/<audio>/<img>/<embed>."""
import io

import pytest
from PIL import Image

from api.services import media
from api.services.render import render_markdown

MP4 = b"\x00\x00\x00\x18ftypmp42" + b"\x00" * 40
MP3 = b"ID3\x04\x00\x00\x00\x00\x00\x00" + b"\x00" * 40
WEBM = b"\x1aE\xdf\xa3" + b"\x00" * 40
WAV = b"RIFF\x24\x00\x00\x00WAVE" + b"\x00" * 40
OGG = b"OggS" + b"\x00" * 40
PDF = b"%PDF-1.7\n" + b"x" * 40


def _png():
    buf = io.BytesIO()
    Image.new("RGB", (32, 24), (20, 90, 160)).save(buf, format="PNG")
    return buf.getvalue()


@pytest.mark.parametrize("raw,ct,kind,ext", [
    (MP4, "video/mp4", "video", "mp4"),
    (WEBM, "video/webm", "video", "webm"),
    (MP3, "audio/mpeg", "audio", "mp3"),
    (WAV, "audio/wav", "audio", "wav"),
    (OGG, "audio/ogg", "audio", "ogg"),
    (PDF, "application/pdf", "pdf", "pdf"),
])
def test_accepts_and_stores_as_is(raw, ct, kind, ext):
    d = media.process_upload(raw, ct)
    assert d["kind"] == kind and d["ext"] == ext and d["mime"] == ct
    assert d["data"] == raw  # jamais ré-encodé


def test_rejects_content_type_mismatch():
    with pytest.raises(media.MediaError):
        media.process_upload(b"this is not a video", "video/mp4")


def test_rejects_oversize_av():
    with pytest.raises(media.MediaError):
        media.process_upload(MP4[:12] + b"\x00" * (media.MAX_AV_BYTES + 1), "video/mp4")


def test_image_path_still_reencodes():
    d = media.process_upload(_png(), "image/png")
    assert d["kind"] == "image" and d["ext"] == "png" and "thumb" in d


def test_render_embeds_media():
    assert "<video" in render_markdown("clip /media/x.mp4 fin")
    assert "<audio" in render_markdown("son /media/y.mp3")
    assert "<img" in render_markdown("photo /media/z.png")
    assert "<embed" in render_markdown("doc /media/d.pdf")


def test_render_forces_media_relative_no_exfiltration():
    # Une réf /media/ pointant sur un autre hôte devient billets-relative.
    out = render_markdown("piege https://evil.example/media/x.mp4")
    assert 'src="/media/x.mp4"' in out
    assert "evil.example" not in out


def test_render_ignores_non_media_url():
    out = render_markdown("lien https://site.example/video/x.mp4")
    assert "<video" not in out  # pas sous /media/
