# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Backfill: fix already-published billets whose bodies still cite BBS file
refs (`/f/NN.ext`) as dead text. billets never received those bytes (they live
in the BBS store), so the media never embedded. The repair re-fetches each ref
from the BBS via a resolver, ingests it through the SAME validated pipeline as a
live upload, and rewrites the body to the billets-relative `/media/…` — which
render then embeds. Idempotent: a rewritten body has no `/f/` left to match."""
import pytest

from api import repo
from api.models import BilletIn
from api.services import backfill_media
from api.services.render import render_markdown

NOW = "2026-07-11T12:00:00Z"

# Minimal but magic-byte-valid payloads (process_upload pins type by content).
_MP4 = b"\x00\x00\x00\x18ftypmp42" + b"\x00" * 32


def _png_bytes() -> bytes:
    import io
    from PIL import Image
    buf = io.BytesIO()
    Image.new("RGB", (24, 16), (10, 120, 200)).save(buf, format="PNG")
    return buf.getvalue()


async def _make_billet(conn, body: str) -> str:
    return await repo.create_billet(
        conn, BilletIn(body=body, ref_url="https://bbs.gk2.secubox.in/t/1",
                       embed_url=None, style="default", publish=True), now=NOW)


@pytest.mark.asyncio
async def test_video_ref_is_fetched_stored_and_body_rewritten(conn, tmp_path, monkeypatch):
    monkeypatch.setenv("BILLETS_MEDIA_DIR", str(tmp_path))
    bid = await _make_billet(conn, "Regarde ça\n\n/f/39.mp4\n")

    def resolve(num, ext):
        assert (num, ext) == ("39", "mp4")
        return _MP4, "video/mp4"

    touched, total = await backfill_media.run(conn, resolve, now=NOW)
    assert (touched, total) == (1, 1)

    row = await repo.get_by_id(conn, bid)
    assert "/f/39.mp4" not in row["body"]
    assert "/media/" in row["body"] and ".mp4" in row["body"]

    media = await repo.list_media(conn, bid)
    assert len(media) == 1 and media[0]["mime"] == "video/mp4"
    assert media[0]["thumb"] == ""              # a/v carry no vignette

    assert "<video" in render_markdown(row["body"])   # now embeds


@pytest.mark.asyncio
async def test_image_ref_is_reencoded_with_thumb(conn, tmp_path, monkeypatch):
    monkeypatch.setenv("BILLETS_MEDIA_DIR", str(tmp_path))
    bid = await _make_billet(conn, "photo\n\n/f/23.png\n")

    def resolve(num, ext):
        return _png_bytes(), "image/png"

    touched, total = await backfill_media.run(conn, resolve, now=NOW)
    assert (touched, total) == (1, 1)
    media = await repo.list_media(conn, bid)
    assert len(media) == 1 and media[0]["thumb"]        # image → vignette present
    assert "<img" in render_markdown((await repo.get_by_id(conn, bid))["body"])


@pytest.mark.asyncio
async def test_is_idempotent(conn, tmp_path, monkeypatch):
    monkeypatch.setenv("BILLETS_MEDIA_DIR", str(tmp_path))
    await _make_billet(conn, "clip\n\n/f/42.mp4\n")
    resolve = lambda num, ext: (_MP4, "video/mp4")

    first = await backfill_media.run(conn, resolve, now=NOW)
    second = await backfill_media.run(conn, resolve, now=NOW)
    assert first == (1, 1)
    assert second == (0, 0)          # nothing left to repair


@pytest.mark.asyncio
async def test_unresolvable_ref_is_left_intact(conn, tmp_path, monkeypatch):
    monkeypatch.setenv("BILLETS_MEDIA_DIR", str(tmp_path))
    bid = await _make_billet(conn, "gone\n\n/f/999.mp4\n")

    touched, total = await backfill_media.run(conn, lambda num, ext: None, now=NOW)
    assert (touched, total) == (0, 0)
    assert "/f/999.mp4" in (await repo.get_by_id(conn, bid))["body"]  # untouched


@pytest.mark.asyncio
async def test_mismatched_content_is_rejected_not_stored(conn, tmp_path, monkeypatch):
    monkeypatch.setenv("BILLETS_MEDIA_DIR", str(tmp_path))
    bid = await _make_billet(conn, "fake\n\n/f/7.mp4\n")

    # Declared mp4 but bytes are not (no ftyp box) → process_upload refuses.
    touched, total = await backfill_media.run(
        conn, lambda num, ext: (b"not a video", "video/mp4"), now=NOW)
    assert (touched, total) == (0, 0)
    assert "/f/7.mp4" in (await repo.get_by_id(conn, bid))["body"]
    assert await repo.list_media(conn, bid) == []
