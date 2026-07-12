# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Media attachments: image ingestion (re-encode/EXIF-strip), upload/delete
flow, public gallery render, and the portable .sbxsite export."""
import io
import json
from pathlib import Path

import httpx
import pytest
import pytest_asyncio
from PIL import Image

from api import repo
from api.main import create_app
from api.services import media
from api.services import security as sec

PW = "s3cret-pass-123"
NOW = "2026-07-11T12:00:00Z"


def _png(color=(10, 120, 200), size=(64, 48)) -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", size, color).save(buf, format="PNG")
    return buf.getvalue()


def _jpeg_with_exif() -> bytes:
    buf = io.BytesIO()
    img = Image.new("RGB", (32, 32), (200, 30, 30))
    exif = Image.Exif()
    exif[0x0112] = 6                 # Orientation
    exif[0x8825] = {}                # a GPS IFD marker
    img.save(buf, format="JPEG", exif=exif)
    return buf.getvalue()


# ── unit: image ingestion ────────────────────────────────────────────────────
def test_process_png_returns_clean_and_thumb():
    out = media.process(_png(size=(1000, 500)))
    assert out["ext"] == "png" and out["mime"] == "image/png"
    assert out["width"] == 1000 and out["height"] == 500
    thumb = Image.open(io.BytesIO(out["thumb"]))
    assert max(thumb.size) <= 480          # vignette bounded


def test_process_strips_exif():
    out = media.process(_jpeg_with_exif())
    reopened = Image.open(io.BytesIO(out["data"]))
    assert not dict(reopened.getexif())    # metadata gone after re-encode


def test_process_rejects_non_image():
    with pytest.raises(media.MediaError):
        media.process(b"<svg xmlns='http://www.w3.org/2000/svg'></svg>")
    with pytest.raises(media.MediaError):
        media.process(b"not an image at all")


def test_process_rejects_oversized():
    with pytest.raises(media.MediaError):
        media.process(b"\x89PNG" + b"\x00" * (media.MAX_BYTES + 1))


def test_store_and_delete_roundtrip(tmp_path):
    out = media.process(_png())
    fn, thumb = media.store("01MEDIA0000000000000000AA", out, directory=tmp_path)
    assert (tmp_path / fn).exists() and (tmp_path / thumb).exists()
    assert media.read_bytes(fn, directory=tmp_path) == out["data"]
    media.delete_files(fn, thumb, directory=tmp_path)
    assert not (tmp_path / fn).exists() and not (tmp_path / thumb).exists()
    media.delete_files(fn, thumb, directory=tmp_path)   # idempotent


# ── integration: upload / render / export ────────────────────────────────────
@pytest_asyncio.fixture
async def client(conn, tmp_path, monkeypatch):
    monkeypatch.setenv("BILLETS_MEDIA_DIR", str(tmp_path / "media"))
    await repo.create_author(conn, "gk", sec.hash_password(PW), now=NOW,
                             author_id="01AUTHOR0000000000000000AA")
    app = create_app(conn, secret="test-secret-xyz", revisions_dir=str(tmp_path / "revs"))
    app.state.clock = lambda: NOW
    app.state.http_client = httpx.AsyncClient(transport=httpx.MockTransport(
        lambda r: httpx.Response(204)))
    app.state.resolver = lambda host, port: [(0, 0, 0, "", ("93.184.216.34", port))]
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t",
                                 follow_redirects=False) as c:
        yield c, conn, tmp_path


async def _login(c):
    await c.get("/admin/login")
    csrf = c.cookies.get("billets_csrf")
    await c.post("/admin/login", data={"username": "gk", "password": PW, "csrf": csrf})
    return c.cookies.get("billets_csrf")


async def test_upload_attaches_media_and_writes_file(client):
    c, conn, tmp_path = client
    csrf = await _login(c)
    r = await c.post("/admin/billets",
                     data={"body": "avec image", "action": "publish", "csrf": csrf},
                     files={"media_files": ("shot.png", _png(), "image/png")})
    assert r.status_code == 303
    bid = (await repo.list_all(conn))[0]["id"]
    rows = await repo.list_media(conn, bid)
    assert len(rows) == 1 and rows[0]["mime"] == "image/png"
    assert (tmp_path / "media" / rows[0]["filename"]).exists()
    assert (tmp_path / "media" / rows[0]["thumb"]).exists()


async def test_invalid_upload_is_skipped_not_fatal(client):
    c, conn, tmp_path = client
    csrf = await _login(c)
    r = await c.post("/admin/billets",
                     data={"body": "texte seul survit", "action": "publish", "csrf": csrf},
                     files={"media_files": ("bad.png", b"junk-not-image", "image/png")})
    assert r.status_code == 303                       # publish still succeeds
    bid = (await repo.list_all(conn))[0]["id"]
    assert await repo.list_media(conn, bid) == []      # bad file dropped


async def test_public_feed_and_permalink_show_gallery(client):
    c, conn, tmp_path = client
    csrf = await _login(c)
    await c.post("/admin/billets",
                 data={"body": "galerie", "action": "publish", "csrf": csrf},
                 files={"media_files": ("a.png", _png(), "image/png")})
    row = (await repo.list_all(conn))[0]
    feed = await c.get("/")
    assert 'class="gallery"' in feed.text and "/media/" in feed.text
    perm = await c.get(f"/b/{row['slug']}")
    assert "data-lightbox" in perm.text and "og:image" in perm.text


async def test_delete_media_removes_row_and_files(client):
    c, conn, tmp_path = client
    csrf = await _login(c)
    await c.post("/admin/billets",
                 data={"body": "x", "action": "draft", "csrf": csrf},
                 files={"media_files": ("a.png", _png(), "image/png")})
    bid = (await repo.list_all(conn))[0]["id"]
    m = (await repo.list_media(conn, bid))[0]
    fpath = tmp_path / "media" / m["filename"]
    assert fpath.exists()
    r = await c.post(f"/admin/media/{m['id']}/delete", data={"csrf": csrf})
    assert r.status_code == 303
    assert await repo.list_media(conn, bid) == []
    assert not fpath.exists()


async def test_delete_billet_cascades_media_files(client):
    c, conn, tmp_path = client
    csrf = await _login(c)
    await c.post("/admin/billets",
                 data={"body": "x", "action": "draft", "csrf": csrf},
                 files={"media_files": ("a.png", _png(), "image/png")})
    bid = (await repo.list_all(conn))[0]["id"]
    m = (await repo.list_media(conn, bid))[0]
    fpath = tmp_path / "media" / m["filename"]
    await c.post(f"/admin/billets/{bid}/delete", data={"csrf": csrf})
    assert await repo.get_media(conn, m["id"]) is None   # row cascaded
    assert not fpath.exists()                            # file removed


async def test_export_sbxsite_embeds_media_base64(client):
    c, conn, tmp_path = client
    csrf = await _login(c)
    await c.post("/admin/billets",
                 data={"body": "portable", "action": "publish", "csrf": csrf},
                 files={"media_files": ("a.png", _png(), "image/png")})
    r = await c.get("/admin/export.sbxsite")
    assert r.status_code == 200
    assert 'filename="billets.sbxsite"' in r.headers.get("content-disposition", "")
    payload = json.loads(r.text)
    assert payload["format"] == "sbxsite/billets" and payload["version"] == 1
    assert len(payload["billets"]) == 1 and len(payload["media"]) == 1
    assert payload["media"][0]["b64"]                    # image inlined
