# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Portable single-file .html archive: JWT-gated, fully self-contained (CSS
inlined, media + embed vignette as data: URIs), the embed rendered as its
snapshot image LINKING to the original (no live iframe → opens offline)."""
import io

import httpx
import pytest_asyncio
from PIL import Image

from api import repo
from api.main import create_app
from api.services import security as sec

PW = "s3cret-pass-123"
NOW = "2026-07-11T12:00:00Z"


def _png() -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (48, 48), (200, 78, 36)).save(buf, format="PNG")
    return buf.getvalue()


@pytest_asyncio.fixture
async def client(conn, tmp_path, monkeypatch):
    monkeypatch.setenv("BILLETS_MEDIA_DIR", str(tmp_path / "media"))
    monkeypatch.setenv("BILLETS_SNAPSHOT_BROWSER", "0")
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


async def _seed_billet(c, conn):
    csrf = await _login(c)
    await c.post("/admin/billets",
                 data={"body": "Communiqué archivable", "style": "communique",
                       "action": "publish", "csrf": csrf},
                 files={"media_files": ("shot.png", _png(), "image/png")})
    row = (await repo.list_all(conn))[0]
    # reuse the stored media file as the (pretend) embed snapshot vignette
    media_row = (await repo.list_media(conn, row["id"]))[0]
    await conn.execute("UPDATE billet SET embed_url=? WHERE id=?",
                       ("https://youtube.com/watch?v=z", row["id"]))
    await conn.commit()
    await repo.set_embed_snapshot(conn, row["id"], media_row["filename"])
    return row


async def test_archive_requires_auth(client):
    c, conn, _ = client
    row = await _seed_billet(c, conn)
    # drop the session cookie → must be redirected to login
    c.cookies.delete("billets_session")
    r = await c.get(f"/admin/billets/{row['id']}/archive.html")
    assert r.status_code == 303 and r.headers["location"] == "/admin/login"


async def test_archive_is_self_contained_html(client):
    c, conn, _ = client
    row = await _seed_billet(c, conn)
    r = await c.get(f"/admin/billets/{row['id']}/archive.html")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/html")
    assert f'filename="billet-{row["slug"]}.html"' in r.headers.get("content-disposition", "")
    body = r.text
    assert body.lstrip().startswith("<!DOCTYPE html")
    assert "<style>" in body                      # CSS inlined, no external sheet
    assert "fonts.googleapis.com" not in body     # offline: system fonts only
    assert "data:image/png;base64," in body       # media + vignette inlined
    # embed = snapshot image LINKING to the original; never a live iframe
    assert "<iframe" not in body
    assert 'href="https://youtube.com/watch?v=z"' in body
    assert "TRANSMISSION" in body                  # communiqué frame label


async def test_archive_missing_billet_redirects(client):
    c, conn, _ = client
    await _login(c)
    r = await c.get("/admin/billets/01DOESNOTEXIST00000000000A/archive.html")
    assert r.status_code == 303 and r.headers["location"] == "/admin"
