# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Per-billet communiqué style: stored on create, permalink picks the poster
template (with the vignette when a snapshot exists); default billets unchanged."""
import httpx
import pytest_asyncio

from api import repo
from api.main import create_app
from api.services import security as sec

PW = "s3cret-pass-123"
NOW = "2026-07-11T12:00:00Z"


@pytest_asyncio.fixture
async def client(conn, tmp_path, monkeypatch):
    monkeypatch.setenv("BILLETS_MEDIA_DIR", str(tmp_path / "media"))
    monkeypatch.setenv("BILLETS_SNAPSHOT_BROWSER", "0")   # no browser launch in tests
    await repo.create_author(conn, "gk", sec.hash_password(PW), now=NOW,
                             author_id="01AUTHOR0000000000000000AA")
    app = create_app(conn, secret="test-secret-xyz", revisions_dir=str(tmp_path / "revs"))
    app.state.clock = lambda: NOW
    # 204 → fetch_og_image finds no og:image → capture yields no snapshot (fast).
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


async def test_create_communique_stores_style(client):
    c, conn, _ = client
    csrf = await _login(c)
    r = await c.post("/admin/billets",
                     data={"body": "Communiqué de presse", "style": "communique",
                           "action": "publish", "csrf": csrf})
    assert r.status_code == 303
    row = (await repo.list_all(conn))[0]
    assert row["style"] == "communique"


async def test_permalink_renders_communique_template(client):
    c, conn, _ = client
    csrf = await _login(c)
    await c.post("/admin/billets",
                 data={"body": "La transmission est en ligne", "style": "communique",
                       "action": "publish", "csrf": csrf})
    row = (await repo.list_all(conn))[0]
    # attach a resolved embed + a (pretend) snapshot vignette so the poster frame
    # shows the click-to-load image
    await conn.execute(
        "UPDATE billet SET embed_html=?, embed_url=?, embed_snapshot=? WHERE id=?",
        ('<iframe src="https://www.youtube.com/embed/z" sandbox="allow-scripts"></iframe>',
         "https://youtube.com/watch?v=z", "01SNAP0000000000000000000A.png", row["id"]))
    await conn.commit()
    r = await c.get(f"/b/{row['slug']}")
    assert r.status_code == 200
    assert "TRANSMISSION" in r.text                        # poster frame legend
    assert "Communiqué officiel" in r.text                 # stamp
    assert "billets-communique.css" in r.text              # poster stylesheet
    assert "01SNAP0000000000000000000A.png" in r.text      # vignette img
    assert 'class="comm-vignette"' in r.text
    assert "data-load-embed" in r.text                     # click-to-load hook
    # communiqué CSP relaxes fonts only (no script widening)
    csp = r.headers["Content-Security-Policy"]
    assert "fonts.googleapis.com" in csp and "fonts.gstatic.com" in csp


async def test_communique_without_snapshot_renders_live_embed(client):
    c, conn, _ = client
    csrf = await _login(c)
    await c.post("/admin/billets",
                 data={"body": "direct", "style": "communique",
                       "action": "publish", "csrf": csrf})
    row = (await repo.list_all(conn))[0]
    await conn.execute(
        "UPDATE billet SET embed_html=?, embed_url=? WHERE id=?",
        ('<iframe src="https://www.youtube.com/embed/z" sandbox="allow-scripts"></iframe>',
         "https://youtube.com/watch?v=z", row["id"]))
    await conn.commit()
    r = await c.get(f"/b/{row['slug']}")
    assert r.status_code == 200
    assert "youtube.com/embed/z" in r.text                 # live iframe rendered
    assert "comm-vignette" not in r.text                   # no vignette (none stored)


async def test_default_billet_renders_default_template(client):
    c, conn, _ = client
    csrf = await _login(c)
    await c.post("/admin/billets",
                 data={"body": "billet ordinaire", "action": "publish", "csrf": csrf})
    row = (await repo.list_all(conn))[0]
    assert row["style"] == "default"
    r = await c.get(f"/b/{row['slug']}")
    assert r.status_code == 200
    assert "Communiqué officiel" not in r.text
    assert "billets-communique.css" not in r.text
    assert "permalien" in r.text                           # normal billet chrome
