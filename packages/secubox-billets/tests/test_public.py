# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
import httpx
import pytest_asyncio

from api import repo
from api.main import create_app
from api.models import BilletIn
from api.seed import seed_billets


@pytest_asyncio.fixture
async def client(conn):
    app = create_app(conn)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        yield c


async def test_feed_empty(client):
    r = await client.get("/")
    assert r.status_code == 200
    assert "Aucun billet" in r.text


async def test_feed_shows_published_hides_drafts(client, conn):
    await seed_billets(conn)
    r = await client.get("/")
    assert r.status_code == 200
    assert "Bienvenue sur" in r.text
    assert "ne doit pas apparaître" not in r.text  # the draft


async def test_security_headers(client):
    r = await client.get("/")
    assert "Content-Security-Policy" in r.headers
    assert "script-src 'self'" in r.headers["Content-Security-Policy"]
    assert r.headers["X-Content-Type-Options"] == "nosniff"


async def test_markdown_rendered_and_script_stripped(client, conn):
    await repo.create_billet(
        conn, BilletIn(body="**gras** et <script>alert(1)</script> vilain"),
        now="2026-07-11T12:00:00Z", ulid="01AAAAAAAAAAAAAAAAAAAAAAAA")
    # publish it
    await conn.execute("UPDATE billet SET status='published', published_at='2026-07-11T12:00:00Z'")
    await conn.commit()
    r = await client.get("/")
    assert "<strong>gras</strong>" in r.text          # markdown rendered
    assert "<script>" not in r.text                    # no LIVE script tag
    assert "<script>alert" not in r.text
    assert "&lt;script&gt;" in r.text                   # raw HTML escaped to inert text


async def test_pagination_cursor(client, conn):
    for i in range(25):
        await repo.create_billet(
            conn, BilletIn(body=f"billet numero {i}", publish=True),
            now=f"2026-07-11T12:{i:02d}:00Z",
            ulid=f"01{i:024d}")
    r1 = await client.get("/")
    assert r1.status_code == 200
    assert 'rel="next"' in r1.text
    import re
    cursor = re.search(r'/\?cursor=([A-Za-z0-9_-]+)', r1.text).group(1)
    r2 = await client.get(f"/?cursor={cursor}")
    assert r2.status_code == 200
    # page 2 has the remaining 5, no further cursor
    assert 'rel="next"' not in r2.text


async def test_permalink_and_404(client, conn):
    ids = await seed_billets(conn)
    row = await repo.get_by_id(conn, ids[0])
    r = await client.get(f"/b/{row['slug']}")
    assert r.status_code == 200
    assert "permalien" in r.text
    assert (await client.get("/b/does-not-exist")).status_code == 404
    # a draft's slug must 404
    draft = await repo.get_by_id(conn, ids[3])
    assert (await client.get(f"/b/{draft['slug']}")).status_code == 404


async def test_permalink_increments_view(client, conn):
    ids = await seed_billets(conn)
    row = await repo.get_by_id(conn, ids[0])
    await client.get(f"/b/{row['slug']}")
    after = await repo.get_by_id(conn, ids[0])
    assert after["view_count"] == 1


async def test_feed_renders_embed_inline(client, conn):
    await repo.create_billet(conn, BilletIn(body="ma video", publish=True),
                             now="2026-07-11T12:30:00Z", ulid="01EMBED00000000000000000AA")
    await conn.execute(
        "UPDATE billet SET embed_html=?, embed_url=? WHERE id='01EMBED00000000000000000AA'",
        ('<iframe src="https://www.youtube.com/embed/z" sandbox="allow-scripts" loading="lazy"></iframe>',
         'https://youtube.com/watch?v=z'))
    await conn.commit()
    r = await client.get("/")
    assert 'class="embed"' in r.text
    assert 'youtube.com/embed/z' in r.text          # real iframe inline in the feed
    csp = r.headers["Content-Security-Policy"]
    assert "frame-src" in csp and "youtube.com" in csp
