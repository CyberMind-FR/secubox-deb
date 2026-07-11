# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
import httpx
import pytest_asyncio

from api import repo
from api.main import create_app
from api.models import BilletIn

NOW = "2026-07-11T12:00:00Z"


@pytest_asyncio.fixture
async def pub(conn, tmp_path):
    bid = await repo.create_billet(conn, BilletIn(body="Bonjour", publish=True),
                                   now=NOW, ulid="01PUB0000000000000000000AA")
    row = await repo.get_by_id(conn, bid)
    app = create_app(conn, secret="test-secret-xyz", revisions_dir=str(tmp_path / "r"))
    from api.routes import public as pub_mod
    pub_mod._comment_limiter._hits.clear()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t",
                                 follow_redirects=False) as c:
        yield c, conn, bid, row["slug"]


async def _pcsrf(c, slug):
    await c.get(f"/b/{slug}")
    return c.cookies.get("billets_pcsrf")


async def test_react_toggle_on_off(pub):
    c, conn, bid, slug = pub
    pcsrf = await _pcsrf(c, slug)
    r = await c.post(f"/b/{slug}/react", data={"emoji": "🔥", "csrf": pcsrf})
    assert r.status_code == 303
    assert (await repo.reaction_counts(conn, bid)).get("🔥") == 1
    # second toggle removes it
    await c.post(f"/b/{slug}/react", data={"emoji": "🔥", "csrf": pcsrf})
    assert (await repo.reaction_counts(conn, bid)).get("🔥") is None


async def test_react_fragment_response(pub):
    c, conn, bid, slug = pub
    pcsrf = await _pcsrf(c, slug)
    r = await c.post(f"/b/{slug}/react", data={"emoji": "❤️", "csrf": pcsrf},
                     headers={"HX-Request": "1"})
    assert r.status_code == 200
    assert 'id="reactions"' in r.text and "❤️" in r.text


async def test_react_csrf_required(pub):
    c, conn, bid, slug = pub
    await _pcsrf(c, slug)
    r = await c.post(f"/b/{slug}/react", data={"emoji": "🔥", "csrf": "WRONG"})
    assert r.status_code == 303
    assert await repo.reaction_counts(conn, bid) == {}


async def test_react_invalid_emoji_rejected(pub):
    c, conn, bid, slug = pub
    pcsrf = await _pcsrf(c, slug)
    r = await c.post(f"/b/{slug}/react", data={"emoji": "💩", "csrf": pcsrf})
    assert r.status_code == 303
    assert await repo.reaction_counts(conn, bid) == {}


async def test_react_on_missing_billet(pub):
    c, conn, bid, slug = pub
    await _pcsrf(c, slug)
    pcsrf = c.cookies.get("billets_pcsrf")
    r = await c.post("/b/nope/react", data={"emoji": "🔥", "csrf": pcsrf})
    assert r.status_code == 303 and r.headers["location"] == "/"
