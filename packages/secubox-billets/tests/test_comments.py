# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
import time

import httpx
import pytest_asyncio

from api import repo
from api.main import create_app
from api.models import BilletIn
from api.services import antispam

SECRET = "test-secret-xyz"
NOW = "2026-07-11T12:00:00Z"


@pytest_asyncio.fixture
async def pub(conn, tmp_path):
    bid = await repo.create_billet(conn, BilletIn(body="Bonjour", publish=True),
                                   now=NOW, ulid="01PUB0000000000000000000AA")
    row = await repo.get_by_id(conn, bid)
    app = create_app(conn, secret=SECRET, revisions_dir=str(tmp_path / "r"))
    from api.routes import public as pub_mod
    pub_mod._comment_limiter._hits.clear()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t",
                                 follow_redirects=False) as c:
        yield c, conn, bid, row["slug"]


async def _prep(c, slug):
    await c.get(f"/b/{slug}")
    pcsrf = c.cookies.get("billets_pcsrf")
    old_token = antispam.issue_form_token(SECRET, now_epoch=int(time.time()) - 10)
    return pcsrf, old_token


async def test_comment_goes_pending(pub):
    c, conn, bid, slug = pub
    pcsrf, tok = await _prep(c, slug)
    r = await c.post(f"/b/{slug}/comment",
                     data={"author_name": "Alice", "body": "joli billet", "csrf": pcsrf,
                           "ts_token": tok, "website": ""})
    assert r.status_code == 303 and "c=pending" in r.headers["location"]
    pend = await repo.list_pending_comments(conn)
    assert len(pend) == 1 and pend[0]["author_name"] == "Alice"


async def test_honeypot_drops_silently(pub):
    c, conn, bid, slug = pub
    pcsrf, tok = await _prep(c, slug)
    r = await c.post(f"/b/{slug}/comment",
                     data={"author_name": "Bot", "body": "spam", "csrf": pcsrf,
                           "ts_token": tok, "website": "http://spam"})
    assert r.status_code == 303 and "c=ok" in r.headers["location"]
    assert await repo.list_pending_comments(conn) == []  # nothing stored


async def test_too_fast_rejected(pub):
    c, conn, bid, slug = pub
    pcsrf, _ = await _prep(c, slug)
    fresh = antispam.issue_form_token(SECRET, now_epoch=int(time.time()))  # 0s delay
    r = await c.post(f"/b/{slug}/comment",
                     data={"author_name": "Rush", "body": "trop vite", "csrf": pcsrf,
                           "ts_token": fresh, "website": ""})
    assert "c=slow" in r.headers["location"]
    assert await repo.list_pending_comments(conn) == []


async def test_csrf_required(pub):
    c, conn, bid, slug = pub
    _, tok = await _prep(c, slug)
    r = await c.post(f"/b/{slug}/comment",
                     data={"author_name": "X", "body": "hello", "csrf": "WRONG",
                           "ts_token": tok, "website": ""})
    assert r.status_code == 303
    assert await repo.list_pending_comments(conn) == []


async def test_rate_limited_after_5(pub):
    c, conn, bid, slug = pub
    pcsrf, _ = await _prep(c, slug)
    last = None
    for i in range(6):
        tok = antispam.issue_form_token(SECRET, now_epoch=int(time.time()) - 10)
        last = await c.post(f"/b/{slug}/comment",
                            data={"author_name": f"U{i}", "body": "coucou", "csrf": pcsrf,
                                  "ts_token": tok, "website": ""})
    assert "c=rate" in last.headers["location"]


async def test_auto_approve_returning_visitor(pub):
    c, conn, bid, slug = pub
    pcsrf, tok = await _prep(c, slug)
    # first comment from this client -> pending; approve it (captures the real ip_hash)
    await c.post(f"/b/{slug}/comment",
                 data={"author_name": "Reg", "body": "ancien", "csrf": pcsrf,
                       "ts_token": tok, "website": ""})
    cid = (await repo.list_pending_comments(conn))[0]["id"]
    await repo.moderate_comment(conn, cid, "approved")
    # a second comment, same name + same client ip -> auto-approved
    tok2 = antispam.issue_form_token(SECRET, now_epoch=int(time.time()) - 10)
    r = await c.post(f"/b/{slug}/comment",
                     data={"author_name": "Reg", "body": "nouveau", "csrf": pcsrf,
                           "ts_token": tok2, "website": ""})
    assert "c=ok" in r.headers["location"]  # auto-approved
    approved = await repo.list_approved_comments(conn, bid)
    assert any(a["body"] == "nouveau" for a in approved)


async def test_approved_comment_renders_on_page(pub):
    c, conn, bid, slug = pub
    await repo.add_comment(conn, bid, author_name="Vera", email_hash=None,
                           body="salut http://exemple.fr voir", ip_hash="x", honeypot=False,
                           status="approved", now=NOW)
    page = await c.get(f"/b/{slug}")
    assert "Vera" in page.text
    assert 'rel="nofollow ugc noopener noreferrer"' in page.text  # autolinked
