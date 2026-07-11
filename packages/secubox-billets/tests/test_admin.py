# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
from pathlib import Path

import httpx
import pytest_asyncio

from api import repo
from api.main import create_app
from api.services import eventlog, revisions
from api.services import security as sec

PW = "s3cret-pass-123"
NOW = "2026-07-11T12:00:00Z"


@pytest_asyncio.fixture
async def admin(conn, tmp_path):
    await repo.create_author(conn, "gk", sec.hash_password(PW), now=NOW,
                             author_id="01AUTHOR0000000000000000AA")
    app = create_app(conn, secret="test-secret-xyz", revisions_dir=str(tmp_path / "revs"))
    app.state.clock = lambda: NOW
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t",
                                 follow_redirects=False) as c:
        yield c, conn, tmp_path


async def _login(c, password=PW, totp=""):
    await c.get("/admin/login")
    csrf = c.cookies.get("billets_csrf")
    return await c.post("/admin/login",
                        data={"username": "gk", "password": password, "totp": totp, "csrf": csrf})


async def test_login_success_and_dashboard(admin):
    c, conn, _ = admin
    r = await _login(c)
    assert r.status_code == 303 and r.headers["location"] == "/admin"
    assert c.cookies.get("billets_session")
    dash = await c.get("/admin")
    assert dash.status_code == 200 and "Nouveau billet" in dash.text


async def test_login_bad_password_logs_failure(admin):
    c, conn, _ = admin
    r = await _login(c, password="wrong")
    assert r.status_code == 303 and "error=bad" in r.headers["location"]
    assert not c.cookies.get("billets_session")
    async with conn.execute("SELECT COUNT(*) FROM event_log WHERE event_type='author.login_failed'") as cur:
        assert (await cur.fetchone())[0] == 1


async def test_csrf_required_on_login(admin):
    c, conn, _ = admin
    await c.get("/admin/login")
    r = await c.post("/admin/login",
                     data={"username": "gk", "password": PW, "csrf": "WRONG"})
    assert r.status_code == 303 and "error=csrf" in r.headers["location"]


async def test_login_rate_limited(admin):
    c, conn, _ = admin
    last = None
    for _ in range(6):
        last = await _login(c, password="wrong")
    assert "error=ratelimit" in last.headers["location"]


async def test_admin_requires_auth(admin):
    c, conn, _ = admin
    assert (await c.get("/admin")).headers["location"] == "/admin/login"
    r = await c.post("/admin/billets", data={"body": "x", "action": "publish", "csrf": "z"})
    assert r.status_code == 303 and r.headers["location"] == "/admin/login"


async def test_create_publish_logs_and_revisions(admin):
    c, conn, tmp_path = admin
    await _login(c)
    csrf = c.cookies.get("billets_csrf")
    r = await c.post("/admin/billets",
                     data={"body": "**Premier** billet publié", "url": "https://secubox.in",
                           "url_kind": "ref", "action": "publish", "csrf": csrf})
    assert r.status_code == 303 and r.headers["location"] == "/admin"
    rows = await repo.list_all(conn, status="published")
    assert len(rows) == 1 and rows[0]["ref_url"] == "https://secubox.in"
    # event log + chain intact
    async with conn.execute("SELECT COUNT(*) FROM event_log WHERE event_type='billet.published'") as cur:
        assert (await cur.fetchone())[0] == 1
    assert await eventlog.verify_chain(conn) is True
    # gitea revision written
    hist = revisions.list_revisions(tmp_path / "revs", rows[0]["id"])
    assert len(hist) == 1


async def test_edit_adds_second_revision(admin):
    c, conn, tmp_path = admin
    await _login(c)
    csrf = c.cookies.get("billets_csrf")
    await c.post("/admin/billets",
                 data={"body": "brouillon initial", "action": "draft", "csrf": csrf})
    bid = (await repo.list_all(conn))[0]["id"]
    r = await c.post(f"/admin/billets/{bid}",
                     data={"body": "corps modifié et publié", "action": "publish", "csrf": csrf})
    assert r.status_code == 303
    row = await repo.get_by_id(conn, bid)
    assert row["status"] == "published" and row["published_at"] is not None
    hist = revisions.list_revisions(tmp_path / "revs", bid)
    assert len(hist) == 2  # create + edit


async def test_delete_removes_and_logs(admin):
    c, conn, _ = admin
    await _login(c)
    csrf = c.cookies.get("billets_csrf")
    await c.post("/admin/billets", data={"body": "à supprimer", "action": "draft", "csrf": csrf})
    bid = (await repo.list_all(conn))[0]["id"]
    r = await c.post(f"/admin/billets/{bid}/delete", data={"csrf": csrf})
    assert r.status_code == 303
    assert await repo.get_by_id(conn, bid) is None
    async with conn.execute("SELECT COUNT(*) FROM event_log WHERE event_type='billet.deleted'") as cur:
        assert (await cur.fetchone())[0] == 1


async def test_totp_enforced_when_enrolled(admin, conn):
    c, conn2, _ = admin
    import pyotp
    secret = pyotp.random_base32()
    await conn2.execute("UPDATE author SET totp_secret=? WHERE username='gk'", (secret,))
    await conn2.commit()
    # right password, missing TOTP -> fail
    r = await _login(c)
    assert "error=bad" in r.headers["location"]
    # right password + right code -> success
    r2 = await _login(c, totp=pyotp.TOTP(secret).now())
    assert r2.headers["location"] == "/admin"
