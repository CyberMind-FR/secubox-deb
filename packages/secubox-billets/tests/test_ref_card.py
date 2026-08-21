# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#1104 — une URL de RÉFÉRENCE (source) qui n'est pas un média distant reçoit
automatiquement une vignette d'aperçu (link-card OG), cachée dans embed_html et
rendue par la vitrine. SSRF-gardée ; ne casse jamais une publication."""
import httpx
import pytest
import pytest_asyncio

from api import repo
from api.main import create_app
from api.services import security as sec

PW = "s3cret-pass-123"
NOW = "2026-07-11T12:00:00Z"

_OG_PAGE = (
    b'<html><head>'
    b'<meta property="og:title" content="Titre source">'
    b'<meta property="og:description" content="Une description de la page">'
    b'<meta property="og:image" content="https://cdn.example/i.jpg">'
    b'</head><body>x</body></html>'
)


def _make_client(conn, tmp_path, handler, resolver):
    app = create_app(conn, secret="test-secret-xyz", revisions_dir=str(tmp_path / "revs"))
    app.state.clock = lambda: NOW
    app.state.http_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    app.state.resolver = resolver
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://t", follow_redirects=False)


async def _login(c):
    await c.get("/admin/login")
    csrf = c.cookies.get("billets_csrf")
    await c.post("/admin/login", data={"username": "gk", "password": PW, "csrf": csrf})
    return c.cookies.get("billets_csrf")


@pytest_asyncio.fixture
async def setup(conn, tmp_path, monkeypatch):
    monkeypatch.setenv("BILLETS_MEDIA_DIR", str(tmp_path / "media"))
    await repo.create_author(conn, "gk", sec.hash_password(PW), now=NOW,
                             author_id="01AUTHOR0000000000000000AA")
    return conn, tmp_path


@pytest.mark.asyncio
async def test_ref_url_gets_preview_card(setup):
    conn, tmp_path = setup
    handler = lambda r: httpx.Response(200, headers={"content-type": "text/html"}, content=_OG_PAGE)
    resolver = lambda host, port: [(0, 0, 0, "", ("93.184.216.34", port))]
    async with _make_client(conn, tmp_path, handler, resolver) as c:
        csrf = await _login(c)
        r = await c.post("/admin/billets", data={
            "body": "voir la source", "url": "https://blog.example/p",
            "url_kind": "ref", "action": "publish", "csrf": csrf})
        assert r.status_code == 303
    bid = (await repo.list_all(conn))[0]["id"]
    row = await repo.get_by_id(conn, bid)
    assert row["embed_html"] and "link-card" in row["embed_html"]
    assert "Titre source" in row["embed_html"]
    assert "cdn.example/i.jpg" in row["embed_html"]
    assert "<iframe" not in row["embed_html"]        # jamais du HTML distant


@pytest.mark.asyncio
async def test_private_ip_ref_is_ssrf_blocked_no_card(setup):
    conn, tmp_path = setup
    handler = lambda r: httpx.Response(200, headers={"content-type": "text/html"}, content=_OG_PAGE)
    # l'hôte résout vers une IP privée → SSRF bloque → aucune vignette, aucun crash.
    resolver = lambda host, port: [(0, 0, 0, "", ("10.0.0.5", port))]
    async with _make_client(conn, tmp_path, handler, resolver) as c:
        csrf = await _login(c)
        r = await c.post("/admin/billets", data={
            "body": "source interne", "url": "https://intra.example/x",
            "url_kind": "ref", "action": "publish", "csrf": csrf})
        assert r.status_code == 303
    row = await repo.get_by_id(conn, (await repo.list_all(conn))[0]["id"])
    assert not row["embed_html"]                     # rien stocké, publication OK
