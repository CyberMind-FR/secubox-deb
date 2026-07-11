# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
import xml.etree.ElementTree as ET

import httpx
import pytest_asyncio

from api import repo
from api.main import create_app
from api.models import BilletIn
from api.services import feeds

NOW = "2026-07-11T12:00:00Z"


def test_billet_title_from_first_line():
    assert feeds.billet_title("**Bonjour** le monde\nsuite") == "Bonjour le monde"
    assert feeds.billet_title("") == "billet"
    assert feeds.billet_title("x" * 100).endswith("…")


def test_excerpt_plain_and_truncated():
    assert feeds.excerpt("**gras** _et_ `code`") == "gras et code"
    assert feeds.excerpt("y" * 300).endswith("…")


def test_build_atom_is_wellformed():
    xml = feeds.build_atom(site_title="billets", base_url="https://b.example",
                           self_url="https://b.example/feed.xml", updated=NOW, entries=[
        {"title": "Bonjour <&>", "url": "https://b.example/b/x", "id": "https://b.example/b/x",
         "updated": NOW, "published": NOW, "content_html": "<p>salut & co</p>"}])
    root = ET.fromstring(xml)  # raises if malformed
    ns = "{http://www.w3.org/2005/Atom}"
    assert root.tag == f"{ns}feed"
    assert root.find(f"{ns}entry/{ns}title").text == "Bonjour <&>"


def test_build_jsonfeed_structure():
    jf = feeds.build_jsonfeed(site_title="billets", base_url="https://b.example",
                              feed_url="https://b.example/feed.json", items=[
        {"id": "i1", "url": "u1", "title": "t", "content_html": "<p>x</p>", "date_published": NOW}])
    assert jf["version"] == "https://jsonfeed.org/version/1.1"
    assert jf["items"][0]["content_html"] == "<p>x</p>"


@pytest_asyncio.fixture
async def client(conn, tmp_path):
    bid = await repo.create_billet(conn, BilletIn(body="**Titre** du billet\ncorps", publish=True),
                                   now=NOW, ulid="01FEED000000000000000000AA")
    row = await repo.get_by_id(conn, bid)
    app = create_app(conn, secret="s", revisions_dir=str(tmp_path / "r"))
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t",
                                 follow_redirects=False) as c:
        yield c, row["slug"]


async def test_feed_atom_route(client):
    c, slug = client
    r = await c.get("/feed.xml")
    assert r.status_code == 200 and "application/atom+xml" in r.headers["content-type"]
    root = ET.fromstring(r.text)
    assert root.find("{http://www.w3.org/2005/Atom}entry") is not None
    assert f"/b/{slug}" in r.text


async def test_feed_json_route(client):
    c, slug = client
    r = await c.get("/feed.json")
    body = r.json()
    assert body["version"].endswith("/1.1")
    assert body["items"][0]["title"] == "Titre du billet"
    assert body["items"][0]["url"].endswith(f"/b/{slug}")


async def test_oembed_out(client):
    c, slug = client
    r = await c.get(f"/oembed?url=http://t/b/{slug}&format=json")
    j = r.json()
    assert j["type"] == "rich" and j["provider_name"] == "billets"
    assert "blockquote" in j["html"] and "<iframe" not in j["html"]


async def test_oembed_rejects_foreign_url(client):
    c, slug = client
    assert (await c.get("/oembed?url=http://t/not/a/billet")).status_code == 404
    assert (await c.get("/oembed?url=http://t/b/nonexistent")).status_code == 404


async def test_og_and_oembed_discovery_on_page(client):
    c, slug = client
    r = await c.get(f"/b/{slug}")
    assert '<meta property="og:title" content="Titre du billet">' in r.text
    assert 'name="twitter:card"' in r.text
    assert 'type="application/json+oembed"' in r.text
    assert "↗ Republier" in r.text and "bsky.app/intent" in r.text


async def test_stats_json_cors(client):
    c, slug = client
    r = await c.get("/stats.json")
    assert r.status_code == 200
    assert r.headers.get("access-control-allow-origin") == "*"
    d = r.json()
    assert d["billets_published"] >= 1
    assert "reactions_by" in d and isinstance(d["latest"], list)
    assert d["latest"][0]["url"].endswith(f"/b/{slug}")
