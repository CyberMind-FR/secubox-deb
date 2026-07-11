# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
import json

import httpx

from api.services import linkcard
from api.services.oembed import resolve_oembed


def _resolver(host_ip=None):
    def r(host, port):
        return [(0, 0, 0, "", ((host_ip or {}).get(host, "93.184.216.34"), port))]
    return r


def _client(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def test_youtube_oembed_sanitized():
    def handler(request):
        assert request.url.host == "www.youtube.com"
        return httpx.Response(200, headers={"content-type": "application/json"},
            content=json.dumps({"provider_name": "YouTube",
                "html": '<iframe src="https://www.youtube.com/embed/xyz" onload="x()"></iframe>'}).encode())
    client = _client(handler)
    emb = await resolve_oembed("https://youtube.com/watch?v=xyz", client=client, resolver=_resolver())
    assert emb and emb["provider"] == "youtube" and emb["kind"] == "oembed"
    assert 'sandbox="' in emb["html"] and "onload" not in emb["html"]
    await client.aclose()


async def test_unknown_host_without_discovery_returns_none():
    def handler(request):
        return httpx.Response(200, headers={"content-type": "text/html"}, content=b"<html>no oembed</html>")
    client = _client(handler)
    emb = await resolve_oembed("https://unknown.example/post/1", client=client, resolver=_resolver())
    assert emb is None
    await client.aclose()


async def test_discovery_same_origin():
    page = ('<html><head><link rel="alternate" type="application/json+oembed" '
            'href="https://mast.example/oembed?url=x"></head></html>')
    def handler(request):
        if request.url.path.startswith("/oembed"):
            return httpx.Response(200, headers={"content-type": "application/json"},
                content=json.dumps({"html": '<iframe src="https://mast.example/embed/1"></iframe>'}).encode())
        return httpx.Response(200, headers={"content-type": "text/html"}, content=page.encode())
    client = _client(handler)
    emb = await resolve_oembed("https://mast.example/@user/1", client=client, resolver=_resolver())
    assert emb and emb["kind"] == "oembed" and "mast.example/embed/1" in emb["html"]
    assert "sandbox=" in emb["html"]
    await client.aclose()


async def test_discovery_cross_origin_rejected():
    page = ('<link rel="alternate" type="application/json+oembed" '
            'href="https://evil.example/oembed?url=x">')
    def handler(request):
        return httpx.Response(200, headers={"content-type": "text/html"}, content=page.encode())
    client = _client(handler)
    emb = await resolve_oembed("https://victim.example/post", client=client, resolver=_resolver())
    assert emb is None  # oembed endpoint on a different host is refused
    await client.aclose()


async def test_linkcard_from_opengraph():
    html = ('<html><head>'
            '<meta property="og:title" content="Un &lt;titre&gt;">'
            '<meta property="og:description" content="desc">'
            '<meta property="og:image" content="https://cdn.example/i.jpg">'
            '</head></html>')
    def handler(request):
        return httpx.Response(200, headers={"content-type": "text/html"}, content=html.encode())
    client = _client(handler)
    card = await linkcard.fetch_card("https://blog.example/p", client=client, resolver=_resolver())
    assert card and card["kind"] == "linkcard"
    assert "link-card" in card["html"] and "<iframe" not in card["html"]
    assert "cdn.example/i.jpg" in card["html"]
    await client.aclose()


async def test_resolve_embed_falls_back_to_card():
    html = '<html><head><meta property="og:title" content="Titre"></head></html>'
    def handler(request):
        return httpx.Response(200, headers={"content-type": "text/html"}, content=html.encode())
    client = _client(handler)
    res = await linkcard.resolve_embed("https://plain.example/x", client=client, resolver=_resolver())
    assert res["kind"] == "linkcard"
    await client.aclose()


async def test_resolve_embed_ssrf_returns_none_kind():
    def handler(request):
        return httpx.Response(200, content=b"x")
    client = _client(handler)
    # resolves to a private IP -> ssrf blocks -> pipeline returns kind none, never raises
    res = await linkcard.resolve_embed(
        "https://intra.example/x", client=client, resolver=_resolver({"intra.example": "10.0.0.1"}))
    assert res["kind"] == "none"
    await client.aclose()
