# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#1268 — Mur infini : fragment /feed/suite + pager instrumenté.

Vérifie que le fil se déroule par pages keyset et que le fragment rend
EXACTEMENT les mêmes cartes que la page (partiel partagé)."""
import httpx
import pytest_asyncio

from api import repo
from api.main import create_app
from api.models import BilletIn

NOW = "2026-07-11T12:00:00Z"
N = 25  # > PAGE_SIZE (20) → au moins deux pages


@pytest_asyncio.fixture
async def client(conn, tmp_path):
    for i in range(N):
        await repo.create_billet(
            conn, BilletIn(body=f"**Billet {i}**\ncorps {i}", publish=True),
            now=NOW, ulid="01FEED" + "0" * 18 + f"{i:02d}")
    app = create_app(conn, secret="s", revisions_dir=str(tmp_path / "r"))
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t",
                                 follow_redirects=False) as c:
        yield c


async def test_page_has_wall_hooks(client):
    r = await client.get("/")
    assert r.status_code == 200
    # Les ancres du mur infini sont présentes pour le client JS…
    assert 'id="fil-billets"' in r.text
    assert 'id="fil-pager"' in r.text and "data-cursor=" in r.text
    # …et le lien pager reste un fallback no-JS.
    assert 'rel="next"' in r.text
    assert r.text.count("<article") == 20  # PAGE_SIZE


async def test_suite_fragment_json_and_end(client, conn):
    # Curseur après la 1re page, obtenu comme le fait le handler.
    rows, cur = await repo.list_published(conn, limit=20)
    assert cur  # il reste des billets
    r = await client.get("/feed/suite", params={"cursor": cur})
    assert r.status_code == 200
    body = r.json()
    assert body["html"].count("<article") == N - 20  # les 5 restants
    assert body["next_cursor"] is None  # fin du fil → le client retire le pager


async def test_suite_same_card_markup_as_page(client):
    # Sans curseur = première page : le fragment doit rendre les mêmes cartes
    # « dossier » que la page.
    r = await client.get("/feed/suite")
    assert r.status_code == 200
    body = r.json()
    assert 'class="dossier h-entry billet"' in body["html"]
    assert body["html"].count("<article") == 20
    assert body["next_cursor"]  # il reste des billets → curseur non nul
