# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Adaptateurs ytsas et BBS (#3574) : la médiathèque reste aux membres, rien d'interne ne sort, rubriques publiques."""
import asyncio

import httpx

from api import bus as busmod
from api.bus import Bus

YTSAS = [
    {"id": "111", "title": "Conférence WAF", "url": "https://x.com/secret/status/1", "path": "/data/ytsas/111/v.mp4",
     "complete": "1", "added_at": "200"},
    {"id": "222", "title": "En cours", "url": "https://y", "path": "/data/ytsas/222", "complete": "0", "added_at": "300"},
]
MENU = {"categories": [{"slug": "atelier", "title": "Atelier", "threads": 19}, {"slug": "", "title": "vide"}]}


def _transport(req: httpx.Request) -> httpx.Response:
    if req.url.path == "/api/v1/ytsas/list":
        return httpx.Response(200, json=YTSAS)
    if req.url.path == "/api/v1/bbs/menu":
        return httpx.Response(200, json=MENU)
    return httpx.Response(404)


def _bus(monkeypatch):
    vrai = httpx.AsyncClient
    monkeypatch.setattr(busmod.httpx, "AsyncClient", lambda *a, **k: vrai(transport=httpx.MockTransport(_transport)))
    monkeypatch.setattr(busmod.httpx, "AsyncHTTPTransport", lambda *a, **k: None)
    monkeypatch.setattr(busmod, "_hote", lambda s: f"{s}.exemple.in")
    b = Bus({"bus_cache_s": 60})

    async def vide():
        return []
    for nom in ("_metanews", "_billets", "_peertube", "_registry"):
        monkeypatch.setattr(b, nom, vide)
    return b


def test_ytsas_reserve_aux_membres_sans_fuite(monkeypatch):
    b = _bus(monkeypatch)
    invite = asyncio.run(b.objets("guest", force=True))
    membre = asyncio.run(b.objets("member"))
    assert not [o for o in invite if o["service"] == "ytsas"]
    yt = [o for o in membre if o["service"] == "ytsas"]
    assert [o["title"] for o in yt] == ["Conférence WAF"]            # incomplet écarté
    texte = repr(yt)
    assert "/data/ytsas" not in texte and "x.com" not in texte
    assert yt[0]["url"] == "https://admin.exemple.in/ytsas/"


def test_rubriques_bbs_publiques(monkeypatch):
    b = _bus(monkeypatch)
    rub = [o for o in asyncio.run(b.objets("guest", force=True)) if o["service"] == "bbs"]
    assert [o["title"] for o in rub] == ["Atelier"]
    assert rub[0]["url"] == "https://bbs.exemple.in/c/atelier" and "19 fils" in rub[0]["summary"]
