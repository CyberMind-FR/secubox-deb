# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Podcasts (#3574) : lus avec le jeton du DEMANDEUR, jamais sans, jamais gardés dans le cache partagé."""
import asyncio

import httpx

from api import bus as busmod
from api.bus import Bus, JETON_DEMANDEUR

LIB = {"episodes": [{"id": 7, "title": "Épisode sur le chiffrement", "feed": "Les Causeries", "pubdate": 2,
                     "media": "/api/v1/podcaster/media/7"}]}
VUS = []


def _transport(req: httpx.Request) -> httpx.Response:
    VUS.append(req.headers.get("authorization"))
    return httpx.Response(200, json=LIB) if req.url.path == "/public/library" else httpx.Response(404)


def _bus(monkeypatch):
    VUS.clear()
    vrai = httpx.AsyncClient
    monkeypatch.setattr(busmod.httpx, "AsyncClient", lambda *a, **k: vrai(transport=httpx.MockTransport(_transport)))
    monkeypatch.setattr(busmod.httpx, "AsyncHTTPTransport", lambda *a, **k: None)
    monkeypatch.setattr(busmod, "_hote", lambda s: f"{s}.exemple.in")
    b = Bus({"bus_cache_s": 60})

    async def vide():
        return []
    for nom in ("_metanews", "_billets", "_peertube", "_registry", "_ytsas", "_bbs"):
        monkeypatch.setattr(b, nom, vide)
    return b


def _cherche(b, jeton, q="les podcasts", type_="media.audio"):
    async def run():
        pose = JETON_DEMANDEUR.set(jeton)
        try:
            return await b.search(q, type_=type_, role="registered")
        finally:
            JETON_DEMANDEUR.reset(pose)
    return asyncio.run(run())


def test_avec_session_les_episodes_arrivent_avec_son_jeton(monkeypatch):
    b = _bus(monkeypatch)
    res = _cherche(b, "jeton-de-lea")
    assert [o["title"] for o in res] == ["Épisode sur le chiffrement"]
    assert res[0]["url"] == "https://admin.exemple.in/api/v1/podcaster/media/7"
    assert VUS == ["Bearer jeton-de-lea"]


def test_sans_session_rien_n_est_demande(monkeypatch):
    b = _bus(monkeypatch)
    assert _cherche(b, "") == [] and VUS == []


def test_jamais_dans_le_cache_partage(monkeypatch):
    b = _bus(monkeypatch)
    _cherche(b, "jeton-de-lea")
    assert not [o for o in asyncio.run(b.objets("admin")) if o["service"] == "podcaster"]
