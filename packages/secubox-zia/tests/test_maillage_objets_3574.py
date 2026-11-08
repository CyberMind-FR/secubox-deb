# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Recherche dans les box du maillage (#3574) : objets publics des voisines, sans boucle, voisine muette écartée."""
import asyncio

import httpx

from api import bus as busmod
from api.bus import Bus

APPELS = []


def _transport(req: httpx.Request) -> httpx.Response:
    APPELS.append(req.url.host)
    if req.url.host == "10.10.0.5":
        return httpx.Response(200, json={"objets": [
            {"id": "peertube:video:x", "type": "media.video", "service": "peertube", "title": "Visio sur gk3",
             "summary": "démo", "url": "https://peertube.gk3/w/x", "tags": ["vidéo"]}]})
    raise httpx.ConnectError("muette")


def _bus(monkeypatch, pairs):
    APPELS.clear()
    vrai = httpx.AsyncClient
    monkeypatch.setattr(busmod.httpx, "AsyncClient",
                        lambda *a, **k: vrai(transport=httpx.MockTransport(_transport)))
    b = Bus({"bus_cache_s": 60, "pairs_maillage": pairs})

    async def vide():
        return []
    for nom in ("_metanews", "_billets", "_peertube", "_registry", "_ytsas", "_bbs"):
        monkeypatch.setattr(b, nom, vide)
    return b


def test_objets_des_voisines_avec_leur_noeud(monkeypatch):
    b = _bus(monkeypatch, ["https://10.10.0.5", "https://10.10.0.9", "http://10.10.0.8"])
    res = asyncio.run(b.search("visio"))
    assert [o["title"] for o in res] == ["Visio sur gk3"]
    assert res[0]["id"] == "maillage:10.10.0.5:peertube:video:x" and res[0]["summary"].startswith("sur 10.10.0.5")
    assert "10.10.0.8" not in APPELS                       # http refusé : seulement https


def test_voisine_muette_mise_de_cote(monkeypatch):
    b = _bus(monkeypatch, ["https://10.10.0.9"])
    asyncio.run(b.search("visio"))
    asyncio.run(b.search("visio"))
    assert APPELS == ["10.10.0.9"]


def test_objets_ne_relaie_jamais_aux_voisines(monkeypatch):
    b = _bus(monkeypatch, ["https://10.10.0.5"])
    assert asyncio.run(b.search("visio", maillage=False)) == [] and APPELS == []
