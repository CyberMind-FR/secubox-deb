# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Bus ZIA (#3574) : une source en échec ne vide jamais son dernier relevé réussi (double tampon, #3011)."""
import asyncio

from api.bus import Bus

SUJET = {"id": "metanews:topic:1", "type": "news.topic", "service": "metanews", "title": "Sujet",
         "visibility": "guest", "tags": []}


def test_metanews_en_echec_garde_le_dernier_releve(monkeypatch):
    bus = Bus({"bus_cache_s": 0})
    reponses = [[SUJET], []]

    async def metanews():
        return reponses.pop(0)

    async def vide():
        return []
    monkeypatch.setattr(bus, "_metanews", metanews)
    for nom in ("_billets", "_peertube", "_registry", "_ytsas", "_bbs"):
        monkeypatch.setattr(bus, nom, vide)
    premier = asyncio.run(bus.objets(force=True))
    second = asyncio.run(bus.objets(force=True))      # metanews a dépassé son délai : []
    assert SUJET["id"] in [o["id"] for o in premier]
    assert SUJET["id"] in [o["id"] for o in second]


def test_cache_expire_repond_sans_attendre_la_source_lente(monkeypatch):
    import time
    bus = Bus({"bus_cache_s": 0})

    async def lent():
        await asyncio.sleep(5)
        return [SUJET]

    async def vide():
        return []

    async def scenario():
        for nom in ("_metanews", "_billets", "_peertube", "_registry", "_ytsas", "_bbs"):
            monkeypatch.setattr(bus, nom, vide)
        await bus.objets(force=True)                 # premier relevé (attendu)
        monkeypatch.setattr(bus, "_metanews", lent)
        bus._ts -= 10                                # cache expiré
        t0 = time.monotonic()
        await bus.objets()
        duree = time.monotonic() - t0
        bus._releve.cancel()
        return duree
    assert asyncio.run(scenario()) < 0.5
