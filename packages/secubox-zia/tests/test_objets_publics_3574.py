# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""GET /objets (#3574) : sources SecuBox pour une IA — rôle invité imposé, aucune génération, bornes."""
import asyncio
import os
from pathlib import Path

import secubox_core.config as _conf
_conf._CONF_PATHS[:] = [p for p in _conf._CONF_PATHS if os.access(p, os.R_OK)] or \
    [Path(__file__).resolve().parents[3] / "secubox.conf.example"]

import api.main as main  # noqa: E402
import httpx  # noqa: E402

OBJS = [
    {"id": "metanews:topic:1", "type": "news.topic", "service": "metanews", "title": "Panne réseau à Lyon",
     "summary": "résumé", "url": "https://metanews/#1", "visibility": "guest", "tags": ["réseau"]},
    {"id": "billets:post:a", "type": "post", "service": "billets", "title": "Recette du pain",
     "summary": "levain", "url": "https://billets/b/a", "visibility": "guest", "tags": ["billet"]},
    {"id": "secret:1", "type": "post", "service": "billets", "title": "Pain réservé aux membres",
     "summary": "x", "url": "https://billets/b/s", "visibility": "member", "tags": []},
]


class _Bus:
    def __init__(self):
        self.roles, self.appels = [], []

    async def search(self, q, type_="", role="guest", limit=8, maillage=True):
        self.roles.append(role)
        self.appels.append(("search", q, limit))
        self.maillage = maillage
        return [o for o in OBJS if o["visibility"] == "guest" and q.lower()[:4] in o["title"].lower()][:limit]

    async def recent(self, limit=6, role="guest"):
        self.roles.append(role)
        self.appels.append(("recent", limit))
        return [o for o in OBJS if o["visibility"] == "guest"][:limit]


def _get(chemin, **entetes):
    async def run():
        tr = httpx.ASGITransport(app=main.app)
        async with httpx.AsyncClient(transport=tr, base_url="http://t") as c:
            return await c.get("/api/v1/zia" + chemin, headers=entetes)
    return asyncio.run(run())


def test_recherche_role_invite_sans_moteur(monkeypatch):
    bus = _Bus()
    monkeypatch.setattr(main, "BUS", bus)
    async def interdit(*a, **k):
        raise AssertionError("aucune génération ne doit être appelée")
    monkeypatch.setattr(main.runtime, "respond", interdit)
    r = _get("/objets?q=pain", Authorization="Bearer x")
    assert r.status_code == 200
    ids = [o["id"] for o in r.json()["objets"]]
    assert ids == ["billets:post:a"] and "secret:1" not in ids
    assert set(bus.roles) == {"guest"}
    assert bus.maillage is False          # /objets ne relaie jamais aux voisines : pas de boucle entre box (#3574)
    assert "visibility" not in r.json()["objets"][0]


def test_actualite_rend_le_recent(monkeypatch):
    bus = _Bus()
    monkeypatch.setattr(main, "BUS", bus)
    r = _get("/objets?q=Derniere%20news")
    assert bus.appels[0][0] == "recent"
    assert r.json()["objets"][0]["service"] == "metanews"


def test_bornes(monkeypatch):
    bus = _Bus()
    monkeypatch.setattr(main, "BUS", bus)
    r = _get("/objets?q=" + "x" * 500 + "&limit=999")
    assert len(r.json()["q"]) == 200
    assert bus.appels[0][2] == 10
    _get("/objets?limit=-5")
    assert bus.appels[1][2] == 1
