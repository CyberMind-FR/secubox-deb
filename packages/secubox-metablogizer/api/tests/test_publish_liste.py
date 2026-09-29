# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""L'assistant de publication rafraîchit la liste « Mes sites » (#1687).

Appel direct des routes (sans TestClient) : ce qui compte est que chaque
chemin d'écriture de l'assistant prévienne le cache de liste."""
import asyncio
import io
import json

import pytest
from starlette.datastructures import UploadFile

import routers.publish as rp


@pytest.fixture
def appels(tmp_path, monkeypatch):
    compte = []
    monkeypatch.setattr(rp, "invalider_cache_sites", lambda: compte.append(1))
    monkeypatch.setattr(rp, "SITES_ROOT", tmp_path / "sites")
    (tmp_path / "sites" / "zem").mkdir(parents=True)

    async def sequence(name, domain, data, nom_fichier):
        yield "content", {"index_present": True}
        yield "route", {"route_ok": True}
        yield "vhost", {"ok": True}

    monkeypatch.setattr(rp, "_sequence_publication", sequence)
    monkeypatch.setattr(rp, "marque_publie", lambda site, ok: {"published": ok})
    return compte


def _fichier():
    return UploadFile(file=io.BytesIO(b"<html></html>"), filename="index.html")


def test_publication_directe_rafraichit_la_liste(appels):
    r = asyncio.run(rp.publish_wizard(name="zem", domain="zem.ex.com", file=_fichier(), flux=0, user={}))
    assert r["ok"] is True
    assert appels == [1]


def test_publication_en_flux_rafraichit_la_liste(appels):
    async def lire():
        rep = await rp.publish_wizard(name="zem", domain="zem.ex.com", file=_fichier(), flux=1, user={})
        return [json.loads(l) async for l in rep.body_iterator]

    lignes = asyncio.run(lire())
    assert lignes[-1]["type"] == "fin" and lignes[-1]["ok"] is True
    assert appels == [1]


def test_route_rafraichit_la_liste(appels, monkeypatch):
    monkeypatch.setattr(rp, "apply_route", lambda domain, port=8900: {"route_ok": True})

    async def cert(domain):
        return {"mode": "wildcard"}

    monkeypatch.setattr(rp, "_cert_step", cert)
    r = asyncio.run(rp.publish_route(rp.RouteRequest(domain="zem.ex.com"), user={}))
    assert r["ok"] is True and appels == [1]


def test_import_rafraichit_la_liste(appels, monkeypatch):
    monkeypatch.setattr(rp, "import_site", lambda art, racine: {"name": "zem"})
    asyncio.run(rp.publish_import(file=_fichier(), user={}))
    assert appels == [1]
