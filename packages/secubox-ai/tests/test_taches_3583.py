# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Tâches de fond, travaux en cours, Tout arrêter (#3583)."""
import asyncio
import json
import time

import httpx
import pytest
from fastapi.testclient import TestClient

from secubox_core.auth import require_jwt
from api import moteurs, taches
from api.main import app


@pytest.fixture(autouse=True)
def propre(monkeypatch):
    taches.TACHES.clear()
    taches.TRAVAUX.clear()
    ajouts = []
    monkeypatch.setattr(taches, "HISTORIQUE_AJOUTER", lambda *a, **k: ajouts.append(a))
    yield ajouts
    monkeypatch.setattr(moteurs, "FABRIQUE_TRANSPORT", None)
    taches.TACHES.clear()
    taches.TRAVAUX.clear()


async def attendre(t):
    await taches.TACHES[t]["_tache"]


@pytest.mark.asyncio
async def test_arret_garde_le_partiel(propre):
    t = taches.nouvelle_tache("document", "Doc")

    async def travail():
        taches.etape(t, "lecture")
        taches.TACHES[t]["resultat"] = "début du résumé"
        await asyncio.sleep(30)

    taches.lancer_tache(t, travail(), 60)
    await asyncio.sleep(0.05)
    taches.TACHES[t]["_tache"].cancel()
    await asyncio.sleep(0.05)
    x = taches.TACHES[t]
    assert x["etat"] == "arrete"
    assert x["resultat"].startswith("début du résumé") and "Arrêté à la demande" in x["resultat"]
    assert x["etapes"][-1]["etat"] == "arrete"
    assert propre and propre[0][1] == "Doc (partiel)"


@pytest.mark.asyncio
async def test_arret_sans_partiel():
    t = taches.nouvelle_tache("document", "Doc")
    taches.lancer_tache(t, asyncio.sleep(30), 60)
    await asyncio.sleep(0.05)
    taches.TACHES[t]["_tache"].cancel()
    await asyncio.sleep(0.05)
    assert taches.TACHES[t]["etat"] == "arrete" and taches.TACHES[t]["resultat"] == "Arrêté à la demande."


@pytest.mark.asyncio
async def test_depassement_echec_partiel_garde(propre):
    t = taches.nouvelle_tache("agent", "Agent")

    async def travail():
        taches.TACHES[t]["resultat"] = "acquis"
        await asyncio.sleep(30)

    taches.lancer_tache(t, travail(), 0.1)
    await attendre(t)
    x = taches.TACHES[t]
    assert x["etat"] == "echec" and x["resultat"].startswith("acquis") and "dépassé sa durée maximale" in x["resultat"]
    assert propre[0][1] == "Agent (partiel)"


@pytest.mark.asyncio
async def test_formule_creuse_retiree_et_fini_historise(propre):
    t = taches.nouvelle_tache("document", "Doc")
    taches.etape(t, "a")
    taches.finir(t, "fini", "Voici le résumé :\n\nLe fond.")
    assert taches.TACHES[t]["resultat"] == "Le fond."
    assert taches.TACHES[t]["etapes"][0]["etat"] == "fait"
    assert propre[0][:3] == ("document", "Doc", "Le fond.")


@pytest.mark.asyncio
async def test_erreur_http_devient_echec():
    t = taches.nouvelle_tache("document", "Doc")

    async def travail():
        raise httpx.ConnectError("x")

    taches.lancer_tache(t, travail(), 5)
    await attendre(t)
    assert taches.TACHES[t]["etat"] == "echec" and "ConnectError" in taches.TACHES[t]["resultat"]


@pytest.mark.asyncio
async def test_deux_taches_simultanees_gardent_leurs_etapes():
    a, b = taches.nouvelle_tache("document", "A"), taches.nouvelle_tache("document", "B")

    async def travail(t, nom):
        taches.etape(t, nom + "1")
        await asyncio.sleep(0.05)
        taches.etape(t, nom + "2")
        await asyncio.sleep(0.05)
        taches.finir(t, "fini", "res " + nom)

    taches.lancer_tache(a, travail(a, "a"), 5)
    taches.lancer_tache(b, travail(b, "b"), 5)
    await attendre(a)
    await attendre(b)
    assert a != b
    assert [e["texte"] for e in taches.TACHES[a]["etapes"]] == ["a1", "a2"]
    assert [e["texte"] for e in taches.TACHES[b]["etapes"]] == ["b1", "b2"]
    assert taches.TACHES[a]["resultat"] == "res a" and taches.TACHES[b]["resultat"] == "res b"


def test_limite_de_30_taches():
    for i in range(35):
        taches.nouvelle_tache("g", str(i))
    assert len(taches.TACHES) == 30


@pytest.mark.asyncio
async def test_fil_suivi_recopie_dans_le_travail():
    taches.TRAVAUX["w"] = {"id": "w", "question": "q", "evenements": [], "texte": "", "dernier": None, "lecture": None,
                           "fini": False, "debut": time.time(), "fin": None}
    f = taches.FilSuivi("w", time.time())
    await f.put({"etape": "lecture", "fait": 3, "total": 9})
    await f.put({"etape": "texte", "morceau": "abc"})
    tr = taches.TRAVAUX["w"]
    assert tr["lecture"] == [3, 9] and tr["texte"] == "abc" and tr["dernier"] == "texte"
    assert all("t" in e for e in tr["evenements"])
    await f.put(None)
    assert tr["fini"] is True and tr["fin"]


def test_purge_des_travaux_finis_expires():
    taches.TRAVAUX["vieux"] = {"fini": True, "fin": time.time() - 4000}
    taches.TRAVAUX["frais"] = {"fini": False, "fin": None}
    taches.purger_travaux()
    assert "vieux" not in taches.TRAVAUX and "frais" in taches.TRAVAUX


def sse(*messages):
    corps = "".join("data: " + json.dumps(m) + "\n\n" for m in messages) + "data: [DONE]\n\n"
    return httpx.Response(200, content=corps.encode(), headers={"content-type": "text/event-stream"})


@pytest.mark.asyncio
async def test_demander_modele_progression(monkeypatch):
    t = taches.nouvelle_tache("document", "Doc")
    vus, corps_vu = [], []

    async def assurer(delai=180, pas=1.0):
        return moteurs.Moteur("local")

    def h(req):
        corps_vu.append(json.loads(req.content))
        return sse({"prompt_progress": {"processed": 10, "total": 40, "time_ms": 5}},
                   {"choices": [{"delta": {"content": "<think>x</think>Bon"}}]},
                   {"choices": [{"delta": {"content": "jour"}}]})

    monkeypatch.setattr(taches, "assurer_moteur", assurer)
    monkeypatch.setattr(moteurs, "FABRIQUE_TRANSPORT", lambda nom: httpx.MockTransport(h))
    orig = taches.TACHES[t]

    class Espion(dict):
        def __setitem__(self, k, v):
            if k == "progression":
                vus.append(v)
            super().__setitem__(k, v)

    taches.TACHES[t] = Espion(orig)
    res = await taches.demander_modele("sys", "util", 50, t)
    assert res == "Bonjour"
    assert vus[0]["phase"] == "attente"
    assert {"phase": "lecture", "fait": 10, "total": 40, "ms": 5} in vus
    assert vus[-1] == {"phase": "ecriture", "fait": 2, "total": 50}
    assert corps_vu[0]["return_progress"] is True and corps_vu[0]["stream"] is True
    assert corps_vu[0]["messages"][0]["role"] == "system"
    assert taches.COMPTEURS["en_cours"] == 0


@pytest.mark.asyncio
async def test_demander_modele_refus(monkeypatch):
    from fastapi import HTTPException

    async def assurer(delai=180, pas=1.0):
        return moteurs.Moteur("local")

    monkeypatch.setattr(taches, "assurer_moteur", assurer)
    monkeypatch.setattr(moteurs, "FABRIQUE_TRANSPORT", lambda nom: httpx.MockTransport(lambda r: httpx.Response(500)))
    with pytest.raises(HTTPException) as e:
        await taches.demander_modele("s", "u")
    assert e.value.status_code == 502 and taches.COMPTEURS["en_cours"] == 0


def test_routes_exigent_jwt():
    c = TestClient(app)
    for m, u in (("get", "/travaux"), ("get", "/travaux/x"), ("post", "/travaux/x/arreter"), ("post", "/tout-arreter"),
                 ("get", "/taches/x"), ("post", "/taches/x/arreter")):
        assert getattr(c, m)(u).status_code in (401, 403), u


@pytest.mark.asyncio
async def test_routes_et_tout_arreter():
    app.dependency_overrides[require_jwt] = lambda: {"sub": "admin"}
    try:
        t = taches.nouvelle_tache("document", "Doc")
        taches.lancer_tache(t, asyncio.sleep(30), 60)
        tache_w = asyncio.create_task(asyncio.sleep(30))
        taches.TRAVAUX["w"] = {"id": "w", "question": "q" * 200, "evenements": [{"etape": "texte"}], "texte": "ab",
                               "dernier": "texte", "lecture": None, "fini": False, "debut": time.time(), "fin": None,
                               "_tache": tache_w}
        await asyncio.sleep(0.05)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
            liste = (await c.get("/travaux")).json()["travaux"]
            assert {x["id"] for x in liste} == {t, "w"}
            w = next(x for x in liste if x["id"] == "w")
            assert w["genre"] == "dialogue" and len(w["titre"]) == 120 and w["progression"]["phase"] == "ecriture"
            lu = (await c.get(f"/taches/{t}")).json()
            assert lu["etat"] == "en_cours" and "_tache" not in lu
            assert (await c.get("/taches/zzz")).status_code == 404
            assert (await c.get("/travaux/zzz")).status_code == 404
            assert (await c.get("/travaux/w?depuis=1")).json()["evenements"] == []
            r = await c.post("/tout-arreter")
            assert r.json() == {"arretes": 2}
            await asyncio.sleep(0.05)
        assert taches.TACHES[t]["etat"] == "arrete"
        assert taches.TRAVAUX["w"]["fini"] and taches.TRAVAUX["w"]["dernier"] == "arrêté"
        assert tache_w.cancelled()
    finally:
        app.dependency_overrides.pop(require_jwt, None)


@pytest.mark.asyncio
async def test_arreter_une_tache_et_un_travail():
    app.dependency_overrides[require_jwt] = lambda: {"sub": "admin"}
    try:
        t = taches.nouvelle_tache("agent", "Ag")
        taches.lancer_tache(t, asyncio.sleep(30), 60)
        tw = asyncio.create_task(asyncio.sleep(30))
        taches.TRAVAUX["w"] = {"id": "w", "question": "q", "evenements": [], "texte": "", "dernier": None, "lecture": None,
                               "fini": False, "debut": time.time(), "fin": None, "_tache": tw}
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
            assert (await c.post(f"/taches/{t}/arreter")).json() == {"ok": True}
            assert (await c.post("/travaux/w/arreter")).json() == {"ok": True}
            assert (await c.post("/travaux/zzz/arreter")).status_code == 404
            await asyncio.sleep(0.05)
        assert taches.TACHES[t]["etat"] == "arrete" and taches.TRAVAUX["w"]["fini"]
    finally:
        app.dependency_overrides.pop(require_jwt, None)
