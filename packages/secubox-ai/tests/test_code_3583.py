# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Code (#3583, tâche 11) : expliquer, relire, tests, corriger, documenter. Moteur simulé, aucun réseau réel."""
import asyncio
import json
import logging

import httpx
import pytest

from secubox_core.auth import require_jwt

from api import code, moteurs, reglages, taches
from api.main import app

SECRET = "mot_de_passe_unique_xyz = 'hunter2'"


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("SECUBOX_AI_ETAT", str(tmp_path / "etat"))
    monkeypatch.setenv("SECUBOX_AI_CONF", str(tmp_path / "ai.toml"))
    monkeypatch.setenv("SECUBOX_AI_CLE", str(tmp_path / "cle"))
    monkeypatch.setenv("SECUBOX_AI_RUN", str(tmp_path / "run"))
    taches.TACHES.clear()
    moteurs._cache_sonde.clear()
    app.dependency_overrides[require_jwt] = lambda: {"sub": "admin"}
    yield tmp_path
    app.dependency_overrides.pop(require_jwt, None)
    taches.TACHES.clear()


def moteur_simule(monkeypatch, reponse="Réponse du modèle."):
    vus = []

    def fabrique(nom):
        def h(req):
            if req.url.path == "/health":
                return httpx.Response(200)
            if req.url.path == "/props":
                return httpx.Response(200, json={"default_generation_settings": {"n_ctx": 4096}})
            if req.url.path == "/v1/chat/completions":
                vus.append(json.loads(req.content))
                flux = "data: " + json.dumps({"choices": [{"delta": {"content": reponse}}]}) + "\n\ndata: [DONE]\n\n"
                return httpx.Response(200, content=flux.encode(), headers={"content-type": "text/event-stream"})
            return httpx.Response(404)
        return httpx.MockTransport(h)

    monkeypatch.setattr(moteurs, "FABRIQUE_TRANSPORT", fabrique)
    return vus


async def appeler(methode, chemin, **kw):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        return await c.request(methode, chemin, **kw)


async def attendre(t):
    for _ in range(200):
        if taches.TACHES[t]["etat"] != "en_cours":
            return taches.TACHES[t]
        await asyncio.sleep(0.02)
    raise AssertionError("tâche non terminée")


@pytest.mark.asyncio
async def test_action_inconnue_404(env):
    r = await appeler("POST", "/code/deviner", json={"code": "x = 1"})
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_code_vide_422(env):
    assert (await appeler("POST", "/code/relire", json={"code": "  \n "})).status_code == 422


@pytest.mark.asyncio
async def test_code_trop_long_413(env):
    r = await appeler("POST", "/code/relire", json={"code": "a" * (code.CODE_MAX + 1)})
    assert r.status_code == 413
    assert not taches.TACHES


@pytest.mark.asyncio
async def test_langue_assainie_et_code_numerote(env, monkeypatch):
    vus = moteur_simule(monkeypatch)
    r = await appeler("POST", "/code/expliquer", json={"code": "a = 1\nb = 2", "langue": "py;rm"})
    t = r.json()["tache"]
    fin = await attendre(t)
    assert fin["etat"] == "fini" and fin["resultat"] == "Réponse du modèle."
    utilisateur = vus[0]["messages"][-1]["content"]
    assert "Langage : pyrm\n" in utilisateur and "py;rm" not in utilisateur
    assert "   1 a = 1\n   2 b = 2" in utilisateur
    assert fin["titre"] == "Expliquer — pyrm"
    assert any(e["texte"] == "lire et expliquer" for e in fin["etapes"])


@pytest.mark.asyncio
async def test_consigne_perso_bornee_a_500(env, monkeypatch):
    vus = moteur_simule(monkeypatch)
    t = (await appeler("POST", "/code/tests", json={"code": "x", "consigne": " " + "z" * 600})).json()["tache"]
    await attendre(t)
    assert "Consigne en plus : " + "z" * 500 + "\n" in vus[0]["messages"][-1]["content"]
    assert "z" * 501 not in vus[0]["messages"][-1]["content"]


@pytest.mark.asyncio
async def test_regles_de_la_memoire_jointes_quand_active(env, monkeypatch):
    vus = moteur_simule(monkeypatch)
    demandes = []

    def chercher(question, budget, compter):
        demandes.append((question, budget, compter))
        return [{"id": 1, "genre": "note", "titre": "Style", "repere": "", "texte": "Toujours des docstrings en français."}]

    monkeypatch.setattr(code, "memoire_chercher", chercher)
    t = (await appeler("POST", "/code/relire", json={"code": "x = 1", "langue": "python"})).json()["tache"]
    fin = await attendre(t)
    assert demandes == [("règles code conventions python", 3000, True)]
    systeme = vus[0]["messages"][0]["content"]
    assert "Règles de code de l'utilisateur" in systeme and "Toujours des docstrings en français." in systeme
    assert fin["etapes"][0]["texte"] == "chercher tes règles de code dans la mémoire"


@pytest.mark.asyncio
async def test_memoire_inactive_pas_de_recherche(env, monkeypatch):
    vus = moteur_simule(monkeypatch)
    vraies = reglages.lire_prefs

    def prefs():
        p = vraies()
        return {**p, "memoire": {**p["memoire"], "actif": False}}

    monkeypatch.setattr(reglages, "lire_prefs", prefs)
    monkeypatch.setattr(code, "memoire_chercher", lambda *a: pytest.fail("mémoire interrogée alors qu'inactive"))
    t = (await appeler("POST", "/code/corriger", json={"code": "x = 1"})).json()["tache"]
    await attendre(t)
    assert "Règles de code" not in vus[0]["messages"][0]["content"]


@pytest.mark.asyncio
async def test_exception_imprevue_finit_en_echec(env, monkeypatch, caplog):
    moteur_simule(monkeypatch)

    def casse(*a):
        raise RuntimeError("boum " + SECRET)

    monkeypatch.setattr(code, "memoire_chercher", casse)
    with caplog.at_level(logging.DEBUG):
        t = (await appeler("POST", "/code/relire", json={"code": SECRET, "langue": "klingon"})).json()["tache"]
        fin = await attendre(t)
    assert fin["etat"] == "echec" and "RuntimeError" in fin["resultat"]
    assert "hunter2" not in fin["resultat"]


@pytest.mark.asyncio
async def test_le_journal_ne_contient_ni_code_ni_langue_ni_consigne(env, monkeypatch, caplog):
    moteur_simule(monkeypatch)
    with caplog.at_level(logging.DEBUG):
        t = (await appeler("POST", "/code/documenter", json={"code": SECRET, "langue": "klingon",
                                                              "consigne": "consigne_secrete_abc"})).json()["tache"]
        await attendre(t)
    journal = caplog.text + "\n".join(r.getMessage() for r in caplog.records)
    for interdit in ("hunter2", "mot_de_passe_unique_xyz", "klingon", "consigne_secrete_abc"):
        assert interdit not in journal


@pytest.mark.asyncio
async def test_toutes_les_routes_exigent_le_jeton(env):
    app.dependency_overrides.pop(require_jwt, None)
    for action in code.CONSIGNES_CODE:
        assert (await appeler("POST", f"/code/{action}", json={"code": "x"})).status_code in (401, 403)
