# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""ZIA : moteur du maillage s'il répond, local sinon, heuristique en dernier (#3512)."""
import asyncio

import httpx
import pytest

from api import runtime

DISTANT, LOCAL = "http://distant", "http://local"
CFG = {"llm_urls": [DISTANT], "llm_url": LOCAL}


def brancher(monkeypatch, gestion):
    vrai = httpx.AsyncClient
    monkeypatch.setattr(runtime.httpx, "AsyncClient", lambda **k: vrai(transport=httpx.MockTransport(gestion), **k))
    runtime._SONDES.clear()


def reponses(sante, appels):
    def gestion(req):
        hote = "http://" + req.url.host
        if req.url.path == "/health":
            if sante[hote] is None:
                raise httpx.ConnectError("absent")
            return httpx.Response(200, json={"status": sante[hote]})
        appels.append(hote)
        return httpx.Response(200, json={"choices": [{"message": {"content": "de " + hote}}]})
    return gestion


@pytest.mark.parametrize("distant,local,attendu", [
    ("ok", "ok", "de http://distant"),
    (None, "ok", "de http://local"),
    ("veille", "ok", "de http://local"),
    (None, None, None),
])
def test_ordre_et_replis(monkeypatch, distant, local, attendu):
    appels = []
    brancher(monkeypatch, reponses({DISTANT: distant, LOCAL: local}, appels))
    assert asyncio.run(runtime._llm_text(CFG, "x")) == attendu


def test_moteur_tombe_apres_la_sonde_passe_au_suivant(monkeypatch):
    def gestion(req):
        if req.url.path == "/health":
            return httpx.Response(200, json={"status": "ok"})
        if req.url.host == "distant":
            raise httpx.ReadTimeout("trop long")
        return httpx.Response(200, json={"choices": [{"message": {"content": "local"}}]})
    brancher(monkeypatch, gestion)
    assert asyncio.run(runtime._llm_text(CFG, "x")) == "local"
    assert runtime._SONDES[DISTANT][1] is False


def test_sonde_gardee_en_cache(monkeypatch):
    vus = []
    def gestion(req):
        vus.append(req.url.host)
        return httpx.Response(200, json={"status": "ok"})
    brancher(monkeypatch, gestion)
    asyncio.run(runtime.moteurs_disponibles({"llm_url": LOCAL}))
    asyncio.run(runtime.moteurs_disponibles({"llm_url": LOCAL}))
    assert vus == ["local"]


def test_sans_liste_comportement_inchange():
    assert runtime.liste_moteurs({"llm_url": LOCAL}) == [LOCAL]
    assert runtime.liste_moteurs({}) == []
