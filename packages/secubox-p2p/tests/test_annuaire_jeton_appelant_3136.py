# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3136 — page « Registre de services » : « Catalogue de l'annuaire indisponible » (gk2 et gk1).

L'annuaire garde /services et /subscriptions en lecture depuis #1256 ; le client p2p les appelait sans jeton (401), et
son jeton de service n'a pas de session au registre partagé (refusé aussi). Le module relaie à l'annuaire LOCAL le jeton
de l'appelant, le temps de sa requête."""
import pytest
from fastapi.testclient import TestClient

from api import annuaire_client as ac
from api import main


@pytest.fixture
def capture(monkeypatch):
    vus = []

    def faux(methode, chemin, sock, body=None, auth_token=None):
        vus.append((methode, chemin, auth_token))
        return {"services": [], "subscriptions": []}, None

    monkeypatch.setattr(ac, "_request", faux)
    monkeypatch.setattr(ac, "_service_token", lambda: "JETON-DE-SERVICE")
    return vus


def test_sans_appelant_les_lectures_restent_sans_jeton(capture):
    ac.get_catalog()
    ac.get_subscriptions("did:plc:" + "a" * 32)
    assert [j for _, _, j in capture] == [None, None]


def test_jeton_de_l_appelant_envoye_aux_lectures(capture):
    avec = ac.JETON_APPELANT.set("JETON-ADMIN")
    try:
        ac.get_catalog()
        ac.get_subscriptions("did:plc:" + "a" * 32)
    finally:
        ac.JETON_APPELANT.reset(avec)
    assert [j for _, _, j in capture] == ["JETON-ADMIN", "JETON-ADMIN"]


def test_abonnement_prefere_le_jeton_de_l_appelant_au_jeton_de_service(capture):
    ac.subscribe("svc", "did:plc:" + "a" * 32, "11" * 32)
    assert capture[-1][2] == "JETON-DE-SERVICE"            # sans appelant : l'ancien comportement
    avec = ac.JETON_APPELANT.set("JETON-ADMIN")
    try:
        ac.subscribe("svc", "did:plc:" + "a" * 32, "11" * 32)
    finally:
        ac.JETON_APPELANT.reset(avec)
    assert capture[-1][2] == "JETON-ADMIN"


def _jeton_vu_par_le_catalogue(monkeypatch, **requete):
    vus = []

    def faux(methode, chemin, sock, body=None, auth_token=None):
        vus.append(auth_token)
        return {"services": [], "subscriptions": []}, None

    monkeypatch.setattr(ac, "_request", faux)
    main.app.dependency_overrides[main.require_lecture] = lambda: {"sub": "admin"}
    try:
        TestClient(main.app).get("/services", **requete)
    finally:
        main.app.dependency_overrides.clear()
    return vus[0]


def test_la_requete_relaie_son_en_tete_authorization(monkeypatch):
    assert _jeton_vu_par_le_catalogue(monkeypatch, headers={"Authorization": "Bearer ABC.DEF.GHI"}) == "ABC.DEF.GHI"


def test_la_requete_relaie_son_cookie_de_session(monkeypatch):
    from secubox_core.auth import SESSION_COOKIE
    assert _jeton_vu_par_le_catalogue(monkeypatch, cookies={SESSION_COOKIE: "COOKIE.TOK.EN"}) == "COOKIE.TOK.EN"


def test_requete_anonyme_ne_relaie_rien(monkeypatch):
    assert _jeton_vu_par_le_catalogue(monkeypatch) is None


def test_le_jeton_ne_survit_pas_a_la_requete(monkeypatch):
    _jeton_vu_par_le_catalogue(monkeypatch, headers={"Authorization": "Bearer ABC.DEF.GHI"})
    assert ac.JETON_APPELANT.get() is None
