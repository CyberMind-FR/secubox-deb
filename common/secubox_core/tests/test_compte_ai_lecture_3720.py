# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""#3720 : compte de service `ai-lecture` (portée `waf-lecture`), jeton lié à la méthode GET et au chemin exact,
garde `require_lecture_ou_compte("ai-lecture")` sans repli anonyme dès qu'un porteur EdDSA est présent."""
from __future__ import annotations

import os
import sys
import time

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(__file__))
from test_compte_service_3716 import T, _nouvelle_cle, _poser, cs  # noqa: E402,F401

CHEMIN = "/api/v1/waf/menaces"


@pytest.fixture
def lecture(cs, tmp_path):
    d = tmp_path / "ai-lecture"
    d.mkdir(mode=0o755)
    os.chmod(d, 0o755)
    c = _nouvelle_cle()
    _poser(d, c)
    return c


@pytest.fixture
def ban(cs, tmp_path):
    d = tmp_path / "ai-ban"
    d.mkdir(mode=0o755)
    os.chmod(d, 0o755)
    c = _nouvelle_cle()
    _poser(d, c)
    return c


def _client(cs, tableau=False, monkeypatch=None):
    app = FastAPI()

    def route(p=Depends(cs.require_lecture_ou_compte("ai-lecture"))):
        return {"sub": p.get("sub"), "anonyme": bool(p.get("tableau_de_bord"))}
    app.add_api_route(CHEMIN, route, methods=["GET", "POST"])
    app.add_api_route("/api/v1/waf/autre", route, methods=["GET"])
    return TestClient(app)


def _j(cs, cle, methode="GET", chemin=CHEMIN, compte="ai-lecture"):
    return cs.frapper_jeton(cle.prive, compte, "gk2", b"", time.time(), methode=methode, chemin=chemin)


def test_compte_et_portee(cs):
    assert cs.COMPTES_SERVICE["ai-lecture"] == "waf-lecture"
    # les autres comptes inchangés
    assert {k: v for k, v in cs.COMPTES_SERVICE.items() if k != "ai-lecture"} == {
        "ai-ban": "waf-ban", "ai-filtres": "waf-filtres", "garde": "garde-ban"}


def test_frapper_exige_methode_get_et_chemin(cs, lecture):
    with pytest.raises(ValueError):
        cs.frapper_jeton(lecture.prive, "ai-lecture", "gk2", b"", T)
    with pytest.raises(ValueError):
        cs.frapper_jeton(lecture.prive, "ai-lecture", "gk2", b"", T, methode="POST", chemin=CHEMIN)
    with pytest.raises(ValueError):
        cs.frapper_jeton(lecture.prive, "ai-lecture", "gk2", b"", T, methode="GET", chemin=CHEMIN + "?a=1")


def test_jeton_valide_bon_chemin(cs, lecture):
    r = _client(cs).get(CHEMIN + "?depuis=0", headers={"Authorization": f"Bearer {_j(cs, lecture)}"})
    assert r.status_code == 200 and r.json() == {"sub": "ai-lecture", "anonyme": False}


def test_autre_chemin_401(cs, lecture):
    r = _client(cs).get("/api/v1/waf/autre", headers={"Authorization": f"Bearer {_j(cs, lecture)}"})
    assert r.status_code == 401 and "chemin" in r.json()["detail"]


def test_post_401(cs, lecture):
    r = _client(cs).post(CHEMIN, headers={"Authorization": f"Bearer {_j(cs, lecture)}"})
    assert r.status_code == 401 and "methode" in r.json()["detail"]


def test_jeton_mal_forme_401_jamais_anonyme(cs, lecture, monkeypatch):
    monkeypatch.setenv("SECUBOX_TABLEAU_DE_BORD", "1")
    monkeypatch.setattr(cs.auth, "_requete_lan", lambda r: True)
    c = _client(cs)
    assert c.get(CHEMIN).json()["anonyme"] is True   # témoin : sans porteur, repli de require_lecture
    for faux in ("pas-un-jeton", _j(cs, lecture)[:-4] + "AAAA", _j(cs, lecture).replace(".", "", 1)):
        r = c.get(CHEMIN, headers={"Authorization": f"Bearer {faux}"})
        assert r.status_code == 401, faux
    import jwt
    hs = jwt.encode({"sub": "admin"}, "pas-le-secret-de-la-box-mais-assez-long", algorithm="HS256")
    assert c.get(CHEMIN, headers={"Authorization": f"Bearer {hs}"}).status_code == 401


def test_sans_porteur_comportement_de_require_lecture(cs, lecture, monkeypatch):
    c = _client(cs)
    assert c.get(CHEMIN).status_code == 401
    monkeypatch.setattr(cs.auth.user_store, "is_enabled", lambda s: True)
    monkeypatch.setattr(cs.auth.user_store, "get_user", lambda s: {"role": "admin", "enabled": True})
    monkeypatch.setattr(cs.auth, "_session_validator", lambda jti: True)
    session = cs.auth.create_token("admin")
    r = c.get(CHEMIN, headers={"Authorization": f"Bearer {session}"})
    assert r.status_code == 200 and r.json()["sub"] == "admin"


def test_jeton_ai_ban_refuse(cs, lecture, ban):
    j = cs.frapper_jeton(ban.prive, "ai-ban", "gk2", b"", time.time())
    assert _client(cs).get(CHEMIN, headers={"Authorization": f"Bearer {j}"}).status_code in (401, 403)
    # même une clé ai-ban qui signerait des réclamations ai-lecture : clé inconnue du compte
    j = cs.frapper_jeton(ban.prive, "ai-lecture", "gk2", b"", time.time(), methode="GET", chemin=CHEMIN)
    r = _client(cs).get(CHEMIN, headers={"Authorization": f"Bearer {j}"})
    assert r.status_code == 401 and "cle_inconnue" in r.json()["detail"]


def test_rejeu_refuse(cs, lecture):
    c, j = _client(cs), _j(cs, lecture)
    assert c.get(CHEMIN, headers={"Authorization": f"Bearer {j}"}).status_code == 200
    r = c.get(CHEMIN, headers={"Authorization": f"Bearer {j}"})
    assert r.status_code == 401 and "rejeu" in r.json()["detail"]


def test_ai_lecture_refuse_par_require_ai_ban(cs, lecture, ban):
    app = FastAPI()
    app.add_api_route("/ai", lambda p=Depends(cs.require_ai_ban): {}, methods=["POST"])
    j = cs.frapper_jeton(lecture.prive, "ai-lecture", "gk2", b"", time.time(), methode="GET", chemin="/ai")
    assert TestClient(app).post("/ai", headers={"Authorization": f"Bearer {j}"}).status_code == 401


def test_autres_comptes_sans_reclamations_de_requete(cs, ban):
    """ai-ban reste inchangé : ni `methode` ni `chemin` frappés ni exigés."""
    import jwt
    j = cs.frapper_jeton(ban.prive, "ai-ban", "gk2", b"{}", T)
    p = jwt.decode(j, options={"verify_signature": False})
    assert "methode" not in p and "chemin" not in p
    assert cs.verifier_jeton("ai-ban", j, b"{}", T + 1)["sub"] == "ai-ban"
