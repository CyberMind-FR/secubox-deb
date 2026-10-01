# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Déconnexion et registre des sessions (#1803).

- La déconnexion retire le jti du registre (cookie comme Bearer), pas seulement
  le cookie du navigateur.
- Toute écriture du registre passe par `sessions.muter` : verrouillée et
  atomique — deux processus qui écrivent en même temps ne perdent rien.
"""
import json
import multiprocessing
import os
import stat

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from secubox_core import auth, sessions


@pytest.fixture
def registre(tmp_path, monkeypatch):
    p = tmp_path / "sessions.json"
    p.write_text("[]")
    os.chmod(p, 0o640)
    monkeypatch.setenv("SECUBOX_AUTH_SESSIONS", str(p))
    monkeypatch.setenv("SECUBOX_JWT_SECRET", "secret-de-test-uniquement-1803")
    monkeypatch.setattr(auth, "get_config", lambda section="": {})
    sessions.invalidate_cache()
    return p


def _lignes(p):
    return json.loads(p.read_text())


# ── muter ─────────────────────────────────────────────────────────────────
def test_muter_ajoute_et_garde_le_mode(registre):
    sessions.muter(lambda rows: rows + [{"id": "a", "username": "gk2"}])
    assert _lignes(registre) == [{"id": "a", "username": "gk2"}]
    assert stat.S_IMODE(os.stat(registre).st_mode) == 0o640
    assert sessions.is_valid("a")
    assert not list(registre.parent.glob(".sessions.*")), "aucun temporaire laissé"


def test_muter_registre_absent_ou_corrompu(registre):
    registre.write_text("{ pas du json")
    sessions.muter(lambda rows: rows + [{"id": "b"}])
    assert _lignes(registre) == [{"id": "b"}]


def _ajoute_n(chemin, prefixe, n):
    os.environ["SECUBOX_AUTH_SESSIONS"] = chemin
    from secubox_core import sessions as s
    for i in range(n):
        s.muter(lambda rows, i=i: rows + [{"id": f"{prefixe}-{i}"}])


def test_muter_deux_processus_ne_perdent_rien(registre):
    ctx = multiprocessing.get_context("fork")
    ps = [ctx.Process(target=_ajoute_n, args=(str(registre), f"p{k}", 150)) for k in range(2)]
    for p in ps:
        p.start()
    for p in ps:
        p.join(60)
    assert len(_lignes(registre)) == 300


def test_jtis_du_compte(registre):
    registre.write_text(json.dumps([{"id": "x", "username": "gk2"}, {"id": "y", "username": "op"},
                                    {"id": "z", "username": "gk2"}]))
    assert sorted(sessions.jtis_du_compte("gk2")) == ["x", "z"]


# ── déconnexion ───────────────────────────────────────────────────────────
@pytest.fixture
def client(registre, monkeypatch):
    evenements = []

    def rappel(evt, user, details):
        evenements.append((evt, user, details))
        if evt == "sessions_coupees":
            cibles = set(details.get("jtis") or [])
            sessions.muter(lambda rows: [r for r in rows if r.get("id") not in cibles])
    monkeypatch.setattr(auth, "_session_callback", rappel)
    app = FastAPI()
    app.include_router(auth.router, prefix="/auth")
    return TestClient(app), evenements


def _session(registre, sub="gk2"):
    jeton = auth.create_token(sub)
    jti = jwt_jti(jeton)
    sessions.muter(lambda rows: rows + [{"id": jti, "username": sub}])
    return jeton, jti


def jwt_jti(jeton):
    import jwt
    return jwt.decode(jeton, options={"verify_signature": False})["jti"]


def test_deconnexion_par_cookie_retire_le_jti(registre, client):
    c, evts = client
    jeton, jti = _session(registre)
    autre, jti2 = _session(registre)
    r = c.post("/auth/logout", cookies={auth.SESSION_COOKIE: jeton})
    assert r.status_code == 200
    restants = {l["id"] for l in _lignes(registre)}
    assert jti not in restants and jti2 in restants, "seule CETTE session est coupée"
    assert evts[-1][0] == "sessions_coupees"


def test_deconnexion_par_bearer(registre, client):
    c, _ = client
    jeton, jti = _session(registre)
    c.post("/auth/logout", headers={"Authorization": "Bearer " + jeton})
    assert jti not in {l["id"] for l in _lignes(registre)}


def test_jeton_illisible_n_empeche_pas_d_effacer_le_cookie(registre, client):
    c, evts = client
    r = c.post("/auth/logout", cookies={auth.SESSION_COOKIE: "pas.un.jeton"})
    assert r.status_code == 200 and evts == []
    assert auth.SESSION_COOKIE in r.headers.get("set-cookie", "")


def test_jeton_d_intention_jamais_traite_comme_session(registre, client):
    c, evts = client
    jeton = auth.create_token("gk2", scope="mfa-challenge")
    c.post("/auth/logout", headers={"Authorization": "Bearer " + jeton})
    assert evts == []


def test_muter_relit_l_ancien_format_et_reecrit_une_liste(registre):
    registre.write_text(json.dumps({"sessions": [{"id": "c3"}, {"id": "d4"}], "revoked_at": "x"}))
    sessions.muter(lambda rows: [r for r in rows if r["id"] != "c3"])
    assert _lignes(registre) == [{"id": "d4"}]


def test_muter_chemin_explicite(tmp_path, registre):
    autre = tmp_path / "autre.json"
    sessions.muter(lambda rows: rows + [{"id": "z"}], chemin=autre)
    assert json.loads(autre.read_text()) == [{"id": "z"}] and _lignes(registre) == []
