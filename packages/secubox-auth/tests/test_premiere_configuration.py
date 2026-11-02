# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""#1707 : la première configuration d'un compte est un acte LOCAL."""
import importlib
import json
import os
from pathlib import Path

import pytest
from argon2 import PasswordHasher
from fastapi.testclient import TestClient


def _compte(nom, mdp, a_changer):
    return {"username": nom, "email": None, "role": "admin", "enabled": True,
            "password_hash": PasswordHasher().hash(mdp) if mdp else None,
            "must_change_password": a_changer, "totp": None, "google": None, "services": [],
            "created": "2026-09-01T00:00:00+00:00", "last_login": None}


@pytest.fixture
def c(tmp_path: Path, monkeypatch):
    users = tmp_path / "users.json"
    users.write_text(json.dumps({"version": 2, "groups": [], "users": [
        _compte("gk3", None, True),               # le cas vécu : admin, aucun mot de passe
        _compte("admin", "secubox", True),        # le compte du premier démarrage
    ]}))
    (tmp_path / "sessions.json").write_text("[]")
    (tmp_path / "totp-pending.json").write_text("{}")
    for k, v in {"USERS_FILE": users, "SECUBOX_AUTH_DATA_DIR": tmp_path,
                 "SECUBOX_AUTH_SESSIONS": tmp_path / "sessions.json",
                 "SECUBOX_AUTH_AUDIT": tmp_path / "audit.log",
                 "SECUBOX_AUTH_TOTP_PENDING": tmp_path / "totp-pending.json",
                 "SECUBOX_AUTH_REGLAGES": tmp_path / "reglages.json",
                 "SECUBOX_USERS_JSON": users, "SECUBOX_AUDIT_LOG": tmp_path / "audit-secubox.log"}.items():
        monkeypatch.setenv(k, str(v))
    monkeypatch.setenv("SECUBOX_JWT_SECRET", "test-secret-de-trente-deux-octets!!")
    from secubox_core import config as sbx_config, user_store
    monkeypatch.setattr(sbx_config, "_CONF_PATHS", [])
    monkeypatch.setattr(sbx_config, "_CONFIG", None)
    monkeypatch.setattr(user_store, "USERS_PATH", users)
    from api import main as auth_main
    importlib.reload(auth_main)
    return TestClient(auth_main.app)


def _login(c, nom, mdp, lan):
    return c.post("/login", json={"username": nom, "password": mdp}, headers={"X-SecuBox-LAN": lan})


def test_depuis_le_wan_un_mot_de_passe_vide_ne_donne_rien(c):
    r = _login(c, "gk3", "", "0")
    assert r.status_code == 401 and "setup_token" not in r.text


def test_depuis_le_lan_la_premiere_configuration_est_offerte(c):
    r = _login(c, "gk3", "", "1")
    assert r.status_code == 200 and r.json().get("setup_required") is True


def test_compte_a_changer_avec_mot_de_passe_le_vide_ne_suffit_pas(c):
    r = _login(c, "admin", "", "1")
    assert r.status_code == 401 and "setup_token" not in r.text


def test_le_bon_mot_de_passe_impose_le_changement_pas_une_session(c):
    # Sans le marqueur « Plus tard », le flux d'origine (#1707) : changement obligatoire.
    r = _login(c, "admin", "secubox", "1").json()
    assert r.get("setup_required") is True and "access_token" not in r


def _setup(c, nom="admin", lan="1", xff=None):
    h = {"X-SecuBox-LAN": lan}
    if xff:
        h["X-Forwarded-For"] = xff
    r = c.post("/login", json={"username": nom, "password": "secubox"}, headers=h).json()
    assert r.get("setup_required") is True and "access_token" not in r
    return r["setup_token"]


def _plus_tard(c, jeton, lan="1", xff=None):
    h = {"Authorization": "Bearer " + jeton, "X-SecuBox-LAN": lan}
    if xff:
        h["X-Forwarded-For"] = xff
    return c.post("/plus-tard", headers=h)


def test_plus_tard_ouvre_une_session_lan_admin_auditee(c, tmp_path):
    r = _plus_tard(c, _setup(c))
    assert r.status_code == 200 and "access_token" in r.json()
    lignes = [json.loads(x) for x in (tmp_path / "audit-secubox.log").read_text().splitlines()]
    assert lignes[-1]["evenement"] == "mot_de_passe_defaut_reporte" and lignes[-1]["compte"] == "admin"


def test_plus_tard_depuis_le_maillage(c):
    jeton = _setup(c, lan="0", xff="10.10.0.7")
    assert _plus_tard(c, jeton, lan="0", xff="10.64.2.9").status_code == 200


def test_plus_tard_refuse_hors_lan(c):
    jeton = _setup(c)
    r = _plus_tard(c, jeton, lan="0", xff="203.0.113.9")
    assert r.status_code == 401 and "access_token" not in r.text


def test_plus_tard_refuse_pour_un_non_admin(c, tmp_path):
    users = tmp_path / "users.json"
    d = json.loads(users.read_text())
    d["users"].append(_compte("bob", "secubox", True))
    users.write_text(json.dumps(d))
    r = _plus_tard(c, _setup(c, "bob"))
    assert r.status_code == 403 and "access_token" not in r.text


def test_la_connexion_suivante_redemande(c):
    _plus_tard(c, _setup(c))
    _setup(c)                                   # la question revient : rien n'a été persisté


def test_setup_token_a_usage_unique(c):
    jeton = _setup(c)
    assert _plus_tard(c, jeton).status_code == 200
    assert _plus_tard(c, jeton).status_code == 401
    r = c.post("/set-password", json={"new_password": "une phrase longue et choisie"},
               headers={"Authorization": "Bearer " + jeton})
    assert r.status_code == 401


def test_defaut_depuis_le_maillage_demande_le_changement(c):
    _setup(c, lan="0", xff="10.10.0.7")


def test_depuis_le_wan_le_defaut_est_un_401_identique_mais_audite(c, tmp_path):
    bon = _login(c, "admin", "secubox", "0")
    faux = _login(c, "admin", "secubox2", "0")
    assert bon.status_code == faux.status_code == 401 and bon.json() == faux.json()
    assert "connexion_refusee_hors_lan" in (tmp_path / "audit-secubox.log").read_text()


def test_depuis_le_wan_un_mauvais_mot_de_passe_reste_un_401_muet(c):
    r = _login(c, "admin", "secubox2", "0")
    assert r.status_code == 401 and "défaut" not in r.text


def test_un_mot_de_passe_reinitialise_impose_encore_le_changement(c, tmp_path):
    users = tmp_path / "users.json"
    d = json.loads(users.read_text())
    d["users"].append(_compte("bob", "provisoire-tres-long", True))
    users.write_text(json.dumps(d))
    r = _login(c, "bob", "provisoire-tres-long", "1").json()
    assert r.get("setup_required") is True and "access_token" not in r


def test_etat_refuse_a_un_non_administrateur(c):
    assert c.get("/mot-de-passe-defaut").status_code == 401
    assert c.get("/mot-de-passe-defaut", headers={"Authorization": "Bearer faux"}).status_code == 401


def test_etat_garde_par_require_jwt():
    from api import main as m
    r = next(r for r in m._login_router.routes if getattr(r, "path", "") == "/mot-de-passe-defaut")
    assert any(d.call is m.require_jwt for d in r.dependant.dependencies)


def test_etat_rendu_a_un_administrateur_reel(c):
    from api import main as m
    c.app.dependency_overrides[m.require_jwt] = lambda: {"sub": "admin"}
    try:
        assert c.get("/mot-de-passe-defaut").json()["etat"] == "actif"
    finally:
        c.app.dependency_overrides.clear()
