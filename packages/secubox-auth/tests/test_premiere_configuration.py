# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""#1707 : la première configuration d'un compte est un acte LOCAL."""
import importlib
import json
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
                 "SECUBOX_USERS_JSON": users, "SECUBOX_AUDIT_LOG": tmp_path / "audit-secubox.log",
                 "SECUBOX_PLUS_TARD": tmp_path / "plus-tard"}.items():
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


def test_plus_tard_ouvre_une_session_lan_pour_admin_et_s_audite(c, tmp_path):
    (tmp_path / "plus-tard").write_text("")
    r = _login(c, "admin", "secubox", "1").json()
    assert "access_token" in r and r.get("setup_required") is not True
    lignes = [json.loads(x) for x in (tmp_path / "audit-secubox.log").read_text().splitlines()]
    assert lignes[-1]["evenement"] == "connexion_reussie" and lignes[-1]["compte"] == "admin"
    assert "secubox\"" not in (tmp_path / "audit-secubox.log").read_text()


def test_plus_tard_ne_vaut_que_pour_admin(c, tmp_path):
    (tmp_path / "plus-tard").write_text("")
    users = tmp_path / "users.json"
    d = json.loads(users.read_text())
    d["users"].append(_compte("bob", "secubox", True))
    users.write_text(json.dumps(d))
    r = _login(c, "bob", "secubox", "1").json()
    assert r.get("setup_required") is True and "access_token" not in r


def test_depuis_le_wan_le_defaut_est_un_401_identique_mais_audite(c, tmp_path):
    (tmp_path / "plus-tard").write_text("")
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


def test_etat_vide_pour_un_non_administrateur(c):
    assert c.get("/mot-de-passe-defaut").json() == {}
    assert c.get("/mot-de-passe-defaut", headers={"Authorization": "Bearer faux"}).json() == {}


def test_etat_rendu_a_un_administrateur_reel(c, monkeypatch):
    from api import main as m

    async def admin(request, creds=None):
        return {"sub": "admin"}
    monkeypatch.setattr(m, "require_jwt", admin)
    assert c.get("/mot-de-passe-defaut").json()["etat"] == "actif"
