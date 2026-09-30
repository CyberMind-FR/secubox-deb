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
                 "SECUBOX_AUTH_REGLAGES": tmp_path / "reglages.json"}.items():
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
    r = _login(c, "admin", "secubox", "1").json()
    assert r.get("setup_required") is True and "access_token" not in r


def test_depuis_le_wan_le_mot_de_passe_par_defaut_ne_sert_a_rien(c):
    r = _login(c, "admin", "secubox", "0")
    assert r.status_code == 401 and "setup_token" not in r.text
