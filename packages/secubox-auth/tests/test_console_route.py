# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Route de la console locale (#1695) : une vraie session d'administrateur pour
le kiosque, et rien pour personne d'autre — ni par la route, ni par /login."""
import importlib
import json
from pathlib import Path

import pytest
from argon2 import PasswordHasher
from fastapi.testclient import TestClient

from test_console import ENTETE, KIOSQUE, _ligne, _v4

PAIRE = "127.0.0.1:54321"


@pytest.fixture
def env(tmp_path: Path, monkeypatch):
    users = tmp_path / "users.json"
    users.write_text(json.dumps({"version": 2, "groups": [], "users": [{
        "username": "admin", "email": "a@b.c", "role": "admin", "enabled": True,
        "password_hash": PasswordHasher().hash("GoodPass!42xyz"), "must_change_password": False,
        "totp": None, "google": None, "services": [], "created": "2026-05-13T00:00:00+00:00",
        "last_login": None}]}))
    sessions = tmp_path / "sessions.json"
    sessions.write_text("[]")
    (tmp_path / "totp-pending.json").write_text("{}")
    for k, v in {"USERS_FILE": users, "SECUBOX_AUTH_DATA_DIR": tmp_path,
                 "SECUBOX_AUTH_SESSIONS": sessions, "SECUBOX_AUTH_AUDIT": tmp_path / "audit.log",
                 "SECUBOX_AUTH_TOTP_PENDING": tmp_path / "totp-pending.json",
                 "SECUBOX_AUTH_RUNTIME": tmp_path / "auth-runtime.json"}.items():
        monkeypatch.setenv(k, str(v))
    monkeypatch.setenv("SECUBOX_JWT_SECRET", "test-secret")
    from secubox_core import config as sbx_config, user_store
    monkeypatch.setattr(sbx_config, "_CONF_PATHS", [])
    monkeypatch.setattr(sbx_config, "_CONFIG", None)
    monkeypatch.setattr(user_store, "USERS_PATH", users)

    net = tmp_path / "proc" / "net"
    net.mkdir(parents=True)
    (net / "tcp").write_text(ENTETE + _ligne(1, _v4("127.0.0.1", 54321), _v4("127.0.0.1", 9078), KIOSQUE))
    (net / "tcp6").write_text(ENTETE)
    secret = tmp_path / "console.key"
    secret.write_text("s3cret\n")

    from api import main as auth_main
    importlib.reload(auth_main)
    from api import console
    monkeypatch.setattr(console, "PROC", tmp_path / "proc")
    monkeypatch.setattr(console, "SECRET", secret)
    monkeypatch.setattr(console, "uid_kiosque", lambda nom=console.COMPTE_KIOSQUE: KIOSQUE)
    return TestClient(auth_main.app), users, sessions


def _demande(c, **entetes):
    h = {"x-secubox-console": "s3cret", "x-secubox-console-paire": PAIRE,
         "x-secubox-console-hote": "hall.localhost"}
    h.update(entetes)
    return c.get("/console/jeton", headers=h)


def test_le_kiosque_obtient_une_session_d_administrateur(env):
    c, users, sessions = env
    r = _demande(c)
    assert r.status_code == 200, r.text
    corps = r.json()
    assert corps["compte"] == "console" and corps["access_token"]

    u = next(u for u in json.loads(users.read_text())["users"] if u["username"] == "console")
    # Le compte dédié : admin, actif, mot de passe aléatoire posé — jamais « à définir ».
    assert u["role"] == "admin" and u["enabled"] and u["password_hash"]
    assert u["must_change_password"] is False
    # Une session ordinaire, inscrite, donc visible et révocable.
    assert any(s["username"] == "console" for s in json.loads(sessions.read_text()))
    # Et elle ouvre l'administration (require_jwt = administrateur réel).
    r = c.get("/sessions", headers={"Authorization": "Bearer " + corps["access_token"]})
    assert r.status_code == 200, r.text


def test_une_session_par_demi_journee_pas_une_par_page(env):
    c, _, sessions = env
    a, b = _demande(c).json(), _demande(c).json()
    assert a["access_token"] == b["access_token"]
    assert sum(s["username"] == "console" for s in json.loads(sessions.read_text())) == 1


def test_sans_le_secret_rien_n_est_cree(env):
    c, users, sessions = env
    r = _demande(c, **{"x-secubox-console": "devine"})
    assert r.status_code == 403
    assert all(u["username"] != "console" for u in json.loads(users.read_text())["users"])
    assert json.loads(sessions.read_text()) == []


def test_rebond_dns_refuse(env):
    c, _, _ = env
    assert _demande(c, **{"x-secubox-console-hote": "evil.example"}).status_code == 403
    # Host seul ne compte plus : l'agrégateur le réécrit en relayant.
    assert _demande(c, **{"x-secubox-console-hote": ""}).status_code == 403
    assert _demande(c, origin="http://evil.example:9078").status_code == 403


def test_le_compte_console_n_entre_jamais_par_mot_de_passe(env):
    c, _, _ = env
    _demande(c)  # le compte existe désormais
    # Ni la branche de première configuration (mot de passe vide)…
    r = c.post("/auth/login", json={"username": "console", "password": ""})
    assert r.status_code == 401 and "setup_token" not in r.text
    # … ni un mot de passe quelconque.
    assert c.post("/auth/login", json={"username": "console", "password": "x"}).status_code == 401


def test_compte_desactive_coupe_la_console(env):
    c, users, _ = env
    _demande(c)
    doc = json.loads(users.read_text())
    for u in doc["users"]:
        if u["username"] == "console":
            u["enabled"] = False
    users.write_text(json.dumps(doc))
    from api import main as auth_main
    auth_main._console_session.update(jeton=None)
    assert _demande(c).status_code == 403
