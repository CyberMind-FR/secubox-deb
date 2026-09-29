# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Second facteur selon le réseau (#1699) : exigé depuis le WAN, facultatif sur
le LAN. Le LAN est le verdict de nginx (X-SecuBox-LAN: 1), rien d'autre."""
import importlib
import json
from pathlib import Path

import pytest
from argon2 import PasswordHasher
from fastapi.testclient import TestClient

MDP = "GoodPass!42xyz"


def _compte(nom, role, otp):
    return {"username": nom, "email": None, "role": role, "enabled": True,
            "password_hash": PasswordHasher().hash(MDP), "must_change_password": False,
            "totp": ({"secret": "JBSWY3DPEHPK3PXP", "enabled": True, "enrolled_at": "2026-09-01T00:00:00+00:00",
                      "last_step": None, "backup_codes": []} if otp else None),
            "google": None, "services": [], "created": "2026-09-01T00:00:00+00:00", "last_login": None}


@pytest.fixture
def env(tmp_path: Path, monkeypatch):
    users = tmp_path / "users.json"
    users.write_text(json.dumps({"version": 2, "groups": [], "users": [
        _compte("gandalf", "admin", otp=True),
        _compte("neuf", "admin", otp=False),
        _compte("lecteur", "user", otp=True),
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
    return TestClient(auth_main.app), tmp_path


def _login(c, nom, lan="0"):
    # « 0 » explicite pour le WAN : secubox_core.testing fait poser
    # X-SecuBox-LAN: 1 par défaut à tout TestClient du parc.
    return c.post("/login", json={"username": nom, "password": MDP},
                  headers={"X-SecuBox-LAN": lan}).json()


def test_wan_exige_le_defi_otp(env):
    c, _ = env
    assert _login(c, "gandalf").get("mfa_required") is True


def test_lan_le_mot_de_passe_suffit_meme_enrole(env):
    c, tmp = env
    r = _login(c, "gandalf", lan="1")
    assert r.get("access_token") and not r.get("mfa_required")
    # Le journal dit que l'OTP a été sauté, et pourquoi.
    audit = [json.loads(l) for l in (tmp / "audit.log").read_text().splitlines()]
    assert any(a["event"] == "login_success" and a.get("otp") == "facultatif (LAN)" for a in audit)


def test_admin_sans_otp_wan_enrolement_force_lan_session(env):
    c, _ = env
    assert _login(c, "neuf").get("enrollment_required") is True
    assert _login(c, "neuf", lan="1").get("access_token")


def test_utilisateur_enrole_meme_regle(env):
    c, _ = env
    assert _login(c, "lecteur").get("mfa_required") is True
    assert _login(c, "lecteur", lan="1").get("access_token")


def test_verdict_lan_strict(env):
    # Seul « 1 » vaut LAN : toute autre valeur est le WAN.
    c, _ = env
    for v in ("0", "", "true", "yes", "1 "):
        r = _login(c, "gandalf", lan=v)
        if v.strip() == "1":
            continue
        assert r.get("mfa_required") is True, v


def test_reglage_obligatoire_rend_l_otp_au_lan(env):
    c, tmp = env
    (tmp / "reglages.json").write_text(json.dumps({"otp_lan": "obligatoire"}))
    assert _login(c, "gandalf", lan="1").get("mfa_required") is True
    assert _login(c, "neuf", lan="1").get("enrollment_required") is True


def test_route_reglages_admin(env):
    c, tmp = env
    jeton = _login(c, "gandalf", lan="1")["access_token"]
    h = {"Authorization": "Bearer " + jeton}
    assert c.get("/settings", headers=h).json() == {
        "otp_lan": "facultatif", "otp_wan": "obligatoire", "require_admin_totp": False}
    r = c.post("/settings", headers=h, json={"otp_lan": "obligatoire"})
    assert r.status_code == 200 and r.json()["otp_lan"] == "obligatoire"
    assert json.loads((tmp / "reglages.json").read_text()) == {"otp_lan": "obligatoire"}
    # Ancien contrat du bouton du panneau.
    assert c.post("/settings", headers=h, json={"require_admin_totp": False}).json()["otp_lan"] == "facultatif"
    assert c.post("/settings", headers=h, json={"otp_lan": "jamais"}).status_code == 400
    # Sans session : refusé.
    assert c.get("/settings").status_code == 401


def test_en_tete_absent_vaut_wan(env):
    # Hors nginx (appel direct au socket), pas de verdict : l'OTP est exigé.
    from starlette.requests import Request
    from api import main as auth_main
    sans = Request({"type": "http", "headers": []})
    avec = Request({"type": "http", "headers": [(b"x-secubox-lan", b"1")]})
    assert auth_main._otp_exige(sans) is True
    assert auth_main._otp_exige(avec) is False
