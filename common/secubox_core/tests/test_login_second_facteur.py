# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""La route /login heritee (montee par 47 modules) ne contourne plus le
second facteur (#1406)."""
import json
from pathlib import Path

import pytest
from argon2 import PasswordHasher
from fastapi import HTTPException, Response
from starlette.requests import Request

from secubox_core import auth, user_store

MDP = "GoodPass!42xyz"


def _app(tmp_path: Path, monkeypatch, **champs):
    base = {"username": "alice", "email": "a@b.c", "role": "operator", "enabled": True,
            "password_hash": PasswordHasher().hash(MDP), "must_change_password": False,
            "totp": None, "google": None, "services": [],
            "created": "2026-05-13T00:00:00+00:00", "last_login": None}
    base.update(champs)
    p = tmp_path / "users.json"
    p.write_text(json.dumps({"version": 2, "users": [base], "groups": []}))
    monkeypatch.setattr(user_store, "USERS_PATH", p)
    monkeypatch.setenv("SECUBOX_JWT_SECRET", "test-secret-do-not-use-in-prod-please")
    monkeypatch.setattr(auth, "_emit_session_event", lambda *a, **k: None)
    # Le domaine du cookie se lit dans /etc/secubox : hors sujet ici.
    monkeypatch.setattr(auth, "set_session_cookie",
                        lambda rep, tok, **k: rep.set_cookie("secubox_session", tok))
    return None


def _login(_c, mdp=MDP):
    """Appelle la route directement ; rend (code, corps, set-cookie)."""
    import asyncio
    req = Request({"type": "http", "method": "POST", "path": "/auth/login",
                   "headers": [], "client": ("192.0.2.1", 1234)})
    rep = Response()
    try:
        out = asyncio.run(auth.login(auth.LoginRequest(username="alice", password=mdp), req, rep))
        return 200, out.access_token, rep.headers.get("set-cookie", "")
    except HTTPException as e:
        return e.status_code, str(e.detail), rep.headers.get("set-cookie", "")


@pytest.mark.parametrize("champs", [
    {"totp": {"enabled": True, "secret": "JBSWY3DPEHPK3PXP"}},
    {"role": "admin"},
    {"must_change_password": True},
])
def test_refus_si_second_facteur_requis(tmp_path, monkeypatch, champs):
    code, corps, cookie = _login(_app(tmp_path, monkeypatch, **champs))
    assert code == 403
    assert "secubox_session" not in cookie


def test_compte_sans_second_facteur_passe_toujours(tmp_path, monkeypatch):
    code, jeton, cookie = _login(_app(tmp_path, monkeypatch))
    assert code == 200 and jeton and "secubox_session" in cookie


def test_mauvais_mot_de_passe_ne_revele_pas_le_second_facteur(tmp_path, monkeypatch):
    code, _, _ = _login(_app(tmp_path, monkeypatch, role="admin"), "mauvais")
    assert code == 401
