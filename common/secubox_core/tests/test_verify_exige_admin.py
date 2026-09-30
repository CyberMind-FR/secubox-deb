# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""`/auth/verify?exige=admin` : la garde d'administration déléguée à nginx (#1783).

Un service qui ne peut pas lire le secret JWT (il tourne sous son propre
compte) fait trancher nginx par `auth_request` sur cette route. Sans le
paramètre, toute session valide passe (SSO-lite, inchangé) ; avec, seul un
administrateur réel — le prédicat de require_jwt.
"""
import json
from pathlib import Path

import pytest
from argon2 import PasswordHasher
from fastapi import HTTPException

from secubox_core import auth, user_store


def _ecrire_comptes(p: Path, *comptes):
    base = {
        "email": "a@b.c", "enabled": True,
        "password_hash": PasswordHasher().hash("GoodPass!42xyz"),
        "must_change_password": False, "totp": None, "google": None,
        "services": [], "created": "2026-05-13T00:00:00+00:00", "last_login": None,
    }
    p.write_text(json.dumps({"version": 2, "groups": [],
                             "users": [{**base, **c} for c in comptes]}))


@pytest.fixture
def comptes(tmp_path: Path, monkeypatch):
    p = tmp_path / "users.json"
    _ecrire_comptes(p, {"username": "admin", "role": "admin"},
                    {"username": "alice", "role": "user"})
    monkeypatch.setattr(user_store, "USERS_PATH", p)
    monkeypatch.setattr(auth, "get_config", lambda section: {})
    monkeypatch.setenv("SECUBOX_JWT_SECRET", "test-secret-do-not-use-in-prod-please")
    monkeypatch.setattr(auth, "_session_validator", lambda jti: True)
    yield


class _Req:
    def __init__(self, jeton, **params):
        self.cookies = {auth.SESSION_COOKIE: jeton}
        self.headers = {}
        self.query_params = params


@pytest.mark.asyncio
async def test_un_admin_passe_la_garde(comptes):
    r = await auth.verify(_Req(auth.create_token("admin", jti="j1"), exige="admin"))
    assert r.status_code == 200
    assert r.headers["Remote-User"] == "admin"


@pytest.mark.asyncio
async def test_un_usager_est_refuse_quand_admin_exige(comptes):
    with pytest.raises(HTTPException) as exc:
        await auth.verify(_Req(auth.create_token("alice", jti="j2"), exige="admin"))
    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_sans_exigence_la_session_suffit_toujours(comptes):
    """Le SSO-lite des autres vhosts ne change pas."""
    r = await auth.verify(_Req(auth.create_token("alice", jti="j3")))
    assert r.status_code == 200
