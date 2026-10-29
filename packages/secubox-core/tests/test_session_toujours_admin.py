# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3126 L2 tâche 7 : `session_toujours_admin(payload)` revérifie, pour une connexion longue (flux SSE), ce que require_jwt a vérifié à
l'ouverture : échéance du jeton, session vivante (jti), administrateur réel."""
import pytest

from secubox_core import auth


@pytest.fixture
def monde(monkeypatch):
    etat = {"session": True, "admin": True}
    monkeypatch.setattr(auth, "_session_validator", lambda jti: etat["session"] and jti == "j1")
    monkeypatch.setattr(auth, "est_admin_reel", lambda payload: etat["admin"])
    return etat


def payload(**kw):
    import time
    return {"sub": "alice", "jti": "j1", "exp": time.time() + 600, **kw}


def test_session_valide(monde):
    assert auth.session_toujours_admin(payload()) is True


def test_jeton_expire(monde):
    import time
    assert auth.session_toujours_admin(payload(exp=time.time() - 1)) is False
    assert auth.session_toujours_admin(payload(exp=time.time())) is False          # exp <= maintenant


def test_session_revoquee(monde):
    monde["session"] = False
    assert auth.session_toujours_admin(payload()) is False
    assert auth.session_toujours_admin(payload(jti="autre")) is False
    assert auth.session_toujours_admin({k: v for k, v in payload().items() if k != "jti"}) is False


def test_plus_administrateur(monde):
    monde["admin"] = False
    assert auth.session_toujours_admin(payload()) is False


@pytest.mark.parametrize("exp", ["demain", None, True, float("nan")])
def test_exp_illisible_refuse(monde, exp):
    p = payload()
    p["exp"] = exp
    assert auth.session_toujours_admin(p) is False


def test_jamais_d_exception(monde, monkeypatch):
    def casse(jti):
        raise RuntimeError("registre illisible")
    monkeypatch.setattr(auth, "_session_validator", casse)
    assert auth.session_toujours_admin(payload()) is False
    assert auth.session_toujours_admin(None) is False
