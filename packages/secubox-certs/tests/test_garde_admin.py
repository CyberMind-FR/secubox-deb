# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Émettre, renouveler, révoquer : réservé aux admins (#942, #1749).

La garde posée par #942 a été effacée une fois par une fusion (aff481735)
sans qu'aucun test ne proteste. Ceux-ci protestent : un compte ordinaire
reçoit 403 sur chaque verbe qui change les certificats, un admin passe la
garde, et la lecture reste ouverte à toute session.
"""
import sys
from pathlib import Path

import pytest

RACINE = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(RACINE / "common"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient  # noqa: E402

import api.main as M  # noqa: E402
from secubox_core import user_store  # noqa: E402

MUTATIONS = [
    ("post", "/issue", {"domain": "exemple.invalid"}),
    ("post", "/renew/exemple.invalid", None),
    ("post", "/renew-all", None),
    ("delete", "/revoke/exemple.invalid", None),
]


@pytest.fixture
def client_en_tant_que(monkeypatch):
    def fabrique(role, enabled=True):
        M.app.dependency_overrides[M.require_jwt] = lambda: {"sub": "quelquun"}
        monkeypatch.setattr(user_store, "get_user",
                            lambda sub: {"username": sub, "role": role, "enabled": enabled})
        return TestClient(M.app)
    yield fabrique
    M.app.dependency_overrides.clear()


@pytest.mark.parametrize("verbe,chemin,corps", MUTATIONS)
def test_compte_ordinaire_refuse(client_en_tant_que, verbe, chemin, corps):
    c = client_en_tant_que("user")
    r = getattr(c, verbe)(chemin, **({"json": corps} if corps else {}))
    assert r.status_code == 403, (chemin, r.status_code, r.text)


@pytest.mark.parametrize("verbe,chemin,corps", MUTATIONS)
def test_admin_desactive_refuse(client_en_tant_que, verbe, chemin, corps):
    c = client_en_tant_que("admin", enabled=False)
    r = getattr(c, verbe)(chemin, **({"json": corps} if corps else {}))
    assert r.status_code == 403, (chemin, r.status_code)


@pytest.mark.parametrize("verbe,chemin,corps", MUTATIONS)
def test_admin_passe_la_garde(client_en_tant_que, monkeypatch, verbe, chemin, corps):
    # Rien ne doit réellement s'exécuter : on coupe les effets et on ne
    # regarde que la garde (tout sauf 401/403).
    monkeypatch.setattr(M.subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("coupé")))
    c = client_en_tant_que("admin")
    try:
        r = getattr(c, verbe)(chemin, **({"json": corps} if corps else {}))
        code = r.status_code
    except RuntimeError:
        code = 500  # la garde est passée, l'effet coupé a levé
    assert code not in (401, 403), (chemin, code)


def test_lecture_ouverte_a_toute_session(client_en_tant_que):
    c = client_en_tant_que("user")
    r = c.get("/list")
    assert r.status_code not in (401, 403), r.status_code
