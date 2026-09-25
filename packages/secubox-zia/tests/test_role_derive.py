# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""#1411 — le rôle ZIA se DÉRIVE de la session ; le corps ne peut que restreindre."""
import asyncio
import os
from pathlib import Path

import pytest

import secubox_core.config as _conf
_conf._CONF_PATHS[:] = [p for p in _conf._CONF_PATHS if os.access(p, os.R_OK)] or \
    [Path(__file__).resolve().parents[3] / "secubox.conf.example"]

main = pytest.importorskip("api.main")
from fastapi import HTTPException  # noqa: E402
from starlette.requests import Request  # noqa: E402
from secubox_core import auth, user_store, appareils  # noqa: E402


def _req(jeton=None):
    h = [(b"authorization", f"Bearer {jeton}".encode())] if jeton else []
    return Request({"type": "http", "method": "POST", "path": "/", "headers": h})


@pytest.fixture
def porteurs(monkeypatch):
    comptes = {"gk2": {"role": "admin"}, "op": {"role": "operator"}}
    monkeypatch.setattr(auth, "_validate_token", lambda t: {"sub": t} if t != "faux" else None)
    monkeypatch.setattr(user_store, "get_user", lambda s: comptes.get(s))
    monkeypatch.setattr(appareils, "profil_de", lambda s: {"sbx-a": "admin", "sbx-u": "user"}.get(s, "guest"))


@pytest.mark.parametrize("jeton,attendu", [
    (None, "guest"), ("faux", "guest"), ("gk2", "admin"), ("op", "member"),
    ("sbx-a", "admin"), ("sbx-u", "member"), ("sbx-g", "registered"),
])
def test_role_derive_de_la_session(porteurs, jeton, attendu):
    assert main._role_du_porteur(_req(jeton)) == attendu


def test_le_corps_ne_peut_que_restreindre(porteurs):
    assert main._role_effectif(_req(None), "admin") == "guest"      # l'ancienne faille
    assert main._role_effectif(_req("sbx-g"), "admin") == "registered"
    assert main._role_effectif(_req("gk2"), "guest") == "guest"     # se restreindre : permis
    assert main._role_effectif(_req("gk2"), "n'importe") == "admin"


def test_config_reservee_aux_admins(porteurs):
    with pytest.raises(HTTPException) as e:
        asyncio.run(main.exige_admin(_req("op")))
    assert e.value.status_code == 403
    asyncio.run(main.exige_admin(_req("gk2")))                        # passe
