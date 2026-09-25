# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""#1414 — le coffre n'est ouvert qu'aux administrateurs système."""
import asyncio
import os
import sys
from pathlib import Path

import pytest

RACINE = Path(__file__).resolve().parents[3]
sys.path[:0] = [str(RACINE / "common"), str(RACINE / "packages" / "secubox-vault")]
import secubox_core.config as _conf  # noqa: E402
_conf._CONF_PATHS[:] = [p for p in _conf._CONF_PATHS if os.access(p, os.R_OK)] or [RACINE / "secubox.conf.example"]
main = pytest.importorskip("api.main")
from fastapi import HTTPException  # noqa: E402
from secubox_core import user_store, auth  # noqa: E402


@pytest.fixture
def comptes(monkeypatch):
    c = {"gk2": {"role": "admin", "enabled": True}, "operator": {"role": "operator"},
         "ancien": {"role": "admin", "enabled": False}}
    monkeypatch.setattr(user_store, "get_user", lambda s: c.get(s))


@pytest.mark.parametrize("sub,passe", [("gk2", True), ("operator", False), ("sbx-4a56a1f0", False),
                                       ("ancien", False), ("", False)])
def test_seul_un_admin_systeme_ouvre_le_coffre(comptes, sub, passe):
    try:
        asyncio.run(main.require_admin_systeme({"sub": sub}))
        assert passe
    except HTTPException as e:
        assert not passe and e.status_code == 403


def test_aucune_route_au_seul_jwt():
    for r in main.app.routes:
        if hasattr(r, "dependant") and r.path != "/health":
            assert auth.require_jwt not in [d.call for d in r.dependant.dependencies], r.path
