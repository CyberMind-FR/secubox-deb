# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Une action sur un compte d'administrateur est réservée à un administrateur ;
un appareil n'administre jamais le module (#1811)."""
import asyncio
import json
import os
from pathlib import Path

import pytest
from fastapi import HTTPException

import secubox_core.config as _conf
_conf._CONF_PATHS[:] = [p for p in _conf._CONF_PATHS if os.access(p, os.R_OK)] or \
    [Path(__file__).resolve().parents[5] / "secubox.conf.example"]

main = pytest.importorskip("api.main")

COMPTES = [
    {"username": "gk2", "role": "admin", "enabled": True},
    {"username": "operator", "role": "operator", "enabled": True},
    {"username": "alice", "role": "viewer", "enabled": True},
    {"username": "ancien", "role": "admin", "enabled": False},
]


class _Req:
    def __init__(self, cible):
        self.path_params = {"username": cible} if cible else {}


@pytest.fixture(autouse=True)
def comptes(tmp_path, monkeypatch):
    p = tmp_path / "users.json"
    p.write_text(json.dumps({"version": 2, "users": COMPTES, "groups": []}))
    monkeypatch.setattr(main, "load_users", lambda: json.loads(p.read_text()))
    monkeypatch.setattr(main, "load_roles", lambda: main.DEFAULT_ROLES)
    from secubox_core import appareils
    monkeypatch.setattr(appareils, "get", lambda c: {"compte": c} if c.startswith("sbx-") else None)
    monkeypatch.setattr(appareils, "profil_de", lambda c: "admin")


def _passe(permission, sujet, cible):
    dep = main.require_permission(permission)
    return asyncio.run(dep(request=_Req(cible), creds={"sub": sujet}))


@pytest.mark.parametrize("perm", ["users.password", "users.edit"])
def test_un_operateur_ne_touche_pas_a_un_administrateur(perm):
    with pytest.raises(HTTPException) as e:
        _passe(perm, "operator", "gk2")
    assert e.value.status_code == 403


def test_un_operateur_agit_sur_un_compte_ordinaire():
    assert _passe("users.password", "operator", "alice")["sub"] == "operator"


def test_un_administrateur_agit_sur_un_administrateur():
    assert _passe("users.edit", "gk2", "ancien")["sub"] == "gk2"


def test_un_administrateur_desactive_n_est_plus_administrateur():
    with pytest.raises(HTTPException):
        _passe("users.edit", "ancien", "gk2")


def test_un_appareil_au_profil_admin_n_administre_pas_le_module():
    perms = main.get_user_permissions("sbx-0123456789ab")
    assert "users.edit" not in perms and "roles.assign" not in perms
    with pytest.raises(HTTPException):
        _passe("roles.assign", "sbx-0123456789ab", "alice")


def test_la_lecture_reste_ouverte_aux_operateurs():
    assert _passe("users.view", "operator", "gk2")["sub"] == "operator"
