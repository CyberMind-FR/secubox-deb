# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Montage commun des tests."""


# #3401 : la garde d exposition est fail-closed (users.json absent = état inconnu = refus). Par défaut, les tests
# tournent sur une box au mot de passe admin CHANGÉ ; les tests #3401 posent leur propre users.json.
import json as _json_3401

import pytest as _pytest_3401
from argon2 import PasswordHasher as _PH_3401

_EMPREINTE_CHANGEE_3401 = _PH_3401().hash("une phrase longue et choisie")


@_pytest_3401.fixture(autouse=True)
def _mot_de_passe_admin_change_3401(tmp_path_factory, monkeypatch):
    d = tmp_path_factory.mktemp("users3401")
    (d / "users.json").write_text(_json_3401.dumps({"users": [{"username": "admin", "password_hash": _EMPREINTE_CHANGEE_3401}]}))
    monkeypatch.setenv("SECUBOX_USERS_JSON", str(d / "users.json"))
    monkeypatch.setenv("SECUBOX_AUDIT_LOG", str(d / "audit.log"))
