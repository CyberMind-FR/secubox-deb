# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Add the package's api/ directory and common/ to sys.path for tests."""
import sys
from pathlib import Path

# Add the secubox-haproxy package root
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# Add the common/ directory which contains secubox_core
repo_root = Path(__file__).resolve().parents[3]  # Go up from tests/ -> .. -> .. -> ..
sys.path.insert(0, str(repo_root / "common"))

# Le harnais represente un client de tableau de bord LAN (#1256) : mode arme +
# en-tete LAN. `require_jwt` n'est PAS satisfait pour autant — les tests qui
# verifient un refus continuent de le voir.
#
# IMPORT TOLERANT, ET C'EST INDISPENSABLE. `secubox_core.testing` tire
# `secubox_core/__init__` qui tire `auth` qui tire **fastapi**. Or plusieurs
# jobs CI n'installent que pytest pour lancer une suite qui n'a rien d'une API
# (`scripts/tests/test_check_dashboard_cache.py`) : un import dur y fait
# echouer le CHARGEMENT DU CONFTEST, donc toute la suite, sur un
# ModuleNotFoundError qui ne dit rien du vrai sujet. C'est exactement ce qui
# est arrive au premier passage de ce fichier en CI.
#
# Sans fastapi il n'y a de toute facon aucune application a armer : on passe.
try:  # noqa: SIM105
    from secubox_core.testing import active_mode_tableau_de_bord as _sbx_tdb

    _sbx_tdb()
except ImportError:
    pass


# #3401 : la garde d exposition est fail-closed (users.json absent = état inconnu = refus). Par défaut, les tests
# tournent sur une box au mot de passe admin CHANGÉ ; les tests #3401 posent leur propre users.json.
import json as _json_3401  # noqa: E402 — bloc #3401 ajouté en fin de fichier

import pytest as _pytest_3401  # noqa: E402
from argon2 import PasswordHasher as _PH_3401  # noqa: E402

_EMPREINTE_CHANGEE_3401 = _PH_3401().hash("une phrase longue et choisie")


@_pytest_3401.fixture(autouse=True)
def _mot_de_passe_admin_change_3401(tmp_path_factory, monkeypatch):
    d = tmp_path_factory.mktemp("users3401")
    (d / "users.json").write_text(_json_3401.dumps({"users": [{"username": "admin", "password_hash": _EMPREINTE_CHANGEE_3401}]}))
    monkeypatch.setenv("SECUBOX_USERS_JSON", str(d / "users.json"))
    monkeypatch.setenv("SECUBOX_AUDIT_LOG", str(d / "audit.log"))
