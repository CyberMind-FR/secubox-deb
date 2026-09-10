# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Shared fixtures for secubox-users unit tests."""
import json
import sys
from pathlib import Path

import pytest

# Make both `secubox_core` and the package's own api/ importable.
ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "common"))
sys.path.insert(0, str(ROOT / "packages" / "secubox-users"))


@pytest.fixture
def tmp_users_json(tmp_path: Path) -> Path:
    """Empty v2 users.json (no users yet)."""
    path = tmp_path / "users.json"
    path.write_text(json.dumps({"version": 2, "users": [], "groups": []}))
    return path


@pytest.fixture
def tmp_sessions_json(tmp_path: Path) -> Path:
    """Empty sessions.json."""
    path = tmp_path / "sessions.json"
    path.write_text("[]")
    return path


@pytest.fixture(autouse=True)
def _isolate_totp_replay_store(tmp_path, monkeypatch):
    """Isole l'etat d'anti-rejeu TOTP (#990).

    Sans ca, tout Engine construit sans replay_path explicite ecrit dans
    /var/lib/secubox/totp-replay.json — un fichier SYSTEME partage. Constate en
    ecrivant le correctif : un test existant s'est mis a echouer parce qu'un run
    precedent y avait laisse une entree pour le meme utilisateur. Un etat qui
    fuit d'un test a l'autre rend la suite dependante de la machine.
    """
    monkeypatch.setenv("SECUBOX_TOTP_REPLAY_PATH",
                       str(tmp_path / "totp-replay.json"))

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
