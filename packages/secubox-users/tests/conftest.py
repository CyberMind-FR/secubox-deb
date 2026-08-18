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
