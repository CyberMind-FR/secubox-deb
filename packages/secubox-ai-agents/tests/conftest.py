# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Tests de secubox-ai-agents (#3986).

Ils tournent avec le Python de l'environnement dédié (`/opt/secubox-ai-agents/venv/bin/python -m pytest`,
pytest fourni à part par `--with`/PYTHONPATH) ou n'importe quel venv qui contient OpenJarvis. Pas de faux
moteur : les tests de conversation parlent au VRAI llama-server (`SECUBOX_AI_AGENTS_MOTEUR`) et sont sautés,
en le disant, quand il est absent.
"""
import os
import secrets
import sys
from pathlib import Path

import pytest

PAQUET = Path(__file__).resolve().parents[1]
RACINE = PAQUET.parents[1]
if str(PAQUET) not in sys.path:
    sys.path.insert(0, str(PAQUET))

MOTEUR = os.environ.get("SECUBOX_AI_AGENTS_MOTEUR", str(Path.home() / "poc-secubox-ai/run/llama.sock"))


@pytest.fixture
def jeton(tmp_path, monkeypatch):
    j = tmp_path / "jeton"
    j.write_text(secrets.token_urlsafe(32))
    j.chmod(0o600)
    monkeypatch.setenv("SECUBOX_AI_AGENTS_GARDE", "jeton-local")
    monkeypatch.setenv("SECUBOX_AI_AGENTS_JETON", str(j))
    monkeypatch.setenv("SECUBOX_AI_AGENTS_ETAT", str(tmp_path / "etat"))
    monkeypatch.setenv("SECUBOX_AI_AGENTS_MOTEUR", MOTEUR)
    monkeypatch.setenv("OPENJARVIS_HOME", str(tmp_path / "oj"))
    monkeypatch.setenv("OPENJARVIS_NO_UPDATE_CHECK", "1")
    return j.read_text()


@pytest.fixture
def client(jeton):
    import importlib

    from fastapi.testclient import TestClient

    import agents.app as module
    module = importlib.reload(module)  # la garde est construite à l'import, avec l'environnement du test
    with TestClient(module.app) as c:
        c.headers["Authorization"] = f"Bearer {jeton}"
        yield c


def moteur_present() -> bool:
    return Path(MOTEUR).is_socket()
