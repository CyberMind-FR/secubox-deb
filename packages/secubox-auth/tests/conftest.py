# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Shared fixtures for secubox-auth integration tests."""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "common"))
# secubox-users must be reachable for the engine/totp modules, but secubox-auth's
# own api/ package must take priority for `from api import …` in auth tests.
# Insert auth LAST so it lands at index 0 (highest priority).
sys.path.insert(0, str(ROOT / "packages" / "secubox-users"))
sys.path.insert(0, str(ROOT / "packages" / "secubox-auth"))


@pytest.fixture
def auth_data_dir(tmp_path: Path) -> Path:
    """Stand-in for /var/lib/secubox/auth/."""
    d = tmp_path / "auth"
    d.mkdir(exist_ok=True)
    (d / "sessions.json").write_text("[]")
    (d / "audit.log").write_text("")
    return d


@pytest.fixture
def env_files(tmp_path: Path, monkeypatch) -> dict:
    """Set env vars so modules pick up tempdir paths."""
    users = tmp_path / "users.json"
    users.write_text(json.dumps({"version": 2, "users": [], "groups": []}))
    monkeypatch.setenv("USERS_FILE", str(users))
    monkeypatch.setenv("SECUBOX_AUTH_DATA_DIR", str(tmp_path / "auth"))
    (tmp_path / "auth").mkdir(exist_ok=True)
    return {"users": users, "data_dir": tmp_path / "auth"}
