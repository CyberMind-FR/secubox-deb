# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Shared fixtures for secubox_core unit tests."""
import json
import os
import sys
from pathlib import Path

import pytest

# Make common/secubox_core importable from tests without installing the package.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


@pytest.fixture
def tmp_users_json(tmp_path: Path) -> Path:
    """A fresh v2 users.json with one admin user (no hash, must_change=true)."""
    path = tmp_path / "users.json"
    path.write_text(json.dumps({
        "version": 2,
        "users": [
            {
                "username": "admin",
                "email": "admin@example.local",
                "role": "admin",
                "enabled": True,
                "password_hash": None,
                "must_change_password": True,
                "totp": None,
                "google": None,
                "services": [],
                "created": "2026-05-13T00:00:00+00:00",
                "last_login": None,
            }
        ],
        "groups": [],
    }, indent=2))
    return path


@pytest.fixture
def tmp_auth_toml(tmp_path: Path) -> Path:
    """A legacy auth.toml with one fallback admin (plaintext)."""
    path = tmp_path / "auth.toml"
    path.write_text(
        '[users.admin]\n'
        'password = "fallbackonly"\n'
        'email = "admin@example.local"\n'
        'role = "admin"\n'
    )
    return path
