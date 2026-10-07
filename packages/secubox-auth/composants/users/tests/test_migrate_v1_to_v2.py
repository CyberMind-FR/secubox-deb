# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Migrate v1 users.json + auth.toml [users.*] → v2."""
import json
from pathlib import Path

import pytest

from api import migrate_v1_to_v2 as M


def _v1_doc():
    return {
        "admin": {
            "password_hash": "deadbeef" * 8,
            "email": "old@local",
            "role": "admin",
            "created": "2026-04-01T00:00:00+00:00",
        },
        "users": [
            {
                "username": "admin",
                "email": "gandalf@gk2.net",
                "enabled": True,
                "services": [],
                "created": "2026-05-09T11:14:11.719355",
                "provision_results": {},
            }
        ],
    }


def test_migrate_discards_sha256_hash_and_forces_must_change(tmp_path: Path):
    p = tmp_path / "users.json"
    p.write_text(json.dumps(_v1_doc()))
    M.migrate(p, auth_toml_path=None)
    doc = json.loads(p.read_text())
    assert doc["version"] == 2
    assert len(doc["users"]) == 1
    u = doc["users"][0]
    assert u["username"] == "admin"
    assert u["password_hash"] is None
    assert u["must_change_password"] is True
    assert u["role"] == "admin"
    assert u["email"] == "gandalf@gk2.net"  # array wins over legacy


def test_migrate_snapshots_before_rewriting(tmp_path: Path):
    """A snapshot must exist before the store is rewritten.

    Was `test_migrate_creates_v1_bak`, asserting a FIXED `users.json.v1.bak`.
    That fixed name is the defect #945 fixes: a second migration overwrote the
    only good copy with the already-damaged file. The snapshot is now
    timestamped, so every run leaves its own recoverable copy.
    """
    p = tmp_path / "users.json"
    original = json.dumps(_v1_doc())
    p.write_text(original)
    M.migrate(p, auth_toml_path=None)

    snaps = list(tmp_path.glob("users.json.pre-migrate.*"))
    assert len(snaps) == 1
    assert json.loads(snaps[0].read_text()) == json.loads(original)


def test_migrate_is_idempotent(tmp_path: Path):
    p = tmp_path / "users.json"
    p.write_text(json.dumps(_v1_doc()))
    M.migrate(p, auth_toml_path=None)
    first = p.read_text()
    M.migrate(p, auth_toml_path=None)  # second run — no-op
    assert p.read_text() == first


def test_migrate_pulls_auth_toml_users(tmp_path: Path):
    p = tmp_path / "users.json"
    p.write_text(json.dumps({"version": 2, "users": [], "groups": []}))
    toml = tmp_path / "auth.toml"
    toml.write_text(
        '[users.admin]\n'
        'password = "secubox"\n'
        'email = "admin@gk2.net"\n'
        'role = "admin"\n'
    )
    M.migrate(p, auth_toml_path=toml)
    doc = json.loads(p.read_text())
    u = next(x for x in doc["users"] if x["username"] == "admin")
    assert u["password_hash"] is None
    assert u["must_change_password"] is True
