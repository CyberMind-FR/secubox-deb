# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Engine TOTP operations."""
import json
import time
from pathlib import Path

import pyotp
import pytest

from api import engine, totp


@pytest.fixture
def store(tmp_path: Path):
    p = tmp_path / "users.json"
    p.write_text(json.dumps({"version": 2, "users": [], "groups": []}))
    eng = engine.Engine(users_path=p)
    eng.create_user("alice", email="a@b.c", role="admin")
    return eng


def test_enroll_totp_persists_secret_and_10_codes(store: engine.Engine):
    secret = totp.generate_secret()
    backup_plain = store.enroll_totp("alice", secret)
    assert len(backup_plain) == 10
    u = store.get_user("alice")
    assert u["totp"]["enabled"] is True
    assert u["totp"]["secret"] == secret
    assert len(u["totp"]["backup_codes"]) == 10
    assert all(bc["used_at"] is None for bc in u["totp"]["backup_codes"])
    assert all(bc["hash"].startswith("$argon2id$") for bc in u["totp"]["backup_codes"])


def test_verify_totp_for_user_accepts_current(store: engine.Engine):
    secret = totp.generate_secret()
    store.enroll_totp("alice", secret)
    code = pyotp.TOTP(secret).now()
    ok = store.verify_totp_for_user("alice", code)
    assert ok is True


def test_verify_totp_refuses_replay(store: engine.Engine):
    secret = totp.generate_secret()
    store.enroll_totp("alice", secret)
    code = pyotp.TOTP(secret).now()
    assert store.verify_totp_for_user("alice", code) is True
    assert store.verify_totp_for_user("alice", code) is False  # replay


def test_consume_backup_code_marks_used_once(store: engine.Engine):
    secret = totp.generate_secret()
    backup = store.enroll_totp("alice", secret)
    code = backup[0]
    assert store.consume_backup_code("alice", code) is True
    assert store.consume_backup_code("alice", code) is False  # already used


def test_disable_totp_removes_block(store: engine.Engine):
    secret = totp.generate_secret()
    store.enroll_totp("alice", secret)
    store.disable_totp("alice")
    u = store.get_user("alice")
    assert u["totp"] is None


def test_regenerate_backup_codes(store: engine.Engine):
    secret = totp.generate_secret()
    old = store.enroll_totp("alice", secret)
    new = store.regenerate_backup_codes("alice")
    assert len(new) == 10
    assert set(new).isdisjoint(set(old))
    u = store.get_user("alice")
    assert len(u["totp"]["backup_codes"]) == 10
