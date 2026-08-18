# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Engine password operations."""
import json
from pathlib import Path

import pytest

from api import engine, password_policy


@pytest.fixture(autouse=True)
def _empty_wordlist(tmp_path: Path, monkeypatch):
    w = tmp_path / "empty.txt"
    w.write_text("")
    monkeypatch.setattr(password_policy, "COMMON_PASSWORDS_PATH", w)
    password_policy._cache.clear()


@pytest.fixture
def store(tmp_path: Path):
    p = tmp_path / "users.json"
    p.write_text(json.dumps({"version": 2, "users": [], "groups": []}))
    eng = engine.Engine(users_path=p)
    eng.create_user("alice", email="a@b.c", role="viewer")
    return eng


def test_set_password_hashes_and_clears_must_change(store: engine.Engine):
    store.set_password("alice", "GoodPass!42xyz")
    u = store.get_user("alice")
    assert u["password_hash"].startswith("$argon2id$")
    assert u["must_change_password"] is False


def test_set_password_rejects_weak(store: engine.Engine):
    with pytest.raises(password_policy.PolicyError):
        store.set_password("alice", "weak")


def test_clear_password_resets_must_change(store: engine.Engine):
    store.set_password("alice", "GoodPass!42xyz")
    store.clear_password("alice")
    u = store.get_user("alice")
    assert u["password_hash"] is None
    assert u["must_change_password"] is True


def test_verify_password_for_user(store: engine.Engine):
    store.set_password("alice", "GoodPass!42xyz")
    assert store.verify_password_for_user("alice", "GoodPass!42xyz") is True
    assert store.verify_password_for_user("alice", "wrong") is False


def test_verify_password_for_user_unknown(store: engine.Engine):
    assert store.verify_password_for_user("ghost", "anything") is False
