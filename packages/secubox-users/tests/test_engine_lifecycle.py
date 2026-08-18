# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Engine lifecycle: create/enable/disable/list."""
import json
import re
from pathlib import Path

import pytest

from api import engine


@pytest.fixture
def store(tmp_path: Path):
    p = tmp_path / "users.json"
    p.write_text(json.dumps({"version": 2, "users": [], "groups": []}))
    return engine.Engine(users_path=p)


def test_create_user_succeeds(store: engine.Engine):
    u = store.create_user("alice", email="a@b.c", role="operator")
    assert u["username"] == "alice"
    assert u["role"] == "operator"
    assert u["enabled"] is True
    assert u["must_change_password"] is True
    assert u["password_hash"] is None
    assert u["totp"] is None


def test_create_user_rejects_bad_username(store: engine.Engine):
    with pytest.raises(engine.EngineError, match="username"):
        store.create_user("Bad Name!", email="x@y.z", role="viewer")


def test_create_user_rejects_duplicate(store: engine.Engine):
    store.create_user("alice", email="a@b.c", role="viewer")
    with pytest.raises(engine.EngineError, match="exists"):
        store.create_user("alice", email="other@b.c", role="viewer")


def test_disable_calls_revoke_callback(store: engine.Engine):
    store.create_user("alice", email="a@b.c", role="viewer")
    calls = []
    store.set_revoke_callback(lambda name: calls.append(name) or 0)
    store.disable_user("alice")
    assert calls == ["alice"]
    assert store.get_user("alice")["enabled"] is False


def test_enable_restores_flag(store: engine.Engine):
    store.create_user("alice", email="a@b.c", role="viewer")
    store.disable_user("alice")
    store.enable_user("alice")
    assert store.get_user("alice")["enabled"] is True


def test_list_users_returns_all(store: engine.Engine):
    store.create_user("ada", email="a@x.y", role="viewer")
    store.create_user("bob", email="b@x.y", role="viewer")
    names = sorted(u["username"] for u in store.list_users())
    assert names == ["ada", "bob"]


def test_atomic_write_does_not_corrupt_on_failure(tmp_path: Path, monkeypatch):
    p = tmp_path / "users.json"
    p.write_text(json.dumps({"version": 2, "users": [], "groups": []}))
    eng = engine.Engine(users_path=p)
    eng.create_user("alice", email="a@b.c", role="viewer")

    # Force os.replace to raise and make sure the original file is preserved.
    import api.engine as engmod
    real_replace = engmod.os.replace
    def boom(src, dst):
        raise OSError("simulated")
    monkeypatch.setattr(engmod.os, "replace", boom)
    with pytest.raises(OSError):
        eng.create_user("bob", email="b@x.y", role="viewer")
    monkeypatch.setattr(engmod.os, "replace", real_replace)

    doc = json.loads(p.read_text())
    assert [u["username"] for u in doc["users"]] == ["alice"]
