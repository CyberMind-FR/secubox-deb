# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Engine session-side methods."""
import json
from pathlib import Path

import pytest

from api import engine


@pytest.fixture
def store(tmp_path: Path):
    p = tmp_path / "users.json"
    p.write_text(json.dumps({"version": 2, "users": [], "groups": []}))
    eng = engine.Engine(users_path=p)
    eng.create_user("alice", email="a@b.c", role="viewer")
    return eng


def test_touch_last_login_writes_timestamp(store: engine.Engine):
    store.touch_last_login("alice")
    u = store.get_user("alice")
    assert u["last_login"] is not None
    assert "T" in u["last_login"]  # iso8601


def test_revoke_sessions_dispatches_callback(store: engine.Engine):
    calls = []
    store.set_revoke_callback(lambda name: calls.append(name) or 7)
    n = store.revoke_sessions("alice")
    assert n == 7
    assert calls == ["alice"]


def test_revoke_sessions_no_callback_returns_zero(store: engine.Engine):
    assert store.revoke_sessions("alice") == 0
