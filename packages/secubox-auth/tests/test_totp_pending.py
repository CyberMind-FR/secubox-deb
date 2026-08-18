# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""TOTP pending-enrollment store with TTL."""
import time
from pathlib import Path

from api import totp_pending


def test_put_get_roundtrip(tmp_path: Path):
    store = totp_pending.PendingStore(tmp_path / "pending.json", ttl_seconds=600)
    store.put("jti-abc", "SECRET123")
    assert store.get("jti-abc") == "SECRET123"


def test_get_returns_none_after_ttl(tmp_path: Path, monkeypatch):
    store = totp_pending.PendingStore(tmp_path / "pending.json", ttl_seconds=1)
    store.put("jti-abc", "SECRET123")
    # Fast-forward clock.
    real_time = time.time
    monkeypatch.setattr(totp_pending.time, "time", lambda: real_time() + 5)
    assert store.get("jti-abc") is None


def test_delete_removes_entry(tmp_path: Path):
    store = totp_pending.PendingStore(tmp_path / "pending.json", ttl_seconds=600)
    store.put("jti-abc", "SECRET123")
    store.delete("jti-abc")
    assert store.get("jti-abc") is None


def test_get_returns_none_for_missing(tmp_path: Path):
    store = totp_pending.PendingStore(tmp_path / "pending.json", ttl_seconds=600)
    assert store.get("unknown") is None
