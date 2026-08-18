# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Tests for secubox_core.user_store."""
import json
import logging
from pathlib import Path

import pytest
from argon2 import PasswordHasher

from secubox_core import user_store


def _write_user(path: Path, **fields):
    base = {
        "username": "admin",
        "email": "a@b.c",
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
    base.update(fields)
    doc = {"version": 2, "users": [base], "groups": []}
    path.write_text(json.dumps(doc))


def test_get_user_returns_dict(tmp_path: Path, monkeypatch):
    p = tmp_path / "users.json"
    _write_user(p)
    monkeypatch.setattr(user_store, "USERS_PATH", p)
    u = user_store.get_user("admin")
    assert u["username"] == "admin"
    assert u["enabled"] is True


def test_get_user_missing_returns_none(tmp_path: Path, monkeypatch):
    p = tmp_path / "users.json"
    _write_user(p)
    monkeypatch.setattr(user_store, "USERS_PATH", p)
    assert user_store.get_user("ghost") is None


def test_verify_password_accepts_correct_hash(tmp_path: Path, monkeypatch):
    h = PasswordHasher().hash("StrongPass!42xy")
    p = tmp_path / "users.json"
    _write_user(p, password_hash=h, must_change_password=False)
    monkeypatch.setattr(user_store, "USERS_PATH", p)
    assert user_store.verify_password("admin", "StrongPass!42xy") is True


def test_verify_password_rejects_wrong(tmp_path: Path, monkeypatch):
    h = PasswordHasher().hash("StrongPass!42xy")
    p = tmp_path / "users.json"
    _write_user(p, password_hash=h, must_change_password=False)
    monkeypatch.setattr(user_store, "USERS_PATH", p)
    assert user_store.verify_password("admin", "wrong") is False


def test_verify_password_rejects_null_hash(tmp_path: Path, monkeypatch):
    p = tmp_path / "users.json"
    _write_user(p, password_hash=None)
    monkeypatch.setattr(user_store, "USERS_PATH", p)
    assert user_store.verify_password("admin", "anything") is False


def test_is_enabled(tmp_path: Path, monkeypatch):
    p = tmp_path / "users.json"
    _write_user(p, enabled=False)
    monkeypatch.setattr(user_store, "USERS_PATH", p)
    assert user_store.is_enabled("admin") is False


def test_fallback_to_auth_toml_when_users_json_missing(tmp_path: Path, monkeypatch, caplog):
    users_missing = tmp_path / "users.json"
    auth_toml = tmp_path / "auth.toml"
    auth_toml.write_text('[users.admin]\npassword = "fallbackonly"\nrole = "admin"\n')
    monkeypatch.setattr(user_store, "USERS_PATH", users_missing)
    monkeypatch.setattr(user_store, "AUTH_TOML_PATH", auth_toml)
    caplog.set_level(logging.WARNING)
    # In fallback mode, verify_password uses plaintext comparison.
    assert user_store.verify_password("admin", "fallbackonly") is True
    assert user_store.verify_password("admin", "wrong") is False
    assert any("fallback" in r.message.lower() for r in caplog.records)


def test_fallback_to_auth_toml_when_users_json_corrupt(tmp_path: Path, monkeypatch, caplog):
    users_bad = tmp_path / "users.json"
    users_bad.write_text("{not json")
    auth_toml = tmp_path / "auth.toml"
    auth_toml.write_text('[users.admin]\npassword = "fallbackonly"\n')
    monkeypatch.setattr(user_store, "USERS_PATH", users_bad)
    monkeypatch.setattr(user_store, "AUTH_TOML_PATH", auth_toml)
    caplog.set_level(logging.WARNING)
    assert user_store.verify_password("admin", "fallbackonly") is True


# --- set_password / provisioning (#410) ---------------------------------------

def test_set_password_updates_existing(tmp_path: Path, monkeypatch):
    p = tmp_path / "users.json"
    _write_user(p)
    monkeypatch.setattr(user_store, "USERS_PATH", p)
    user_store.set_password("admin", "NewPass!99zz")
    assert user_store.verify_password("admin", "NewPass!99zz") is True


def test_set_password_provisions_new_user(tmp_path: Path, monkeypatch):
    p = tmp_path / "users.json"
    _write_user(p)
    monkeypatch.setattr(user_store, "USERS_PATH", p)
    user_store.set_password("gk2", "Gk2Pass!77aa", provision=True, role="user")
    assert "gk2" in user_store.list_users()
    assert user_store.verify_password("gk2", "Gk2Pass!77aa") is True


def test_set_password_unknown_without_provision_raises(tmp_path: Path, monkeypatch):
    p = tmp_path / "users.json"
    _write_user(p)
    monkeypatch.setattr(user_store, "USERS_PATH", p)
    with pytest.raises(KeyError):
        user_store.set_password("ghost", "whatever")


def test_set_password_missing_store_raises(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(user_store, "USERS_PATH", tmp_path / "nope.json")
    with pytest.raises(RuntimeError):
        user_store.set_password("admin", "whatever", provision=True)


def test_set_password_preserves_other_users(tmp_path: Path, monkeypatch):
    p = tmp_path / "users.json"
    _write_user(p)
    monkeypatch.setattr(user_store, "USERS_PATH", p)
    user_store.set_password("gk2", "Gk2Pass!77aa", provision=True)
    user_store.set_password("admin", "AdminPass!88bb")
    assert sorted(user_store.list_users()) == ["admin", "gk2"]
    assert user_store.verify_password("admin", "AdminPass!88bb") is True
    assert user_store.verify_password("gk2", "Gk2Pass!77aa") is True
