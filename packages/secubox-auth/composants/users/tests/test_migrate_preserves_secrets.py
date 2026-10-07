# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""The migration must never destroy credentials (#945).

On gk2 the 1.4.2 → 1.5.1 upgrade wiped the argon2 hashes and the admin TOTP of
all three accounts. Cause: users.json held an array of already-v2 entries but
had lost its `version` key, so `_is_v2()` said "v1" and the conversion rebuilt
every account from a blank template, copying only email/role/created.

Dropping a hash is correct for a LEGACY flat entry (those are unsalted SHA-256
inherited from auth.toml and cannot become argon2id without a re-prompt). It is
never correct for an entry that is already in v2 array shape.
"""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from api.migrate_v1_to_v2 import migrate  # noqa: E402

ARGON2 = "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$aGFzaGhhc2hoYXNo"


def _v2_entry(username, **over):
    e = {
        "username": username,
        "email": f"{username}@example.local",
        "role": "admin",
        "enabled": True,
        "password_hash": ARGON2,
        "must_change_password": False,
        "totp": {"enabled": True, "secret": "SECRET"},
        "google": None,
        "services": ["nextcloud"],
        "created": "2026-05-13T00:00:00+00:00",
        "last_login": None,
    }
    e.update(over)
    return e


def _load(p):
    return json.loads(p.read_text())


def _by_name(doc):
    return {u["username"]: u for u in doc["users"]}


# ── the exact gk2 failure ────────────────────────────────────────────────
def test_v2_array_without_version_key_keeps_credentials(tmp_path):
    """The gk2 case: v2 entries, no `version` key. Nothing may be lost."""
    p = tmp_path / "users.json"
    p.write_text(json.dumps({"users": [
        _v2_entry("admin"),
        _v2_entry("gk2", totp=None),
        _v2_entry("operator", role="operator", totp=None),
    ]}))

    migrate(p, auth_toml_path=None)

    users = _by_name(_load(p))
    assert set(users) == {"admin", "gk2", "operator"}
    for name in users:
        assert users[name]["password_hash"] == ARGON2, f"{name} lost its hash"
        assert users[name]["must_change_password"] is False
    assert users["admin"]["totp"] == {"enabled": True, "secret": "SECRET"}
    assert users["operator"]["role"] == "operator"
    assert users["gk2"]["services"] == ["nextcloud"]


def test_missing_version_key_gets_stamped(tmp_path):
    p = tmp_path / "users.json"
    p.write_text(json.dumps({"users": [_v2_entry("admin")]}))
    migrate(p, auth_toml_path=None)
    assert _load(p)["version"] == 2


def test_full_v2_is_untouched(tmp_path):
    p = tmp_path / "users.json"
    doc = {"version": 2, "users": [_v2_entry("admin")], "groups": []}
    p.write_text(json.dumps(doc))
    before = p.read_text()
    migrate(p, auth_toml_path=None)
    assert _by_name(_load(p))["admin"]["password_hash"] == ARGON2
    assert _load(p) == json.loads(before)


# ── legacy entries still lose their (SHA-256) hash, on purpose ───────────
def test_legacy_flat_entry_still_drops_its_hash(tmp_path):
    """Unsalted SHA-256 from the flat shape must NOT be carried into v2."""
    p = tmp_path / "users.json"
    p.write_text(json.dumps({
        "admin": {
            "password_hash": "5e88489…sha256…",
            "email": "admin@secubox.local",
            "role": "admin",
        }
    }))
    migrate(p, auth_toml_path=None)
    u = _by_name(_load(p))["admin"]
    assert u["password_hash"] is None
    assert u["must_change_password"] is True
    assert u["email"] == "admin@secubox.local"


def test_array_entry_wins_over_legacy_flat_for_the_same_user(tmp_path):
    """A real argon2 hash must survive alongside a stale flat block."""
    p = tmp_path / "users.json"
    p.write_text(json.dumps({
        "users": [_v2_entry("admin")],
        "admin": {"password_hash": "sha256-legacy", "role": "admin"},
    }))
    migrate(p, auth_toml_path=None)
    u = _by_name(_load(p))["admin"]
    assert u["password_hash"] == ARGON2


# ── a snapshot must exist before anything is rewritten ───────────────────
def test_a_timestamped_snapshot_is_taken_before_conversion(tmp_path):
    p = tmp_path / "users.json"
    original = json.dumps({"users": [_v2_entry("admin")]})
    p.write_text(original)

    migrate(p, auth_toml_path=None)

    snaps = list(tmp_path.glob("users.json.pre-migrate.*"))
    assert snaps, "no timestamped snapshot was taken"
    assert json.loads(snaps[0].read_text()) == json.loads(original)


def test_snapshot_does_not_overwrite_a_previous_one(tmp_path):
    """A fixed name lets a second run clobber the only good copy."""
    p = tmp_path / "users.json"
    p.write_text(json.dumps({"users": [_v2_entry("admin")]}))
    migrate(p, auth_toml_path=None)
    first = {s.name for s in tmp_path.glob("users.json.pre-migrate.*")}

    # Knock the version off again and re-run.
    doc = _load(p)
    doc.pop("version")
    p.write_text(json.dumps(doc))
    migrate(p, auth_toml_path=None)

    second = {s.name for s in tmp_path.glob("users.json.pre-migrate.*")}
    assert first <= second
    for s in second:
        content = json.loads((tmp_path / s).read_text())
        assert content["users"][0]["password_hash"] == ARGON2


# ── corrupt input must not silently produce an empty store ───────────────
def test_corrupt_file_is_snapshotted_and_does_not_erase_accounts(tmp_path):
    p = tmp_path / "users.json"
    p.write_text("{ this is not json")
    migrate(p, auth_toml_path=None)
    snaps = list(tmp_path.glob("users.json.pre-migrate.*"))
    assert snaps, "a corrupt store must still be preserved before rewrite"
