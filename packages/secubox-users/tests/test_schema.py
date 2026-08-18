# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Validate users.json v2 against the JSON Schema."""
import json
from pathlib import Path

import jsonschema
import pytest

SCHEMA = json.loads(
    (Path(__file__).resolve().parents[1] / "schema" / "users.json.schema.json").read_text()
)


def _doc(**overrides):
    base = {
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
    }
    base.update(overrides)
    return base


def test_minimal_valid_doc():
    jsonschema.validate(_doc(), SCHEMA)


def test_version_must_be_2():
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(_doc(version=1), SCHEMA)


def test_username_pattern_enforced():
    doc = _doc()
    doc["users"][0]["username"] = "BadName!"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(doc, SCHEMA)


def test_role_enum_enforced():
    doc = _doc()
    doc["users"][0]["role"] = "superuser"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(doc, SCHEMA)


def test_totp_block_shape():
    doc = _doc()
    doc["users"][0]["totp"] = {
        "secret": "JBSWY3DPEHPK3PXP",
        "enabled": True,
        "enrolled_at": "2026-05-13T00:00:00+00:00",
        "last_step": None,
        "backup_codes": [
            {"hash": "$argon2id$...", "used_at": None}
        ],
    }
    jsonschema.validate(doc, SCHEMA)


def test_password_hash_may_be_null():
    doc = _doc()
    doc["users"][0]["password_hash"] = None
    jsonschema.validate(doc, SCHEMA)
