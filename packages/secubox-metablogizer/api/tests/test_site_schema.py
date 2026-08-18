# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Tests for packages/secubox-metablogizer/api/site_schema.py"""
import subprocess
import tempfile
from pathlib import Path

import pytest

from site_schema import enrich, load_schema, validate


def test_load_schema_returns_dict():
    s = load_schema()
    assert isinstance(s, dict)
    assert s.get("title") == "MetaBlogizer site.json"


def test_validate_minimal_valid_doc():
    ok, errs = validate({
        "name": "zkp",
        "domain": "zkp.gk2.secubox.in",
        "published": True,
    })
    assert ok is True
    assert errs == []


def test_validate_missing_required_field():
    ok, errs = validate({
        "name": "zkp",
        "published": True,
    })
    assert ok is False
    assert any("domain" in e for e in errs)


def test_validate_bad_version_pattern():
    ok, errs = validate({
        "name": "zkp",
        "domain": "zkp.gk2.secubox.in",
        "published": True,
        "version": "1.0",  # missing v prefix and a third digit
    })
    assert ok is False
    assert any("version" in e for e in errs)


def test_validate_accepts_extra_fields():
    ok, errs = validate({
        "name": "zkp",
        "domain": "zkp.gk2.secubox.in",
        "published": True,
        "auto_deploy": True,  # not in schema; additionalProperties: true
    })
    assert ok is True
    assert errs == []


def test_enrich_no_git_returns_same_doc():
    with tempfile.TemporaryDirectory() as td:
        out = enrich({"name": "x"}, Path(td))
        assert out == {"name": "x"}


def test_enrich_with_git_populates_version_and_last_updated():
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        subprocess.run(["git", "-C", str(d), "init", "-q", "-b", "main"], check=True)
        subprocess.run(
            ["git", "-C", str(d), "-c", "user.email=t@t", "-c", "user.name=t",
             "commit", "-q", "--allow-empty", "-m", "init"],
            check=True,
        )
        subprocess.run(["git", "-C", str(d), "tag", "v1.0.0"], check=True)

        out = enrich({"name": "x"}, d)
        assert out["version"] == "v1.0.0"
        assert out["last_updated"]  # RFC3339-ish string, just non-empty


def test_enrich_preserves_existing_version():
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        subprocess.run(["git", "-C", str(d), "init", "-q", "-b", "main"], check=True)
        out = enrich({"name": "x", "version": "v9.9.9"}, d)
        assert out["version"] == "v9.9.9"  # not overwritten
