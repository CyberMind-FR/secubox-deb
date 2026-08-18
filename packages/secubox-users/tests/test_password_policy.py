# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Password policy enforcement."""
from pathlib import Path

import pytest

from api import password_policy


@pytest.fixture(autouse=True)
def _wordlist(tmp_path: Path, monkeypatch):
    p = tmp_path / "common.txt"
    p.write_text("password\npassword123\nhunter2\nletmein\n")
    monkeypatch.setattr(password_policy, "COMMON_PASSWORDS_PATH", p)
    # Reset module-level cache so the new path is read.
    password_policy._cache.clear()


USER = {"username": "alice"}


def test_accepts_strong_password():
    password_policy.validate("Correct!Horse9Battery", USER)


def test_rejects_short():
    with pytest.raises(password_policy.PolicyError) as ei:
        password_policy.validate("Sh0rt!Ab", USER)
    assert "12" in str(ei.value)


def test_rejects_too_long():
    with pytest.raises(password_policy.PolicyError):
        password_policy.validate("A1!" + "x" * 200, USER)


def test_rejects_low_charset_variety():
    with pytest.raises(password_policy.PolicyError):
        password_policy.validate("alllowercaseonly", USER)


def test_rejects_username_substring_case_insensitive():
    with pytest.raises(password_policy.PolicyError):
        password_policy.validate("ALICE!Password9X", USER)


def test_rejects_common_password():
    # 'password123' is in the wordlist fixture.
    with pytest.raises(password_policy.PolicyError):
        password_policy.validate("Password123!XY", {"username": "bob"})
