# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Tests for secubox_core.feature_flags."""
from pathlib import Path

import pytest

from secubox_core import feature_flags


def test_defaults_when_file_missing(tmp_path: Path):
    flags = feature_flags.load(tmp_path / "missing.toml")
    assert flags["auth"]["enforce_v2"] is False
    assert flags["auth"]["require_totp_for_admin"] is True


def test_overrides_from_toml(tmp_path: Path):
    p = tmp_path / "feature_flags.toml"
    p.write_text('[auth]\nenforce_v2 = true\nrequire_totp_for_admin = false\n')
    flags = feature_flags.load(p)
    assert flags["auth"]["enforce_v2"] is True
    assert flags["auth"]["require_totp_for_admin"] is False


def test_partial_overrides_keep_defaults(tmp_path: Path):
    p = tmp_path / "feature_flags.toml"
    p.write_text('[auth]\nenforce_v2 = true\n')
    flags = feature_flags.load(p)
    assert flags["auth"]["enforce_v2"] is True
    assert flags["auth"]["require_totp_for_admin"] is True  # default


def test_corrupt_file_returns_defaults_and_logs(tmp_path: Path, caplog):
    import logging
    caplog.set_level(logging.WARNING)
    p = tmp_path / "feature_flags.toml"
    p.write_text('not toml at all =')
    flags = feature_flags.load(p)
    assert flags["auth"]["enforce_v2"] is False
    assert any("feature_flags" in r.message.lower() for r in caplog.records)
