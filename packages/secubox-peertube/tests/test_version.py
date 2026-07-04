# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""PeerTube version check (#798)."""
from api import main as m


def test_semver_lt():
    assert m._semver_lt("8.2.0", "8.2.1") is True
    assert m._semver_lt("8.2.0", "8.10.0") is True   # numeric, not lexical
    assert m._semver_lt("8.2.0", "8.2.0") is False
    assert m._semver_lt("9.0.0", "8.9.9") is False


def test_version_upgrade_available(monkeypatch):
    import asyncio
    monkeypatch.setattr(m, "_installed_version", lambda: "8.2.0")
    monkeypatch.setattr(m, "_latest_version", lambda: "8.3.0")
    out = asyncio.run(m.version_info(user={"role": "user"}))
    assert out == {"installed": "8.2.0", "latest": "8.3.0", "upgrade_available": True}


def test_version_up_to_date(monkeypatch):
    import asyncio
    monkeypatch.setattr(m, "_installed_version", lambda: "8.3.0")
    monkeypatch.setattr(m, "_latest_version", lambda: "8.3.0")
    out = asyncio.run(m.version_info(user={"role": "user"}))
    assert out["upgrade_available"] is False


def test_version_offline_latest_none(monkeypatch):
    import asyncio
    monkeypatch.setattr(m, "_installed_version", lambda: "8.2.0")
    monkeypatch.setattr(m, "_latest_version", lambda: None)
    out = asyncio.run(m.version_info(user={"role": "user"}))
    assert out["latest"] is None and out["upgrade_available"] is False
