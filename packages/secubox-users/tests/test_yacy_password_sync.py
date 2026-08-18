# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""secubox-users → YaCy admin password sync (#776) + users.json owner preservation.

The sync pushes the master 'admin' user's password to YaCy's single admin account
over STDIN; the owner-preservation guard keeps a root-run CLI from locking the
secubox auth service out of users.json.
"""
import json
import os
import stat
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "common"))
sys.path.insert(0, str(ROOT / "packages" / "secubox-users"))

import api.main as m  # noqa: E402
from api import engine as E  # noqa: E402


# --- YaCy admin password sync ---------------------------------------------------

def test_sync_yacy_skips_non_admin():
    # Only the master 'admin' user drives YaCy's single admin account.
    assert m._sync_yacy_admin_password("bob", "pw") is None


def test_sync_yacy_skips_when_yacy_absent(monkeypatch):
    monkeypatch.setattr(m, "_yacy_available", lambda: False)
    assert m._sync_yacy_admin_password("admin", "pw") is None


def test_sync_yacy_pushes_password_over_stdin(monkeypatch):
    monkeypatch.setattr(m, "_yacy_available", lambda: True)
    seen = {}

    class _R:
        returncode = 0

    def _fake_run(cmd, **kw):
        seen["cmd"] = cmd
        seen["input"] = kw.get("input")
        return _R()

    monkeypatch.setattr(m.subprocess, "run", _fake_run)
    ok = m._sync_yacy_admin_password("admin", "s3cret;pw")
    assert ok is True
    assert seen["cmd"] == ["sudo", "-n", "/usr/sbin/yacyctl", "set-admin-password"]
    # Password must travel over stdin, never argv (no ps / sudo-log leak).
    assert seen["input"] == "s3cret;pw"
    assert "s3cret;pw" not in " ".join(seen["cmd"])


def test_sync_yacy_reports_failure(monkeypatch):
    monkeypatch.setattr(m, "_yacy_available", lambda: True)

    class _R:
        returncode = 1

    monkeypatch.setattr(m.subprocess, "run", lambda *a, **k: _R())
    assert m._sync_yacy_admin_password("admin", "pw") is False


# --- users.json owner/mode preservation (root-run CLI regression) ---------------

def test_engine_save_preserves_mode(tmp_path):
    """A distinctive pre-existing mode must survive _save.

    Regression: a root-run `usersctl set-password` used to recreate users.json
    with mkstemp's default 0o600 (root:root), locking out the secubox auth
    service. 0o640 is distinct from that default, so this fails without the guard.
    """
    p = tmp_path / "users.json"
    p.write_text(json.dumps({"version": 2, "users": [], "groups": []}))
    os.chmod(p, 0o640)
    eng = E.Engine(users_path=p)
    eng.create_user("bob", email="bob@x.test", role="viewer")
    mode = stat.S_IMODE(os.stat(p).st_mode)
    assert mode == 0o640, f"mode not preserved after _save: {oct(mode)}"
