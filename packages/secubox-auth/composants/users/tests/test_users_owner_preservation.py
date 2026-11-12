# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""secubox-users : users.json owner/mode preservation.

The owner-preservation guard keeps a root-run CLI from locking the
secubox auth service out of users.json. (The YaCy admin password sync that
shared this file was removed with YaCy, #3581.)
"""
import json
import os
import stat
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[5]
sys.path.insert(0, str(ROOT / "common"))
sys.path.insert(0, str(ROOT / "packages" / "secubox-auth" / "composants" / "users"))

from api import engine as E  # noqa: E402


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
