# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Revocation must actually revoke, and must never lie about it (#944).

These pin three defects found from the /users/ panel:

1. the module called `DELETE /session/{id}` on secubox-auth — a route that
   has never existed there (the verb is `POST /revoke_session?session_id=…`);
2. success was read off `curl`'s exit status, and `curl -s` exits 0 on a 404,
   so the endpoint always answered `success: true`;
3. `revoke-all` wrote an OBJECT into sessions.json, whose only valid shape is
   a list — which crashed secubox-auth's validator on every request.
"""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


# ── 3. the store's shape ─────────────────────────────────────────────────
def test_revoke_all_writes_a_list_not_an_object(tmp_path, monkeypatch):
    """A dict here breaks every consumer of the store."""
    store = tmp_path / "sessions.json"
    store.write_text(json.dumps([{"id": "a"}, {"id": "b"}]))
    monkeypatch.setenv("SECUBOX_AUTH_SESSIONS", str(store))

    # A dev workstation cannot read /etc/secubox/secubox.conf (0640
    # secubox:secubox) and api.main calls get_config() at import time. Patch
    # the source module before the (re)import so the binding picks up the stub.
    import importlib
    import secubox_core.config as core_config
    monkeypatch.setattr(core_config, "get_config", lambda section="": {})
    from api import main as users_main
    importlib.reload(users_main)

    out = users_main.revoke_all_sessions()
    assert out["revoked"] == 2

    written = json.loads(store.read_text())
    assert isinstance(written, list), f"expected a list, got {type(written).__name__}"
    assert written == []


def test_object_shaped_store_breaks_the_validator():
    """Why the shape matters — this is what the old code produced."""
    bad = {"sessions": [], "revoked_at": "2026-08-01"}
    with pytest.raises(AttributeError):
        any(s.get("id") == "x" for s in bad)

    good = []
    assert any(s.get("id") == "x" for s in good) is False


# ── 1 & 2. the call to secubox-auth ──────────────────────────────────────
def test_revoke_targets_the_real_auth_route():
    """The old path 404'd; pin the verb and the route that exist."""
    src = Path(__file__).resolve().parents[1] / "api" / "main.py"
    body = src.read_text()
    assert "/api/v1/auth/revoke_session" in body
    assert "client.post(" in body
    assert 'X", "DELETE", "--unix-socket"' not in body


def test_revoke_does_not_infer_success_from_an_exit_code():
    """`curl -s` exits 0 on a 404 — success must come from the HTTP status."""
    src = Path(__file__).resolve().parents[1] / "api" / "main.py"
    body = src.read_text()
    revoke = body.split("async def revoke_session(")[1].split("@app.")[0]
    assert "resp.status_code" in revoke
    assert "returncode" not in revoke


def test_revoke_forwards_caller_credentials():
    """secubox-auth requires a JWT and audits `by: <sub>` — the admin's own
    credential must travel with the call, not a second writer on the store."""
    src = Path(__file__).resolve().parents[1] / "api" / "main.py"
    body = src.read_text()
    helper = body.split("def _auth_credentials(")[1].split("\n\n\n")[0]
    assert "Authorization" in helper
    assert "Cookie" in helper
