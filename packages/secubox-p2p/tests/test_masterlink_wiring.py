# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Issue #774 Task 16b: wire the MasterLink into api/main.py +
[masterlink] config section."""
from fastapi.testclient import TestClient

from api import mesh


def test_load_p2p_config_masterlink_defaults(tmp_path):
    p = tmp_path / "p2p.toml"
    p.write_text('[wireguard]\nrole = "satellite"\n')
    cfg = mesh.load_p2p_config(p)
    assert cfg["masterlink"] == {
        "enabled": False,
        "role_preference": "auto",
        "priority": 100,
        "heartbeat_interval": 5,
        "election_timeout": 15,
        "port": 51824,
        "peer_addrs": [],
    }


def test_load_p2p_config_masterlink_section_overrides(tmp_path):
    p = tmp_path / "p2p.toml"
    p.write_text(
        "[wireguard]\n"
        'role = "master"\n'
        "[masterlink]\n"
        "enabled = true\n"
        "priority = 10\n"
        'peer_addrs = ["10.10.0.2:51824"]\n'
    )
    cfg = mesh.load_p2p_config(p)
    assert cfg["masterlink"]["enabled"] is True
    assert cfg["masterlink"]["priority"] == 10
    assert cfg["masterlink"]["peer_addrs"] == ["10.10.0.2:51824"]
    # Untouched defaults are preserved.
    assert cfg["masterlink"]["heartbeat_interval"] == 5
    assert cfg["masterlink"]["election_timeout"] == 15
    assert cfg["masterlink"]["port"] == 51824


def test_masterlink_topology_endpoint_disabled():
    from api.main import app

    with TestClient(app) as client:
        # masterlink is not enabled in the test environment (no p2p.toml
        # with [masterlink].enabled = true), so startup must set
        # app.state.masterlink = None and never break app startup.
        assert app.state.masterlink is None
        r = client.get("/masterlink/topology")
        assert r.status_code == 200
        assert r.json() == {"enabled": False}


def test_masterlink_promote_endpoint_disabled():
    from api.main import app, require_jwt

    async def _override_jwt():
        return {"sub": "admin"}

    app.dependency_overrides[require_jwt] = _override_jwt
    try:
        with TestClient(app) as client:
            assert app.state.masterlink is None
            r = client.post("/masterlink/promote")
            assert r.status_code == 400
    finally:
        app.dependency_overrides.clear()
