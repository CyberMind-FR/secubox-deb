# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Issue #774 Task 16b: wire the MasterLink into api/main.py +
[masterlink] config section."""
import pytest
from fastapi.testclient import TestClient

from api import masterlink, mesh


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


# -- Final-review fix (Issue #774): peers_fn must reflect the real mesh --
#
# _masterlink_startup used to wire peers_fn=lambda: [], so every node's
# _candidates() only ever contained itself and it trivially self-elected
# regardless of any real peers. peers_fn must be built from the live wg-mesh
# state (wg_mesh.json) via masterlink.peers_from_mesh(), the adapter that
# already existed but was never called.

def test_masterlink_peers_fn_uses_real_mesh_state(monkeypatch):
    import api.main as main_mod

    fake_mesh = {
        "peers": [
            {"public_key": "peerpubkey1", "endpoint": "10.10.0.2:51822",
             "allowed_ips": "10.10.0.2/32"},
        ]
    }
    monkeypatch.setattr(main_mod, "get_wg_mesh_config", lambda: fake_mesh)

    peers = main_mod._masterlink_peers_fn()

    assert peers == masterlink.peers_from_mesh(fake_mesh)
    assert peers != []
    assert peers[0]["priority"] == 100
    assert "node_id_hex" in peers[0]


def test_masterlink_peers_fn_never_raises_on_bad_mesh_state(monkeypatch):
    """peers_fn must degrade to an empty candidate list (self-election),
    never raise, when the mesh-state accessor is unavailable/broken."""
    import api.main as main_mod

    def _boom():
        raise RuntimeError("wg_mesh.json unreadable")

    monkeypatch.setattr(main_mod, "get_wg_mesh_config", _boom)

    assert main_mod._masterlink_peers_fn() == []


@pytest.mark.integration
@pytest.mark.asyncio
async def test_masterlink_startup_wires_real_peers_fn(tmp_path, monkeypatch):
    """End-to-end: _masterlink_startup must wire the MasterLink's peers_fn to
    _masterlink_peers_fn (real mesh state), not a `lambda: []` closure."""
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives.serialization import (
        Encoding, NoEncryption, PrivateFormat,
    )

    import api.annuaire_client as annuaire_client
    import api.main as main_mod

    priv_key = ed25519.Ed25519PrivateKey.generate()
    priv_hex = priv_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex()
    monkeypatch.setattr(annuaire_client, "node_identity", lambda *a, **kw: ("did:x", priv_hex))

    toml = tmp_path / "p2p.toml"
    toml.write_text(
        '[wireguard]\nrole = "satellite"\n'
        "[masterlink]\nenabled = true\nport = 0\n"
    )
    monkeypatch.setattr(main_mod, "CONFIG_FILE", toml)

    fake_mesh = {
        "peers": [
            {"public_key": "peerpubkey1", "endpoint": "10.10.0.2:51822",
             "allowed_ips": "10.10.0.2/32"},
        ]
    }
    monkeypatch.setattr(main_mod, "get_wg_mesh_config", lambda: fake_mesh)

    await main_mod._masterlink_startup()
    ml = main_mod.app.state.masterlink
    try:
        assert ml is not None
        assert ml._peers_fn is main_mod._masterlink_peers_fn
        peers = ml._peers_fn()
        assert peers == masterlink.peers_from_mesh(fake_mesh)
        assert peers != []
    finally:
        await ml.stop()
        main_mod.app.state.masterlink = None
