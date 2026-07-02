# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Issue #774 Task 9: wire the DHT into api/main.py + [dht] config section."""
from fastapi.testclient import TestClient

from api import mesh


def test_load_p2p_config_dht_defaults(tmp_path):
    p = tmp_path / "p2p.toml"
    p.write_text('[wireguard]\nrole = "satellite"\n')
    cfg = mesh.load_p2p_config(p)
    assert cfg["dht"] == {
        "enabled": False,
        "port": 51823,
        "bootstrap": [],
        "announce": False,
        "announce_interval": 900,
        "rps": 50,
    }


def test_load_p2p_config_dht_section_overrides(tmp_path):
    p = tmp_path / "p2p.toml"
    p.write_text(
        "[wireguard]\n"
        'role = "master"\n'
        "[dht]\n"
        "enabled = true\n"
        "port = 51999\n"
    )
    cfg = mesh.load_p2p_config(p)
    assert cfg["dht"]["enabled"] is True
    assert cfg["dht"]["port"] == 51999
    # Untouched defaults are preserved.
    assert cfg["dht"]["announce"] is False
    assert cfg["dht"]["bootstrap"] == []


def test_dht_peers_endpoint_disabled():
    from api.main import app

    with TestClient(app) as client:
        # DHT is not enabled in the test environment (no p2p.toml with
        # [dht].enabled = true), so startup must set app.state.dht = None
        # and never break app startup.
        assert app.state.dht is None
        r = client.get("/dht/peers")
        assert r.status_code == 200
        assert r.json() == {"enabled": False, "peers": [], "buckets": 0}
