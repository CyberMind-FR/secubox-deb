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


# -- Final-review fix (Issue #774): audit log must target a writable path --
#
# DHT_AUDIT_LOG used to point at /var/log/secubox/p2p-audit.log, i.e. directly
# under the shared 0755 root:root /var/log/secubox/ parent — every write there
# raised PermissionError (silently swallowed by _dht_audit), so the CSPN audit
# trail for /dht/announce and /masterlink/promote was never actually written.
# debian/postinst provisions a writable /var/log/secubox/p2p/ (0750
# secubox:secubox); DHT_AUDIT_LOG must live under it.

def test_dht_audit_log_path_under_writable_p2p_subdir():
    from api.main import DHT_AUDIT_LOG

    assert str(DHT_AUDIT_LOG).startswith("/var/log/secubox/p2p/")


def test_dht_audit_writes_json_line(tmp_path, monkeypatch):
    import json as _json

    import api.main as main_mod

    log_path = tmp_path / "p2p-audit.log"
    monkeypatch.setattr(main_mod, "DHT_AUDIT_LOG", log_path)

    main_mod._dht_audit("test_event", foo="bar")

    assert log_path.exists()
    lines = log_path.read_text().strip().splitlines()
    assert len(lines) == 1
    rec = _json.loads(lines[0])
    assert rec["event"] == "test_event"
    assert rec["foo"] == "bar"
    assert "ts" in rec

    # A second call appends rather than truncating.
    main_mod._dht_audit("second_event")
    lines = log_path.read_text().strip().splitlines()
    assert len(lines) == 2
