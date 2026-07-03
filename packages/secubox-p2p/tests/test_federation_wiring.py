# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Issue #774 Task 13: wire federation health-checks into api/main.py +
[federation] config section."""
from fastapi.testclient import TestClient

from api import mesh


def test_load_p2p_config_federation_defaults(tmp_path):
    p = tmp_path / "p2p.toml"
    p.write_text('[wireguard]\nrole = "satellite"\n')
    cfg = mesh.load_p2p_config(p)
    assert cfg["federation"] == {
        "health_checks": False,
        "interval": 30,
        "probe_timeout": 5,
        "max_concurrency": 20,
        "fail_threshold": 3,
    }


def test_load_p2p_config_federation_section_overrides(tmp_path):
    p = tmp_path / "p2p.toml"
    p.write_text(
        "[wireguard]\n"
        'role = "master"\n'
        "[federation]\n"
        "health_checks = true\n"
        "interval = 60\n"
    )
    cfg = mesh.load_p2p_config(p)
    assert cfg["federation"]["health_checks"] is True
    assert cfg["federation"]["interval"] == 60
    # Untouched defaults are preserved.
    assert cfg["federation"]["probe_timeout"] == 5
    assert cfg["federation"]["fail_threshold"] == 3


def test_federation_services_endpoint_disabled():
    from api.main import app

    with TestClient(app) as client:
        # health checks are not enabled in the test environment (no
        # p2p.toml with [federation].health_checks = true), so startup must
        # set app.state.health_checker = None and never break app startup.
        assert app.state.health_checker is None
        r = client.get("/federation/services")
        assert r.status_code == 200
        body = r.json()
        assert body["enabled"] is False
        assert "services" in body
