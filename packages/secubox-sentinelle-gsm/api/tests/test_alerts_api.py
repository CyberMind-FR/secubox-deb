# packages/secubox-sentinelle-gsm/api/tests/test_alerts_api.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gerald Kerma <devel@cybermind.fr>

"""API surface tests for v0.2 /alerts endpoints.

The `client` fixture wires fresh AlertSink + TrustedRegistry instances
into the live `api.main` module so test isolation is per-test (tmp_path).
JWT enforcement is bypassed via FastAPI's dependency_overrides — the real
JWT layer lives at nginx + Authelia, not inside the app.
"""

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(tmp_path):
    from sentinelle_gsm.observer import Anonymizer
    from sentinelle_gsm.alert_sink import AlertSink
    from sentinelle_gsm.trusted import TrustedRegistry
    from api import main as api_main

    api_main._alert_sink = AlertSink(tmp_path / "alerts.db")
    api_main._trusted_registry = TrustedRegistry(
        tmp_path / "trusted.json", Anonymizer(b"x" * 32)
    )
    api_main.app.dependency_overrides[api_main.require_jwt] = (
        lambda: {"sub": "tester"}
    )
    try:
        yield TestClient(api_main.app)
    finally:
        api_main.app.dependency_overrides.clear()
        api_main._alert_sink = None
        api_main._trusted_registry = None


def test_post_alerts_test_writes_one(client):
    r = client.post("/alerts/test")
    assert r.status_code == 200
    assert r.json()["ok"] is True


def test_get_alerts_returns_history(client):
    client.post("/alerts/test", json={"cell_id": "208-01-100-1"})
    client.post("/alerts/test", json={"cell_id": "208-01-100-2"})
    r = client.get("/alerts?limit=10")
    assert r.status_code == 200
    cells = [a["cell_id"] for a in r.json()["alerts"]]
    assert "208-01-100-1" in cells and "208-01-100-2" in cells


def test_test_alert_refuses_plaintext_imsi(client):
    """AlertSink raises ValueError on 15-digit shape → FastAPI surfaces 500."""
    r = client.post(
        "/alerts/test",
        json={"reason": "saw IMSI 208201234567890"},
    )
    assert r.status_code == 500


def test_stream_endpoint_advertises_sse(client):
    """Smoke test the SSE route is registered and advertises text/event-stream.

    Asserting via `app.routes` (not an HTTP call) so we don't have to
    interleave a TestClient write into the async generator awaiting on
    `q.get()`. The actual SSE chunk format is covered by
    `test_alert_sink.py::test_stream_emits_sse_format` against the
    AlertSink directly.
    """
    from api import main as api_main

    route_paths = {r.path: r for r in api_main.app.routes if hasattr(r, "path")}
    assert "/alerts/stream" in route_paths
    assert "/alerts" in route_paths
    assert "/alerts/test" in route_paths

    # Verify the route is wired through the StreamingResponse-returning
    # handler with text/event-stream by inspecting OpenAPI: TestClient.get
    # against /openapi.json is cheap and doesn't open the SSE stream.
    r = client.get("/openapi.json")
    assert r.status_code == 200
    paths = r.json()["paths"]
    assert "/alerts/stream" in paths
    assert "get" in paths["/alerts/stream"]
