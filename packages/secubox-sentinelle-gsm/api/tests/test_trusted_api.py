# packages/secubox-sentinelle-gsm/api/tests/test_trusted_api.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gerald Kerma <devel@cybermind.fr>

"""API surface tests for v0.2 /trusted CRUD endpoints."""

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


def test_add_list_delete_roundtrip(client):
    r = client.post(
        "/trusted", json={"imsi": "208201234567890", "label": "iPhone"}
    )
    assert r.status_code == 200
    pid = r.json()["id"]
    assert r.json()["label"] == "iPhone"
    assert r.json()["imsi_hash"] != "208201234567890"

    r = client.get("/trusted")
    assert r.status_code == 200
    assert len(r.json()["phones"]) == 1

    r = client.delete(f"/trusted/{pid}")
    assert r.status_code == 200

    r = client.get("/trusted")
    assert r.json()["phones"] == []


def test_add_invalid_imsi_returns_400(client):
    r = client.post("/trusted", json={"imsi": "abc", "label": "x"})
    assert r.status_code == 400


def test_delete_unknown_returns_404(client):
    r = client.delete("/trusted/not-an-id")
    assert r.status_code == 404
