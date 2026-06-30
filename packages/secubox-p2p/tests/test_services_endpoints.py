# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
import pytest
from fastapi.testclient import TestClient
from api import main, annuaire_client, registry


async def _override_jwt():
    return {"sub": "admin"}


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "ACTIVATION_FILE", tmp_path / "activation.json")
    monkeypatch.setattr(main, "SERVICES_FILE", tmp_path / "services.json")
    local = "did:plc:" + "a" * 32
    remote = "did:plc:" + "b" * 32
    monkeypatch.setattr(annuaire_client, "node_identity", lambda *a, **k: (local, "11" * 32))
    monkeypatch.setattr(annuaire_client, "get_catalog", lambda *a, **k: ([
        {"service_id": "s1", "name": "WAF", "kind": "module", "provider": local,
         "endpoint": "http://10.10.0.1:8085", "approval_mode": "auto"},
        {"service_id": "s2", "name": "Tor", "kind": "tor-exit", "provider": remote,
         "endpoint": "10.10.0.2:9050", "approval_mode": "auto"},
    ], None))
    monkeypatch.setattr(annuaire_client, "get_subscriptions", lambda *a, **k: ([], None))
    calls = []
    def fake_sub(sid, did, priv, **k):
        calls.append(sid); return ({"subscription_id": "sub-" + sid, "state": "approved"}, None)
    monkeypatch.setattr(annuaire_client, "subscribe", fake_sub)
    main._test_sub_calls = calls
    # Bypass JWT auth for tests
    main.app.dependency_overrides[main.require_jwt] = _override_jwt
    yield TestClient(main.app)
    main.app.dependency_overrides.clear()


def test_services_merges_catalog(client):
    r = client.get("/services")
    assert r.status_code == 200
    rows = r.json()["services"]
    ids = {row["service_id"] for row in rows}
    assert "s1" in ids and "s2" in ids


def test_auto_register_activates_local_and_subscribes_remote(client):
    r = client.post("/services/auto-register")
    assert r.status_code == 200
    body = r.json()
    assert body["activated"] >= 1     # s1 local
    assert body["requested"] >= 1     # s2 remote subscribed
    assert "s2" in main._test_sub_calls
    # s1 now active in the overlay-backed view
    rows = {x["service_id"]: x for x in client.get("/services").json()["services"]}
    assert rows["s1"]["active"] is True


def test_catalog_unavailable_degrades(client, monkeypatch):
    monkeypatch.setattr(annuaire_client, "get_catalog", lambda *a, **k: ([], "socket down"))
    r = client.get("/services")
    assert r.status_code == 200
    assert r.json().get("catalog_unavailable") is True
