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
    monkeypatch.setattr(main, "init_dirs", lambda: None)
    local = "did:plc:" + "a" * 32
    remote = "did:plc:" + "b" * 32
    monkeypatch.setattr(annuaire_client, "node_identity", lambda *a, **k: (local, "11" * 32))
    monkeypatch.setattr(annuaire_client, "get_catalog", lambda *a, **k: ([
        {"service_id": "s1", "name": "WAF", "kind": "module", "provider": local,
         "endpoint": "http://10.10.0.1:8085", "approval_mode": "auto"},
        {"service_id": "s2", "name": "Tor", "kind": "tor-exit", "provider": remote,
         "endpoint": "10.10.0.2:9050", "approval_mode": "auto",
         "macro": {"kind": "tor-exit", "params": {"socks_port": 9050}}},
    ], None))
    monkeypatch.setattr(annuaire_client, "get_subscriptions", lambda *a, **k: ([
        {"service_id": "s2", "state": "approved"},
    ], None))
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


def test_auto_register_activates_local_and_subscribes_remote(client, monkeypatch):
    # s2 is now approved, so auto-register only activates local (s1) + marks s2 already
    monkeypatch.setattr(annuaire_client, "get_subscriptions", lambda *a, **k: ([], None))
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


# ============== M2: macro activate + revoke-access ==============

def test_activate_remote_macro_pulls_and_runs_activate(client, monkeypatch):
    """Remote macro offer with approved subscription: _pull_grant + _macroctl_activate called."""
    cred = {"endpoint": "10.10.0.2:9050", "kind": "tor-exit", "service_id": "s2"}
    pull_calls = []
    activate_calls = []

    def fake_pull(offer):
        pull_calls.append(offer.get("service_id"))
        return cred, None

    def fake_activate(kind, c):
        activate_calls.append((kind, c))
        return True, None

    monkeypatch.setattr(main, "_pull_grant", fake_pull)
    monkeypatch.setattr(main, "_macroctl_activate", fake_activate)

    r = client.post("/services/s2/activate")
    assert r.status_code == 200
    body = r.json()
    assert body.get("status") == "ok"
    assert body.get("endpoint") == "10.10.0.2:9050"
    assert "s2" in pull_calls
    assert len(activate_calls) == 1
    assert activate_calls[0][0] == "tor-exit"


def test_activate_remote_macro_pull_failure_returns_error(client, monkeypatch):
    """If _pull_grant fails, activate returns error without calling _macroctl_activate."""
    activate_calls = []

    monkeypatch.setattr(main, "_pull_grant", lambda offer: (None, "provider unreachable"))
    monkeypatch.setattr(main, "_macroctl_activate", lambda kind, cred: activate_calls.append(kind) or (True, None))

    r = client.post("/services/s2/activate")
    assert r.status_code == 200
    body = r.json()
    assert body.get("status") == "error"
    assert "pull" in body.get("error", "").lower() or "provider" in body.get("error", "").lower()
    assert len(activate_calls) == 0


def test_activate_local_service_unchanged(client, monkeypatch):
    """M1 non-macro local activate path stays unchanged (no _pull_grant called)."""
    pull_calls = []
    monkeypatch.setattr(main, "_pull_grant", lambda offer: pull_calls.append(offer) or (None, "should not call"))

    r = client.post("/services/s1/activate")
    assert r.status_code == 200
    assert r.json().get("status") == "ok"
    # s1 is local (provider == our DID), no macro — _pull_grant must NOT be called
    assert len(pull_calls) == 0


def test_revoke_access_calls_macroctl_revoke(client, monkeypatch):
    """revoke-access runs macroctl revoke and clears active state."""
    revoke_calls = []

    def fake_revoke(kind, sub_did, src_ip):
        revoke_calls.append((kind, sub_did, src_ip))
        return True, None

    monkeypatch.setattr(main, "_macroctl_revoke", fake_revoke)
    monkeypatch.setattr(main, "_get_our_mesh_ip", lambda: "10.10.0.3")

    r = client.post("/services/s2/revoke-access")
    assert r.status_code == 200
    assert r.json().get("status") == "ok"
    assert len(revoke_calls) == 1
    kind, sub_did, src_ip = revoke_calls[0]
    assert kind == "tor-exit"
    assert src_ip == "10.10.0.3"


def test_revoke_access_unknown_service(client, monkeypatch):
    """revoke-access on unknown service_id returns error."""
    r = client.post("/services/nonexistent/revoke-access")
    assert r.status_code == 200
    assert r.json().get("status") == "error"


def test_revoke_access_no_mesh_ip_returns_409(client, monkeypatch):
    """revoke-access returns 409 when node has no valid wg-mesh IP."""
    monkeypatch.setattr(main, "_get_our_mesh_ip", lambda: None)
    r = client.post("/services/s2/revoke-access")
    assert r.status_code == 409
    assert "wg-mesh" in r.json().get("error", "").lower() or "mesh" in r.json().get("error", "")
